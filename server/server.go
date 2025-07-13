package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/songgao/water"
)

const (
	VPN_PACKET_TYPE_DATA          byte = 0x01
	VPN_PACKET_TYPE_TERMINATE     byte = 0x02
	VPN_PACKET_TYPE_KEEPALIVE     byte = 0x03
	VPN_PACKET_TYPE_IP_ASSIGNMENT byte = 0x04
)

const (
	serverAddr    = ":8443"
	vpnTunIPv6    = "fd00::1/64" // IPv6 only
	vpnTunNetIPv6 = "fd00::/64"  // IPv6 only
)

var (
	ipv6Pool = make(map[uint16]bool) // Only IPv6 pool

	clientIPv6Assignments = make(map[string]net.IP) // Only IPv6 assignments

	poolMutex sync.Mutex
)

// debugMode controla la verbosidad de los logs.
// Cambia a 'false' para deshabilitar los logs detallados de tráfico y depuración de firewall.
var debugMode = true

var blockedIPv6s = []net.IP{
	//net.ParseIP("fd00::b"),
	net.ParseIP("2001:db8::2"),
}

func isIPv6Blocked(ip net.IP) bool {
	if ip == nil || ip.To16() == nil {
		if debugMode { // Solo este log de depuración se imprime si debugMode es true
			log.Printf("[DEBUG-FIREWALL] isIPv6Blocked: IP es nil o no es IPv6 válida: %v", ip)
		}
		return false
	}
	for _, blockedIP := range blockedIPv6s {
		if blockedIP.Equal(ip) {
			if debugMode { // Solo este log de depuración se imprime si debugMode es true
				log.Printf("[DEBUG-FIREWALL] isIPv6Blocked: IP %s MATCHEA con IP BLOQUEADA %s", ip, blockedIP)
			}
			return true
		}
	}
	if debugMode { // Solo este log de depuración se imprime si debugMode es true
		log.Printf("[DEBUG-FIREWALL] isIPv6Blocked: IP %s NO está bloqueada.", ip)
	}
	return false
}

func initIPPool() {
	// Inicializar solo el pool de IPv6
	for i := uint16(10); i <= 0xFFFE; i++ {
		ipv6Pool[i] = false
	}
	log.Println("✅ Pool de IPs IPv6 inicializado.")
}

func assignIP(clientCN string) (net.IP, error) { // Ahora solo devuelve una IP IPv6
	poolMutex.Lock()
	defer poolMutex.Unlock()

	var assignedIPv6 net.IP
	for i := uint16(10); i <= 0xFFFE; i++ {
		potentialIPv6 := net.ParseIP(fmt.Sprintf("fd00::%x", i))
		if !ipv6Pool[i] {
			if potentialIPv6 == nil {
				continue
			}
			// Verificar si la IP ya está en uso o si es una IP "reservada" que no quieres asignar
			// Tu código actual ya empieza en 10, lo cual está bien.
			assignedIPv6 = potentialIPv6
			ipv6Pool[i] = true
			break
		}
	}
	if assignedIPv6 == nil {
		return nil, fmt.Errorf("no hay IPs IPv6 disponibles")
	}

	clientIPv6Assignments[clientCN] = assignedIPv6

	return assignedIPv6, nil
}

func releaseIP(clientCN string, ipv6ToRelease net.IP) { // Solo un parámetro para IPv6
	poolMutex.Lock()
	defer poolMutex.Unlock()

	if ipv6ToRelease != nil {
		if ipv6 := ipv6ToRelease.To16(); ipv6 != nil {
			// Comprobar si la IP está dentro del prefijo esperado
			if bytes.Equal(ipv6[:8], net.ParseIP("fd00::").To16()[:8]) {
				id := uint16(ipv6[14])<<8 | uint16(ipv6[15])
				if id >= 10 && id <= 0xFFFE {
					if ipv6Pool[id] { // Solo liberar si está marcada como en uso
						ipv6Pool[id] = false
						delete(clientIPv6Assignments, clientCN)
						log.Printf("ℹ️ IPv6 %s liberada para %s\n", ipv6ToRelease.String(), clientCN)
					} else {
						log.Printf("⚠ Advertencia: Intentando liberar IPv6 %s para %s que no estaba marcada como en uso.\n", ipv6ToRelease.String(), clientCN)
					}
				} else {
					log.Printf("⚠ Advertencia: Intentando liberar IPv6 %s para %s que está fuera del rango asignable.\n", ipv6ToRelease.String(), clientCN)
				}
			}
		}
	}
}

func main() {
	initIPPool()

	serverCert, err := tls.LoadX509KeyPair("../certs/server.crt", "../certs/server.key")
	if err != nil {
		log.Fatalf("❌ Error al cargar el certificado o la clave del servidor: %v", err)
	}
	log.Println("✅ Certificado y clave del servidor cargados.")

	caCertPEM, err := ioutil.ReadFile("../certs/ca.crt")
	if err != nil {
		log.Fatalf("❌ Error al cargar el certificado de la CA: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		log.Fatalf("❌ Error al agregar el certificado de la CA al pool")
	}
	log.Println("✅ Certificado de la CA cargado para verificación de clientes.")

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	config := water.Config{
		DeviceType: water.TUN,
	}
	// Esto solo se aplica a Windows
	if runtime.GOOS == "windows" {
		config.PlatformSpecificParams = water.PlatformSpecificParams{}
	}

	ifce, err := water.New(config)
	if err != nil {
		log.Fatalf("❌ Error al crear la interfaz TUN: %v", err)
	}
	defer ifce.Close()
	log.Printf("✅ Interfaz TUN creada: %s\n", ifce.Name())

	log.Println("Configurando la interfaz TUN. Necesitas ejecutar este programa con privilegios de administrador.")

	var cmd *exec.Cmd
	var out []byte

	if runtime.GOOS == "windows" {
		vpnTunIPv6Addr := strings.Split(vpnTunIPv6, "/")[0]

		log.Printf("Limpiando dirección IPv6 antigua %s de la interfaz %s...", vpnTunIPv6Addr, ifce.Name())
		// Eliminar dirección IPv6 antigua para evitar conflictos
		cmd = exec.Command("netsh", "interface", "ipv6", "delete", "address", ifce.Name(), vpnTunIPv6Addr)
		out, err = cmd.CombinedOutput()
		if err != nil && !netshOutputContains(out, "Element not found.") && !netshOutputContains(out, "no se encontr") {
			log.Printf("⚠ Servidor - Advertencia: Error al intentar limpiar dirección IPv6: %v. Salida: %s\n", err, string(out))
		} else {
			log.Printf("ℹ️ Servidor - Intento de limpiar dirección IPv6. Salida: %s\n", string(out))
		}

		// Configurar la IP IPv6 de la interfaz TUN
		cmd = exec.Command("netsh", "interface", "ipv6", "add", "address", ifce.Name(), vpnTunIPv6Addr)
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv6 de la interfaz TUN en Windows: %v", err)
		}

		// Habilitar la interfaz (si no está ya habilitada)
		cmd = exec.Command("netsh", "interface", "set", "interface", "name="+ifce.Name(), "admin=enable")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Advertencia: No se pudo activar la interfaz %s en Windows. Error: %v\n", ifce.Name(), err)
		}

		// Habilitar el reenvío de IPv6 en la interfaz TUN (crucial para el routing)
		cmd = exec.Command("netsh", "interface", "ipv6", "set", "interface", ifce.Name(), "forwarding=enabled")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Advertencia: No se pudo habilitar el reenvío de IPv6 en la interfaz %s: %v\n", ifce.Name(), err)
		}
	} else {
		// Aquí puedes poner una lógica para sistemas operativos que no sean Windows si en el futuro los soportarás
		// Por ahora, como es Windows-only, esta sección podría considerarse un stub o eliminarse si no es relevante.
		log.Fatalf("❌ Este servidor está diseñado para ejecutarse en Windows para la configuración automática de la interfaz TUN.")
	}

	log.Printf("✅ Interfaz TUN %s configurada con IP IPv6 %s\n", ifce.Name(), vpnTunIPv6)
	log.Println("⚠ Asegúrate de habilitar el IP forwarding y configurar el firewall en tu sistema operativo si deseas que los clientes acceden a Internet.") // Mensaje actualizado

	listener, err := tls.Listen("tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Fatalf("❌ Error al crear el listener TLS en %s: %v", serverAddr, err)
	}
	defer listener.Close()
	log.Printf("🚀 Servidor VPN escuchando en %s con TLS (mTLS activo)...\n", serverAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("⚠ Error al aceptar la conexión: %v", err)
			continue
		}
		go handleServerConnection(conn, ifce)
	}
}

func netshOutputContains(output []byte, s string) bool {
	return bytes.Contains(output, []byte(s))
}

func handleServerConnection(conn net.Conn, ifce *water.Interface) {
	peerCN := "Desconocido"
	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("❌ Error en el handshake TLS con %s: %v\n", conn.RemoteAddr(), err)
			conn.Close()
			return
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			peerCN = state.PeerCertificates[0].Subject.CommonName
		}
	} else {
		log.Printf("Tipo de conexión inesperado de %s\n", conn.RemoteAddr())
		conn.Close()
		return
	}

	log.Printf("✅ Conexión aceptada desde %s (CN: %s)\n", conn.RemoteAddr(), peerCN)

	assignedIPv6, err := assignIP(peerCN) // Ahora solo asigna IPv6
	if err != nil {
		log.Printf("❌ Error al asignar IP para el cliente %s: %v. Cerrando conexión.", peerCN, err)
		conn.Close()
		return
	}
	log.Printf("✅ IP asignada a cliente %s: IPv6 %s\n", peerCN, assignedIPv6) // Mensaje actualizado

	// El payload solo contendrá la IPv6 (16 bytes)
	ipAssignmentPayload := make([]byte, 16)
	copy(ipAssignmentPayload[0:16], assignedIPv6.To16())

	vpnPacket := make([]byte, 1+len(ipAssignmentPayload))
	vpnPacket[0] = VPN_PACKET_TYPE_IP_ASSIGNMENT
	copy(vpnPacket[1:], ipAssignmentPayload)

	_, err = conn.Write(vpnPacket)
	if err != nil {
		log.Printf("❌ Error al enviar paquete de asignación de IP a %s: %v. Liberando IPs y cerrando conexión.", peerCN, err)
		releaseIP(peerCN, assignedIPv6) // Ahora solo pasamos IPv6
		conn.Close()
		return
	}
	log.Printf("✅ Paquete de asignación de IP enviado a %s. IP: %s (IPv6)\n", peerCN, assignedIPv6) // Mensaje actualizado

	defer func() {
		log.Printf("🚫 Conexión desde %s (CN: %s) cerrada.\n", conn.RemoteAddr(), peerCN)
		releaseIP(peerCN, assignedIPv6) // Ahora solo pasamos IPv6
		conn.Close()
	}()

	quit := make(chan struct{})

	// Goroutine: TUN del servidor -> TLS al cliente
	go func() {
		packet := make([]byte, 2000)
		for {
			select {
			case <-quit:
				return
			default:
				n, err := ifce.Read(packet)
				if err != nil {
					log.Printf("⚠ Error al leer del TUN del servidor (%s): %v\n", peerCN, err)
					close(quit)
					return
				}

				// Solo nos interesan los paquetes IPv6 salientes del TUN
				ipVersion := "Desconocido"
				if n > 0 && (packet[0]>>4) == 6 {
					ipVersion = "0x60"
				} else if n > 0 && (packet[0]>>4) == 4 { // Esto es un paquete IPv4 inesperado
					log.Printf("⚠ [TUN -> TLS CLIENT (%s)] Paquete IPv4 inesperado detectado en el TUN del servidor (%d bytes). Descartando. Tipo IP: 0x%x\n", peerCN, n, (packet[0]>>4)<<4)
					continue // Descartar y continuar
				}

				if debugMode {
					log.Printf("[TUN -> TLS CLIENT (%s)] Leídos %d bytes del TUN del servidor. Tipo IP: %s\n", peerCN, n, ipVersion)
				}

				vpnPacket := make([]byte, 1+n)
				vpnPacket[0] = VPN_PACKET_TYPE_DATA
				copy(vpnPacket[1:], packet[:n])

				_, err = conn.Write(vpnPacket)
				if err != nil {
					log.Printf("⚠ Error al escribir en TLS al cliente (%s): %v\n", peerCN, err)
					close(quit)
					return
				}
				if debugMode {
					log.Printf("[TUN -> TLS CLIENT (%s)] Escritos %d bytes (incl. encabezado) a la conexión TLS.\n", peerCN, len(vpnPacket))
				}
			}
		}
	}()

	// Bucle principal: TLS del cliente -> TUN del servidor (incluye firewall)
	buffer := make([]byte, 2000)
	for {
		select {
		case <-quit:
			return
		default:
			n, err := conn.Read(buffer)
			if err != nil {
				if err == io.EOF {
					log.Printf("Cliente %s cerró la conexión.\n", peerCN)
				} else {
					log.Printf("⚠ Error al leer de TLS del cliente (%s): %v\n", peerCN, err)
				}
				close(quit)
				return
			}
			if n > 0 {
				packetType := buffer[0]

				switch packetType {
				case VPN_PACKET_TYPE_DATA:
					if n > 1 {
						ipPacket := buffer[1:n]

						if debugMode {
							log.Printf("[DEBUG-FIREWALL] Recibido paquete de %d bytes. Primer byte (versión): 0x%x", len(ipPacket), ipPacket[0])
						}
						ipVersion := ipPacket[0] >> 4
						if debugMode {
							log.Printf("[DEBUG-FIREWALL] Versión IP detectada: %d", ipVersion)
						}

						if ipVersion == 6 { // SOLO procesamos IPv6
							if len(ipPacket) < 40 { // IPv6 header min length is 40 bytes
								log.Printf("⚠ [SERVER-FIREWALL] Recibido paquete de DATOS de cliente %s demasiado corto (%d bytes) para ser un encabezado IPv6 válido. Descartando.\n", peerCN, len(ipPacket))
								continue // Descartar este paquete
							}

							srcIP := net.IP(ipPacket[8:24])  // IPv6 Source Address is bytes 8-23
							dstIP := net.IP(ipPacket[24:40]) // IPv6 Destination Address is bytes 24-39

							if debugMode {
								log.Printf("[DEBUG-FIREWALL] IPs extraídas: Origen: %s, Destino: %s", srcIP, dstIP)
							}

							if isIPv6Blocked(srcIP) {
								log.Printf("🚫 [SERVER-FIREWALL] Bloqueado paquete de origen sospechoso %s desde cliente %s. Destino: %s\n", srcIP, peerCN, dstIP)
								continue
							}
							if isIPv6Blocked(dstIP) {
								log.Printf("🚫 [SERVER-FIREWALL] Bloqueado paquete a destino sospechoso %s desde cliente %s. Origen: %s\n", dstIP, peerCN, srcIP)
								continue
							}

							// Write the IPv6 packet to the TUN interface
							if debugMode {
								log.Printf("[TLS CLIENT -> TUN (%s)] Escritos %d bytes (datos IP) al TUN del servidor. Tipo IP del payload: 0x60\n", peerCN, len(ipPacket))
							}

							_, err = ifce.Write(ipPacket)
							if err != nil {
								log.Printf("⚠ Error al escribir al TUN del servidor (%s): %v\n", peerCN, err)
								return // Error crítico, salir
							}
						} else { // Si no es IPv6 (podría ser IPv4 o algo desconocido)
							log.Printf("⚠ [SERVER-FIREWALL] Recibido paquete de cliente %s con versión IP no IPv6 (0x%x). Descartando. Tamaño: %d\n", peerCN, ipVersion, len(ipPacket))
							continue // Descartar este paquete
						}
					} else {
						log.Printf("⚠ [TLS CLIENT -> TUN (%s)] Recibido paquete de DATOS sin payload. Tamaño total: %d\n", peerCN, n)
					}
				case VPN_PACKET_TYPE_TERMINATE:
					log.Printf("ℹ️ [SERVER] Recibido mensaje de TERMINACIÓN de cliente %s. Cerrando conexión.\n", peerCN)
					close(quit)
					return
				case VPN_PACKET_TYPE_KEEPALIVE:
					log.Printf("ℹ️ [SERVER] Recibido KEEPALIVE de cliente %s.\n", peerCN)
				case VPN_PACKET_TYPE_IP_ASSIGNMENT:
					log.Printf("⚠ [SERVER] Recibido paquete de ASIGNACIÓN DE IP del cliente %s. Esto es inesperado. Descartando.\n", peerCN)
				default:
					log.Printf("⚠ [SERVER] Recibido paquete VPN de tipo desconocido (0x%02x) de cliente %s. Descartando. Tamaño: %d\n", packetType, peerCN, n)
				}
			} else {
				log.Println("⚠ [SERVER] Recibido paquete vacío de TLS.")
			}
		}
	}
}
