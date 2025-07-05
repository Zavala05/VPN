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
	"sync" // Necesario para Mutex

	"github.com/songgao/water" // Importación necesaria para la interfaz TUN
)

// Constantes para los tipos de paquete de la VPN
const (
	VPN_PACKET_TYPE_DATA          byte = 0x01 // Paquete que contiene datos IP (IPv4 o IPv6)
	VPN_PACKET_TYPE_TERMINATE     byte = 0x02 // Mensaje para indicar terminación de conexión
	VPN_PACKET_TYPE_KEEPALIVE     byte = 0x03 // Mensaje para mantener la conexión viva
	VPN_PACKET_TYPE_IP_ASSIGNMENT byte = 0x04 // Nuevo: Mensaje para asignar IP al cliente
)

const (
	serverAddr    = ":8443"       // Puerto TCP/TLS del servidor
	vpnTunIPv4    = "10.8.0.1/24" // IP y máscara IPv4 para la interfaz TUN del servidor
	vpnTunIPv6    = "fd00::1/64"  // IP y máscara IPv6 para la interfaz TUN del servidor
	vpnTunNetIPv4 = "10.8.0.0/24" // Red virtual IPv4 de la VPN
	vpnTunNetIPv6 = "fd00::/64"   // Red virtual IPv6 de la VPN
)

// IP Management Structures
var (
	// Pool de IPs IPv4 disponibles para clientes (ej. 10.8.0.10 - 10.8.0.254)
	ipv4Pool = make(map[uint8]bool) // true = asignada, false = disponible
	// Pool de IPs IPv6 disponibles para clientes (ej. fd00::10 - fd00::fffe)
	ipv6Pool = make(map[uint16]bool) // usando los últimos 2 bytes de la IP como identificador

	// Asignaciones actuales: CN del cliente -> IP asignada
	clientIPv4Assignments = make(map[string]net.IP)
	clientIPv6Assignments = make(map[string]net.IP)

	poolMutex sync.Mutex // Mutex para proteger el acceso a los pools de IP y asignaciones
)

// Lista de IPs IPv6 a bloquear. Ahora bloquearemos un DESTINO específico (fd00::c)
var blockedIPv6s = []net.IP{
	net.ParseIP("fd00::b"),     // Esta es la IP que bloquearemos.
	net.ParseIP("2001:db8::2"), // Otra IP IPv6 de ejemplo externa para bloquear (si fuera enrutable)
}

// isIPv6Blocked verifica si una IP IPv6 está en la lista de bloqueados
func isIPv6Blocked(ip net.IP) bool {
	if ip == nil || ip.To16() == nil {
		log.Printf("[DEBUG-FIREWALL] isIPv6Blocked: IP es nil o no es IPv6 válida: %v", ip) // Depuración
		return false                                                                        // No es una IP IPv6 válida
	}
	for _, blockedIP := range blockedIPv6s {
		if blockedIP.Equal(ip) {
			log.Printf("[DEBUG-FIREWALL] isIPv6Blocked: IP %s MATCHEA con IP BLOQUEADA %s", ip, blockedIP) // Depuración
			return true
		}
	}
	log.Printf("[DEBUG-FIREWALL] isIPv6Blocked: IP %s NO está bloqueada.", ip) // Depuración
	return false
}

// initIPPool inicializa los pools de direcciones IP disponibles
func initIPPool() {
	for i := uint8(10); i <= 254; i++ { // 10.8.0.10 a 10.8.0.254
		ipv4Pool[i] = false // Marcar como disponible
	}
	for i := uint16(10); i <= 0xFFFE; i++ { // fd00::10 a fd00::fffe
		ipv6Pool[i] = false // Marcar como disponible
	}
	log.Println("✅ Pools de IPs inicializados.")
}

// assignIP intenta asignar una IP IPv4 y una IPv6 a un cliente
func assignIP(clientCN string) (net.IP, net.IP, error) {
	poolMutex.Lock()
	defer poolMutex.Unlock()

	// 1. Asignar IPv4
	var assignedIPv4 net.IP
	for i := uint8(10); i <= 254; i++ {
		if !ipv4Pool[i] {
			assignedIPv4 = net.IPv4(10, 8, 0, i)
			ipv4Pool[i] = true
			break
		}
	}
	if assignedIPv4 == nil {
		return nil, nil, fmt.Errorf("no hay IPs IPv4 disponibles")
	}

	// 2. Asignar IPv6
	var assignedIPv6 net.IP
	for i := uint16(10); i <= 0xFFFE; i++ {
		potentialIPv6 := net.ParseIP(fmt.Sprintf("fd00::%x", i))
		if !ipv6Pool[i] {
			if potentialIPv6 == nil {
				continue
			}
			assignedIPv6 = potentialIPv6
			ipv6Pool[i] = true
			break
		}
	}
	if assignedIPv6 == nil {
		// Si IPv6 falla, liberar la IPv4 ya asignada
		releaseIP(clientCN, assignedIPv4, nil)
		return nil, nil, fmt.Errorf("no hay IPs IPv6 disponibles")
	}

	clientIPv4Assignments[clientCN] = assignedIPv4
	clientIPv6Assignments[clientCN] = assignedIPv6

	return assignedIPv4, assignedIPv6, nil
}

// releaseIP libera las IPs asignadas a un cliente
func releaseIP(clientCN string, ipv4ToRelease net.IP, ipv6ToRelease net.IP) {
	poolMutex.Lock()
	defer poolMutex.Unlock()

	if ipv4ToRelease != nil {
		if ipv4 := ipv4ToRelease.To4(); ipv4 != nil {
			if ipv4[2] == 8 && ipv4[3] >= 10 && ipv4[3] <= 254 { // Asegurarse de que está en nuestro rango
				ipv4Pool[ipv4[3]] = false
				delete(clientIPv4Assignments, clientCN)
				log.Printf("ℹ IPv4 %s liberada para %s", ipv4ToRelease.String(), clientCN)
			}
		}
	}

	if ipv6ToRelease != nil {
		if ipv6 := ipv6ToRelease.To16(); ipv6 != nil {
			// fd00::XXXX -> los últimos 2 bytes son el identificador
			if bytes.Equal(ipv6[:8], net.ParseIP("fd00::").To16()[:8]) { // Comprobar prefijo fd00::/64
				id := uint16(ipv6[14])<<8 | uint16(ipv6[15])
				if id >= 10 && id <= 0xFFFE {
					ipv6Pool[id] = false
					delete(clientIPv6Assignments, clientCN)
					log.Printf("ℹ IPv6 %s liberada para %s", ipv6ToRelease.String(), clientCN)
				}
			}
		}
	}
}

func main() {
	initIPPool() // Inicializar los pools de IP

	// 1. Cargar el certificado del servidor y la clave privada
	serverCert, err := tls.LoadX509KeyPair("../certs/server.crt", "../certs/server.key")
	if err != nil {
		log.Fatalf("❌ Error al cargar el certificado o la clave del servidor: %v", err)
	}
	fmt.Println("✅ Certificado y clave del servidor cargados.")

	// 2. Cargar el certificado de la CA para verificar a los clientes (para mTLS)
	caCertPEM, err := ioutil.ReadFile("../certs/ca.crt")
	if err != nil {
		log.Fatalf("❌ Error al cargar el certificado de la CA: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		log.Fatalf("❌ Error al agregar el certificado de la CA al pool")
	}
	fmt.Println("✅ Certificado de la CA cargado para verificación de clientes.")

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// 3. Crear y configurar la interfaz TUN del servidor
	config := water.Config{
		DeviceType: water.TUN,
	}
	if runtime.GOOS == "windows" {
		config.PlatformSpecificParams = water.PlatformSpecificParams{}
	}

	ifce, err := water.New(config)
	if err != nil {
		log.Fatalf("❌ Error al crear la interfaz TUN: %v", err)
	}
	defer ifce.Close()
	fmt.Printf("✅ Interfaz TUN creada: %s\n", ifce.Name())

	log.Println("Configurando la interfaz TUN. Necesitas ejecutar este programa con privilegios de administrador.")

	var cmd *exec.Cmd
	var out []byte // Declarar 'out' para capturar la salida de los comandos netsh

	if runtime.GOOS == "windows" {
		// Extraer solo la dirección IPv6 sin el prefijo para netsh
		vpnTunIPv6Addr := strings.Split(vpnTunIPv6, "/")[0] // fd00::1

		// Limpiar dirección IPv6 antigua
		log.Printf("Limpiando dirección IPv6 antigua %s de la interfaz %s...", vpnTunIPv6Addr, ifce.Name())
		cmd = exec.Command("netsh", "interface", "ipv6", "delete", "address", ifce.Name(), vpnTunIPv6Addr)
		out, err = cmd.CombinedOutput()                                                                                  // Capturar salida y error
		if err != nil && !netshOutputContains(out, "Element not found.") && !netshOutputContains(out, "no se encontr") { // "no se encontr" para español
			log.Printf("⚠ Advertencia: Error al intentar limpiar dirección IPv6: %v. Salida: %s", err, string(out))
		} else {
			log.Printf("ℹ Intento de limpiar dirección IPv6. Salida: %s", string(out))
		}

		// Configurar IPv4 para la interfaz TUN
		cmd = exec.Command("netsh", "interface", "ip", "set", "address", ifce.Name(), "static", "10.8.0.1", "255.255.255.0")
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv4 de la interfaz TUN en Windows: %v", err)
		}
		// Configurar IPv6 para la interfaz TUN
		cmd = exec.Command("netsh", "interface", "ipv6", "add", "address", ifce.Name(), vpnTunIPv6Addr)
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv6 de la interfaz TUN en Windows: %v", err)
		}
		// Activar la interfaz
		cmd = exec.Command("netsh", "interface", "set", "interface", "name="+ifce.Name(), "admin=enable")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Advertencia: No se pudo activar la interfaz %s en Windows. Error: %v\n", ifce.Name(), err)
		}
		// Habilitar el reenvío de IPv6 en la interfaz (Esto es solo para la interfaz, no el SO global)
		cmd = exec.Command("netsh", "interface", "ipv6", "set", "interface", ifce.Name(), "forwarding=enabled")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Advertencia: No se pudo habilitar el reenvío de IPv6 en la interfaz %s: %v\n", ifce.Name(), err)
		}
	} else { // Asumimos Linux/macOS
		cmd = exec.Command("ifconfig", ifce.Name(), vpnTunIPv4, "up")
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv4 de la interfaz TUN: %v", err)
		}
		cmd = exec.Command("ip", "-6", "addr", "add", vpnTunIPv6, "dev", ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv6 de la interfaz TUN: %v", err)
		}
		cmd = exec.Command("route", "add", "-net", vpnTunNetIPv4, "dev", ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al agregar la ruta IPv4 VPN: %v", err)
		}
		cmd = exec.Command("ip", "-6", "route", "add", vpnTunNetIPv6, "dev", ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Error al agregar la ruta IPv6 VPN: %v", err)
		}
		// Habilitar IP forwarding para IPv6 en Linux
		cmd = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Advertencia: No se pudo habilitar el reenvío de IPv6 a nivel de SO: %v\n", err)
		}
	}
	fmt.Printf("✅ Interfaz TUN %s configurada con IP IPv4 %s e IP IPv6 %s\n", ifce.Name(), vpnTunIPv4, vpnTunIPv6)
	fmt.Println("⚠ Asegúrate de habilitar el IP forwarding y NAT en tu sistema operativo si deseas que los clientes acceden a Internet.")

	// 4. Crear un listener TLS
	listener, err := tls.Listen("tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Fatalf("❌ Error al crear el listener TLS en %s: %v", serverAddr, err)
	}
	defer listener.Close()
	fmt.Printf("🚀 Servidor VPN escuchando en %s con TLS (mTLS activo)...\n", serverAddr)

	// 5. Aceptar y manejar conexiones entrantes
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("⚠ Error al aceptar la conexión: %v", err)
			continue
		}
		go handleServerConnection(conn, ifce)
	}
}

// netshOutputContains es una función de utilidad para verificar la salida de netsh
func netshOutputContains(output []byte, s string) bool {
	return bytes.Contains(output, []byte(s))
}

// handleServerConnection maneja una conexión TLS de un cliente.
func handleServerConnection(conn net.Conn, ifce *water.Interface) {
	// Obtenemos el CN del cliente para la asignación de IP y liberación
	peerCN := "Desconocido" // Valor predeterminado
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

	fmt.Printf("✅ Conexión aceptada desde %s (CN: %s)\n", conn.RemoteAddr(), peerCN)

	// Asignar IP al cliente
	assignedIPv4, assignedIPv6, err := assignIP(peerCN)
	if err != nil {
		log.Printf("❌ Error al asignar IP para el cliente %s: %v. Cerrando conexión.", peerCN, err)
		conn.Close()
		return
	}
	log.Printf("✅ IP asignada a cliente %s: IPv4 %s, IPv6 %s\n", peerCN, assignedIPv4, assignedIPv6)

	// Enviar paquete de asignación de IP al cliente
	// Formato del payload: [IPv4 (4 bytes)] [IPv6 (16 bytes)]
	ipAssignmentPayload := make([]byte, 4+16) // 4 bytes para IPv4, 16 para IPv6
	copy(ipAssignmentPayload[0:4], assignedIPv4.To4())
	copy(ipAssignmentPayload[4:20], assignedIPv6.To16())

	vpnPacket := make([]byte, 1+len(ipAssignmentPayload))
	vpnPacket[0] = VPN_PACKET_TYPE_IP_ASSIGNMENT
	copy(vpnPacket[1:], ipAssignmentPayload)

	_, err = conn.Write(vpnPacket)
	if err != nil {
		log.Printf("❌ Error al enviar paquete de asignación de IP a %s: %v. Liberando IPs y cerrando conexión.", peerCN, err)
		releaseIP(peerCN, assignedIPv4, assignedIPv6)
		conn.Close()
		return
	}
	log.Printf("✅ Paquete de asignación de IP enviado a %s. IPs: %s (IPv4), %s (IPv6)\n", peerCN, assignedIPv4, assignedIPv6)

	// Defer para liberar la IP cuando la conexión se cierre
	defer func() {
		fmt.Printf("🚫 Conexión desde %s (CN: %s) cerrada.\n", conn.RemoteAddr(), peerCN)
		releaseIP(peerCN, assignedIPv4, assignedIPv6)
		conn.Close()
	}()

	quit := make(chan struct{})

	// Goroutine 1: Leer de la interfaz TUN del SERVIDOR y enviar por la conexión TLS al cliente
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

				ipVersion := "Desconocido"
				if n > 0 {
					if (packet[0] >> 4) == 4 {
						ipVersion = "0x40"
					} else if (packet[0] >> 4) == 6 {
						ipVersion = "0x60"
					}
				}
				fmt.Printf("[TUN -> TLS CLIENT (%s)] Leídos %d bytes del TUN del servidor. Tipo IP: %s\n", peerCN, n, ipVersion)

				// Prepend el encabezado de tipo de paquete
				vpnPacket := make([]byte, 1+n)      // 1 byte para el tipo + n bytes del paquete IP
				vpnPacket[0] = VPN_PACKET_TYPE_DATA // El primer byte es nuestro tipo de paquete (DATOS)
				copy(vpnPacket[1:], packet[:n])     // Copiamos el paquete IP real después del encabezado

				_, err = conn.Write(vpnPacket) // Enviamos el paquete con nuestro encabezado
				if err != nil {
					log.Printf("⚠ Error al escribir en TLS al cliente (%s): %v\n", peerCN, err)
					close(quit) // Importante: si no se puede escribir al cliente, la goroutine debe terminar
					return
				}
				fmt.Printf("[TUN -> TLS CLIENT (%s)] Escritos %d bytes (incl. encabezado) a la conexión TLS.\n", peerCN, len(vpnPacket))
			}
		}
	}()

	// Goroutine 2: Leer de la conexión TLS del cliente y escribir a la interfaz TUN del SERVIDOR
	buffer := make([]byte, 2000)
	for {
		select {
		case <-quit:
			return
		default:
			n, err := conn.Read(buffer)
			if err != nil {
				if err == io.EOF {
					fmt.Printf("Cliente %s cerró la conexión.\n", peerCN)
				} else {
					log.Printf("⚠ Error al leer de TLS del cliente (%s): %v\n", peerCN, err)
				}
				close(quit)
				return
			}
			// Leer el encabezado del paquete VPN
			if n > 0 {
				packetType := buffer[0] // El primer byte es el tipo de paquete

				// Procesar según el tipo de paquete
				switch packetType {
				case VPN_PACKET_TYPE_DATA:
					if n > 1 { // Asegurarse de que hay datos después del tipo
						// Extraer el paquete IP real (después de nuestro encabezado)
						ipPacket := buffer[1:n]

						// Lógica de Firewall Básico (IPv6)
						log.Printf("[DEBUG-FIREWALL] Recibido paquete de %d bytes. Primer byte (versión): 0x%x", len(ipPacket), ipPacket[0]) // Depuración
						if len(ipPacket) >= 40 {                                                                                             // Un paquete IPv6 tiene al menos 40 bytes de encabezado
							ipVersion := ipPacket[0] >> 4                                      // Versión IP
							log.Printf("[DEBUG-FIREWALL] Versión IP detectada: %d", ipVersion) // Depuración

							if ipVersion == 6 { // Si es un paquete IPv6
								srcIP := net.IP(ipPacket[8:24])  // Dirección de origen IPv6 (bytes 8-23 del encabezado IPv6)
								dstIP := net.IP(ipPacket[24:40]) // Dirección de destino IPv6 (bytes 24-39 del encabezado IPv6)

								log.Printf("[DEBUG-FIREWALL] IPs extraídas: Origen: %s, Destino: %s", srcIP, dstIP) // Depuración

								// Verificamos tanto IP de origen como de destino contra la lista de bloqueados
								if isIPv6Blocked(srcIP) {
									log.Printf("🚫 [SERVER-FIREWALL] Bloqueado paquete de origen sospechoso %s desde cliente %s. Destino: %s\n", srcIP, peerCN, dstIP)
									return // Descartar el paquete
								}
								if isIPv6Blocked(dstIP) {
									log.Printf("🚫 [SERVER-FIREWALL] Bloqueado paquete a destino sospechoso %s desde cliente %s. Origen: %s\n", dstIP, peerCN, srcIP)
									return // Descartar el paquete
								}
							} else if ipVersion == 4 {
								log.Printf("[DEBUG-FIREWALL] Paquete es IPv4 (0x%x). No se aplica filtro IPv6.", ipVersion) // Depuración
							} else {
								log.Printf("⚠ [SERVER-FIREWALL] Paquete con versión IP desconocida (0x%x). Descartando.", ipVersion) // Depuración
								return                                                                                               // Descartar paquetes con versión IP desconocida
							}
						} else {
							log.Printf("⚠ [SERVER-FIREWALL] Recibido paquete de DATOS demasiado corto (%d bytes) para ser un encabezado IPv6 válido. Descartando.\n", len(ipPacket))
							return // Descartar paquetes inválidos
						}
						// --- FIN Lógica de Firewall Básico ---

						// Determinar el tipo de IP para depuración del payload (paquete IP)
						ipVersionDebug := "Desconocido"
						if len(ipPacket) > 0 { // Asegurarse de que hay al menos 1 byte para leer la versión
							if (ipPacket[0] >> 4) == 4 { // IPv4
								ipVersionDebug = "0x40"
							} else if (ipPacket[0] >> 4) == 6 { // IPv6
								ipVersionDebug = "0x60"
							}
						}

						_, err = ifce.Write(ipPacket) // Escribir solo los datos IP (después del primer byte de tipo)
						if err != nil {
							log.Printf("⚠ Error al escribir al TUN del servidor (%s): %v\n", peerCN, err)
							return // Solo descarta el paquete y continúa con la conexión
						}
						fmt.Printf("[TLS CLIENT -> TUN (%s)] Escritos %d bytes (datos IP) al TUN del servidor. Tipo IP del payload: %s\n", peerCN, len(ipPacket), ipVersionDebug)
					} else {
						log.Printf("⚠ [TLS CLIENT -> TUN (%s)] Recibido paquete de DATOS sin payload. Tamaño total: %d\n", peerCN, n)
					}
				case VPN_PACKET_TYPE_TERMINATE:
					log.Printf("ℹ [SERVER] Recibido mensaje de TERMINACIÓN de cliente %s. Cerrando conexión.\n", peerCN)
					close(quit) // Señal para terminar la goroutine
					return      // Terminar el bucle principal de esta goroutine
				case VPN_PACKET_TYPE_KEEPALIVE:
					log.Printf("ℹ [SERVER] Recibido KEEPALIVE de cliente %s.\n")
					// No se hace nada más que registrar para un keep-alive simple.
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
