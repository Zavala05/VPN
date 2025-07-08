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
	VPN_PACKET_TYPE_DATA        byte = 0x01
	VPN_PACKET_TYPE_TERMINATE   byte = 0x02
	VPN_PACKET_TYPE_KEEPALIVE   byte = 0x03
	VPN_PACKET_TYPE_IP_ASSIGNMENT byte = 0x04
)

const (
	serverAddr      = ":8443"
	vpnTunIPv4      = "10.8.0.1/24"
	vpnTunIPv6      = "fd00::1/64"
	vpnTunNetIPv4 = "10.8.0.0/24"
	vpnTunNetIPv6 = "fd00::/64"
)

var (
	ipv4Pool = make(map[uint8]bool)
	ipv6Pool = make(map[uint16]bool)

	clientIPv4Assignments = make(map[string]net.IP)
	clientIPv6Assignments = make(map[string]net.IP)

	poolMutex sync.Mutex
)

var blockedIPv6s = []net.IP{
	net.ParseIP("fd00::b"),
	net.ParseIP("2001:db8::2"),
}

func isIPv6Blocked(ip net.IP) bool {
	if ip == nil || ip.To16() == nil {
		log.Printf("[DEBUG-FIREWALL] isIPv6Blocked: IP es nil o no es IPv6 válida: %v", ip)
		return false
	}
	for _, blockedIP := range blockedIPv6s {
		if blockedIP.Equal(ip) {
			log.Printf("[DEBUG-FIREWALL] isIPv6Blocked: IP %s MATCHEA con IP BLOQUEADA %s", ip, blockedIP)
			return true
		}
	}
	log.Printf("[DEBUG-FIREWALL] isIPv6Blocked: IP %s NO está bloqueada.", ip)
	return false
}

func initIPPool() {
	for i := uint8(10); i <= 254; i++ {
		ipv4Pool[i] = false
	}
	for i := uint16(10); i <= 0xFFFE; i++ {
		ipv6Pool[i] = false
	}
	log.Println("✅ Pools de IPs inicializados.")
}

func assignIP(clientCN string) (net.IP, net.IP, error) {
	poolMutex.Lock()
	defer poolMutex.Unlock()

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
		releaseIP(clientCN, assignedIPv4, nil)
		return nil, nil, fmt.Errorf("no hay IPs IPv6 disponibles")
	}

	clientIPv4Assignments[clientCN] = assignedIPv4
	clientIPv6Assignments[clientCN] = assignedIPv6

	return assignedIPv4, assignedIPv6, nil
}

func releaseIP(clientCN string, ipv4ToRelease net.IP, ipv6ToRelease net.IP) {
	poolMutex.Lock()
	defer poolMutex.Unlock()

	if ipv4ToRelease != nil {
		if ipv4 := ipv4ToRelease.To4(); ipv4 != nil {
			if ipv4[2] == 8 && ipv4[3] >= 10 && ipv4[3] <= 254 {
				ipv4Pool[ipv4[3]] = false
				delete(clientIPv4Assignments, clientCN)
				log.Printf("ℹ IPv4 %s liberada para %s", ipv4ToRelease.String(), clientCN)
			}
		}
	}

	if ipv6ToRelease != nil {
		if ipv6 := ipv6ToRelease.To16(); ipv6 != nil {
			if bytes.Equal(ipv6[:8], net.ParseIP("fd00::").To16()[:8]) {
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
	initIPPool()

	serverCert, err := tls.LoadX509KeyPair("../certs/server.crt", "../certs/server.key")
	if err != nil {
		log.Fatalf("❌ Error al cargar el certificado o la clave del servidor: %v", err)
	}
	fmt.Println("✅ Certificado y clave del servidor cargados.")

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
	var out []byte

	if runtime.GOOS == "windows" {
		vpnTunIPv6Addr := strings.Split(vpnTunIPv6, "/")[0]

		log.Printf("Limpiando dirección IPv6 antigua %s de la interfaz %s...", vpnTunIPv6Addr, ifce.Name())
		cmd = exec.Command("netsh", "interface", "ipv6", "delete", "address", ifce.Name(), vpnTunIPv6Addr)
		out, err = cmd.CombinedOutput()
		if err != nil && !netshOutputContains(out, "Element not found.") && !netshOutputContains(out, "no se encontr") {
			log.Printf("⚠ Advertencia: Error al intentar limpiar dirección IPv6: %v. Salida: %s", err, string(out))
		} else {
			log.Printf("ℹ Intento de limpiar dirección IPv6. Salida: %s", string(out))
		}

		cmd = exec.Command("netsh", "interface", "ip", "set", "address", ifce.Name(), "static", "10.8.0.1", "255.255.255.0")
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv4 de la interfaz TUN en Windows: %v", err)
		}
		cmd = exec.Command("netsh", "interface", "ipv6", "add", "address", ifce.Name(), vpnTunIPv6Addr)
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv6 de la interfaz TUN en Windows: %v", err)
		}
		cmd = exec.Command("netsh", "interface", "set", "interface", "name="+ifce.Name(), "admin=enable")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Advertencia: No se pudo activar la interfaz %s en Windows. Error: %v\n", ifce.Name(), err)
		}
		cmd = exec.Command("netsh", "interface", "ipv6", "set", "interface", ifce.Name(), "forwarding=enabled")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Advertencia: No se pudo habilitar el reenvío de IPv6 en la interfaz %s: %v\n", ifce.Name(), err)
		}
	} else {
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
		cmd = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Advertencia: No se pudo habilitar el reenvío de IPv6 a nivel de SO: %v\n", err)
		}
	}
	fmt.Printf("✅ Interfaz TUN %s configurada con IP IPv4 %s e IP IPv6 %s\n", ifce.Name(), vpnTunIPv4, vpnTunIPv6)
	fmt.Println("⚠ Asegúrate de habilitar el IP forwarding y NAT en tu sistema operativo si deseas que los clientes acceden a Internet.")

	listener, err := tls.Listen("tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Fatalf("❌ Error al crear el listener TLS en %s: %v", serverAddr, err)
	}
	defer listener.Close()
	fmt.Printf("🚀 Servidor VPN escuchando en %s con TLS (mTLS activo)...\n", serverAddr)

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

	fmt.Printf("✅ Conexión aceptada desde %s (CN: %s)\n", conn.RemoteAddr(), peerCN)

	assignedIPv4, assignedIPv6, err := assignIP(peerCN)
	if err != nil {
		log.Printf("❌ Error al asignar IP para el cliente %s: %v. Cerrando conexión.", peerCN, err)
		conn.Close()
		return
	}
	log.Printf("✅ IP asignada a cliente %s: IPv4 %s, IPv6 %s\n", peerCN, assignedIPv4, assignedIPv6)

	ipAssignmentPayload := make([]byte, 4+16)
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

	defer func() {
		fmt.Printf("🚫 Conexión desde %s (CN: %s) cerrada.\n", conn.RemoteAddr(), peerCN)
		releaseIP(peerCN, assignedIPv4, assignedIPv6)
		conn.Close()
	}()

	quit := make(chan struct{})

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

				vpnPacket := make([]byte, 1+n)
				vpnPacket[0] = VPN_PACKET_TYPE_DATA
				copy(vpnPacket[1:], packet[:n])

				_, err = conn.Write(vpnPacket)
				if err != nil {
					log.Printf("⚠ Error al escribir en TLS al cliente (%s): %v\n", peerCN, err)
					close(quit)
					return
				}
				fmt.Printf("[TUN -> TLS CLIENT (%s)] Escritos %d bytes (incl. encabezado) a la conexión TLS.\n", peerCN, len(vpnPacket))
			}
		}
	}()

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
			if n > 0 {
				packetType := buffer[0]

				switch packetType {
				case VPN_PACKET_TYPE_DATA:
					if n > 1 {
						ipPacket := buffer[1:n]

						log.Printf("[DEBUG-FIREWALL] Recibido paquete de %d bytes. Primer byte (versión): 0x%x", len(ipPacket), ipPacket[0])
						if len(ipPacket) >= 40 {
							ipVersion := ipPacket[0] >> 4
							log.Printf("[DEBUG-FIREWALL] Versión IP detectada: %d", ipVersion)

							if ipVersion == 6 {
								srcIP := net.IP(ipPacket[8:24])
								dstIP := net.IP(ipPacket[24:40])

								log.Printf("[DEBUG-FIREWALL] IPs extraídas: Origen: %s, Destino: %s", srcIP, dstIP)

								if isIPv6Blocked(srcIP) {
									log.Printf("🚫 [SERVER-FIREWALL] Bloqueado paquete de origen sospechoso %s desde cliente %s. Destino: %s\n", srcIP, peerCN, dstIP)
									return
								}
								if isIPv6Blocked(dstIP) {
									log.Printf("🚫 [SERVER-FIREWALL] Bloqueado paquete a destino sospechoso %s desde cliente %s. Origen: %s\n", dstIP, peerCN, srcIP)
									return
								}
							} else if ipVersion == 4 {
								log.Printf("[DEBUG-FIREWALL] Paquete es IPv4 (0x%x). No se aplica filtro IPv6.", ipVersion)
							} else {
								log.Printf("⚠ [SERVER-FIREWALL] Paquete con versión IP desconocida (0x%x). Descartando.", ipVersion)
								return
							}
						} else {
							log.Printf("⚠ [SERVER-FIREWALL] Recibido paquete de DATOS demasiado corto (%d bytes) para ser un encabezado IPv6 válido. Descartando.\n", len(ipPacket))
							return
						}

						ipVersionDebug := "Desconocido"
						if len(ipPacket) > 0 {
							if (ipPacket[0] >> 4) == 4 {
								ipVersionDebug = "0x40"
							} else if (ipPacket[0] >> 4) == 6 {
								ipVersionDebug = "0x60"
							}
						}

						_, err = ifce.Write(ipPacket)
						if err != nil {
							log.Printf("⚠ Error al escribir al TUN del servidor (%s): %v\n", peerCN, err)
							return
						}
						fmt.Printf("[TLS CLIENT -> TUN (%s)] Escritos %d bytes (datos IP) al TUN del servidor. Tipo IP del payload: %s\n", peerCN, len(ipPacket), ipVersionDebug)
					} else {
						log.Printf("⚠ [TLS CLIENT -> TUN (%s)] Recibido paquete de DATOS sin payload. Tamaño total: %d\n", peerCN, n)
					}
				case VPN_PACKET_TYPE_TERMINATE:
					log.Printf("ℹ [SERVER] Recibido mensaje de TERMINACIÓN de cliente %s. Cerrando conexión.\n", peerCN)
					close(quit)
					return
				case VPN_PACKET_TYPE_KEEPALIVE:
					log.Printf("ℹ [SERVER] Recibido KEEPALIVE de cliente %s.\n")
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