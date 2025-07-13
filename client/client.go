package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/songgao/water"
)

const (
	VPN_PACKET_TYPE_DATA          byte = 0x01
	VPN_PACKET_TYPE_TERMINATE     byte = 0x02
	VPN_PACKET_TYPE_KEEPALIVE     byte = 0x03
	VPN_PACKET_TYPE_IP_ASSIGNMENT byte = 0x04
)

const (
	serverHost    = "192.168.0.27"
	serverPort    = "8443"
	serverTunIPv6 = "fd00::1" // Solo mantenemos la IP del servidor TUN para IPv6
)

// debugMode controla la verbosidad de los logs.
// Cambia a 'false' para deshabilitar los logs detallados de tráfico.
var debugMode = true

func main() {
	caCertPEM, err := ioutil.ReadFile("../certs/ca.crt")
	if err != nil {
		log.Fatalf("❌ Error al cargar el certificado de la CA: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		log.Fatalf("❌ Error al agregar el certificado de la CA al pool")
	}
	log.Println("✅ Certificado de la CA cargado para verificación del servidor.")

	clientCert, err := tls.LoadX509KeyPair("../certs/client.crt", "../certs/client.key")
	if err != nil {
		log.Fatalf("❌ Error al cargar el certificado o la clave del cliente: %v", err)
	}
	log.Println("✅ Certificado y clave del cliente cargados.")

	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "MyVPN_Server",
	}

	conn, err := tls.Dial("tcp", serverHost+":"+serverPort, tlsConfig)
	if err != nil {
		log.Fatalf("❌ Error al conectar al servidor TLS en %s:%s: %v", serverHost, serverPort, err)
	}
	defer conn.Close()
	log.Printf("🚀 Conectado al servidor VPN en %s:%s con TLS (mTLS activo).\n", serverHost, serverPort)

	log.Println("Esperando asignación de IP del servidor...")
	ipAssignmentBuffer := make([]byte, 2000)
	n, err := conn.Read(ipAssignmentBuffer)
	if err != nil {
		log.Fatalf("❌ Error al leer la asignación de IP del servidor: %v", err)
	}
	if n < 1 {
		log.Fatalf("❌ Recibido paquete de asignación de IP vacío.")
	}

	packetType := ipAssignmentBuffer[0]
	if packetType != VPN_PACKET_TYPE_IP_ASSIGNMENT {
		log.Fatalf("❌ Se esperaba paquete de asignación de IP (0x%02x), pero se recibió 0x%02x", VPN_PACKET_TYPE_IP_ASSIGNMENT, packetType)
	}
	// Ahora solo esperamos la IP IPv6 (1 byte de tipo + 16 bytes de IPv6)
	if n < 1+16 {
		log.Fatalf("❌ Paquete de asignación de IP demasiado corto. Longitud: %d. Se esperaba al menos 17 bytes para IPv6.", n)
	}

	// Asumimos que la asignación de IP solo contendrá IPv6 a partir de ahora
	assignedIPv6 := make(net.IP, 16)
	copy(assignedIPv6, ipAssignmentBuffer[1:17]) // Copiamos los 16 bytes de IPv6

	displayIPv6 := assignedIPv6.String()

	log.Printf("✅ IP asignada por el servidor: IPv6 %s\n", displayIPv6)

	config := water.Config{
		DeviceType: water.TUN,
	}
	// runtime.GOOS es "windows", así que esta rama siempre se ejecutará
	config.PlatformSpecificParams = water.PlatformSpecificParams{}

	ifce, err := water.New(config)
	if err != nil {
		log.Fatalf("❌ Error al crear la interfaz TUN: %v", err)
	}
	defer ifce.Close()
	log.Printf("✅ Interfaz TUN creada: %s\n", ifce.Name())

	log.Println("Configurando la interfaz TUN. Necesitas ejecutar este programa con privilegios de administrador.")

	var cmd *exec.Cmd
	var out []byte

	currentClientTunIPv6NoPrefix := strings.Split(assignedIPv6.String()+"/64", "/")[0]
	currentClientTunIPv6WithPrefix := assignedIPv6.String() + "/64"

	// Lógica de configuración específica para Windows (solo IPv6)
	ifaceIndex := -1
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("❌ Error al obtener la lista de interfaces de red: %v", err)
	}
	for _, i := range interfaces {
		if i.Name == ifce.Name() {
			ifaceIndex = i.Index
			break
		}
	}
	if ifaceIndex == -1 {
		log.Fatalf("❌ No se encontró el índice de la interfaz TUN '%s'", ifce.Name())
	}
	log.Printf("✅ Interfaz TUN '%s' encontrada con índice: %d\n", ifce.Name(), ifaceIndex)

	log.Println("Limpiando rutas IPv6 por defecto existentes (::/0)...")
	cmd = exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", "interface="+strconv.Itoa(ifaceIndex))
	out, err = cmd.CombinedOutput()
	if err != nil && !netshOutputContains(out, "Element not found.") && !netshOutputContains(out, "no se encontr") {
		log.Printf("⚠️ Cliente - Advertencia: Error al intentar limpiar ruta ::/0 en interfaz TUN: %v. Salida: %s\n", err, string(out))
	} else {
		log.Printf("ℹ️ Cliente - Intento de limpiar ruta ::/0 en interfaz TUN. Salida: %s\n", string(out))
	}

	// Limpieza de rutas IPv6 por defecto antiguas creadas por VPN (via gateway)...
	log.Println("Limpiando rutas IPv6 por defecto antiguas creadas por VPN (via gateway)...")
	cmd = exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", ifce.Name(), serverTunIPv6)
	out, err = cmd.CombinedOutput()
	if err != nil && !netshOutputContains(out, "Element not found.") && !netshOutputContains(out, "no se encontr") {
		log.Printf("⚠️ Cliente - Advertencia: Error al intentar limpiar ruta IPv6 por defecto a través de %s: %v. Salida: %s\n", ifce.Name(), err, string(out))
	} else {
		log.Printf("ℹ️ Cliente - Intento de limpiar ruta IPv6 por defecto a través de %s. Salida: %s\n", ifce.Name(), string(out))
	}

	log.Printf("Limpiando dirección IPv6 antigua %s de la interfaz %s...", currentClientTunIPv6NoPrefix, ifce.Name())
	cmd = exec.Command("netsh", "interface", "ipv6", "delete", "address", ifce.Name(), currentClientTunIPv6NoPrefix)
	out, err = cmd.CombinedOutput()
	if err != nil && !netshOutputContains(out, "Element not found.") && !netshOutputContains(out, "no se encontr") {
		log.Printf("⚠️ Advertencia: Error al intentar limpiar dirección IPv6 en cliente: %v. Salida: %s", err, string(out))
	} else {
		log.Printf("ℹ️ Intento de limpiar dirección IPv6 en cliente. Salida: %s", string(out))
	}

	cmd = exec.Command("netsh", "interface", "ipv6", "add", "address", ifce.Name(), currentClientTunIPv6NoPrefix)
	if err := cmd.Run(); err != nil {
		log.Fatalf("❌ Error al configurar la IP IPv6 de la interfaz TUN en Windows: %v", err)
	}
	cmd = exec.Command("netsh", "interface", "set", "interface", "name="+ifce.Name(), "admin=enable")
	if err := cmd.Run(); err != nil {
		log.Printf("⚠️ Advertencia: No se pudo activar la interfaz %s en Windows. Error: %v\n", ifce.Name(), err)
	}

	time.Sleep(1 * time.Second)

	log.Printf("Configurando ruta IPv6 por defecto a través de la VPN (%s) con métrica 10...", serverTunIPv6)
	cmd = exec.Command("netsh", "interface", "ipv6", "add", "route", "::/0", ifce.Name(), serverTunIPv6, "metric=10")
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("❌ Error al configurar la ruta IPv6 por defecto a través de la VPN: %s", string(out))
	} else {
		log.Printf("✅ Ruta IPv6 por defecto configurada a través de la VPN con métrica 10. Salida: %s\n", string(out))
	}

	log.Printf("✅ Interfaz TUN %s configurada dinámicamente con IP IPv6 %s\n", ifce.Name(), currentClientTunIPv6WithPrefix)
	log.Println("⚠️ Advertencia: Todo el tráfico de la red puede ser enrutado a través de la VPN.")

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
					log.Printf("⚠️ Error al leer del TUN del cliente: %v\n", err)
					close(quit)
					return
				}
				ipVersion := "Desconocido"
				if n > 0 {
					// Solo nos preocupamos por IPv6 ahora
					if (packet[0] >> 4) == 6 {
						ipVersion = "0x60"
					} else {
						// Si llega algo que no es IPv6, lo logueamos pero seguimos enviándolo
						// ya que el TUN es de capa 3 y podría recibir otros protocolos
						log.Printf("ℹ️ [CLIENT -> TLS] Paquete no IPv6 (primer byte: 0x%02x) leído del TUN. Longitud: %d\n", packet[0], n)
					}
				}
				// Envuelto en if debugMode
				if debugMode {
					log.Printf("[CLIENT -> TLS] Leídos %d bytes del TUN. Tipo IP: %s\n", n, ipVersion)
				}

				vpnPacket := make([]byte, 1+n)
				vpnPacket[0] = VPN_PACKET_TYPE_DATA
				copy(vpnPacket[1:], packet[:n])

				_, err = conn.Write(vpnPacket)
				if err != nil {
					log.Printf("⚠️ Error al escribir en TLS del cliente: %v\n", err)
					close(quit)
					return
				}
				// Envuelto en if debugMode
				if debugMode {
					log.Printf("[CLIENT -> TLS] Escritos %d bytes (incl. encabezado) a la conexión TLS.\n", len(vpnPacket))
				}
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
					log.Println("Servidor cerró la conexión.")
				} else {
					log.Printf("⚠️ Error al leer del servidor TLS en cliente: %v\n", err)
				}
				close(quit)
				return
			}
			if n > 0 {
				packetType := buffer[0]
				switch packetType {
				case VPN_PACKET_TYPE_DATA:
					if n > 1 {
						ipVersion := "Desconocido"
						// Solo nos preocupamos por IPv6 ahora
						if n > 1 && (buffer[1]>>4) == 6 {
							ipVersion = "0x60"
						} else if n > 1 && (buffer[1]>>4) == 4 {
							log.Printf("⚠️ [TLS -> CLIENT] Recibido paquete IPv4 (0x%02x) a pesar de solo usar IPv6. Descartando. Tamaño total: %d\n", buffer[1], n)
							continue // Descartar paquetes IPv4
						}
						_, err = ifce.Write(buffer[1:n])
						if err != nil {
							log.Printf("⚠️ Error al escribir al TUN del cliente: %v\n", err)
							close(quit)
							return
						}
						// Envuelto en if debugMode
						if debugMode {
							log.Printf("[TLS -> CLIENT] Escritos %d bytes (datos IP) al TUN. Tipo IP del payload: %s\n", n-1, ipVersion)
						}
					} else {
						log.Printf("⚠️ [TLS -> CLIENT] Recibido paquete de DATOS sin payload. Tamaño total: %d\n", n)
					}
				case VPN_PACKET_TYPE_TERMINATE:
					log.Printf("ℹ️ [CLIENT] Recibido mensaje de TERMINACIÓN del servidor. Cerrando conexión.\n")
					close(quit)
					return
				case VPN_PACKET_TYPE_KEEPALIVE:
					log.Printf("ℹ️ [CLIENT] Recibido KEEPALIVE del servidor.\n")
				case VPN_PACKET_TYPE_IP_ASSIGNMENT:
					log.Printf("⚠️ [CLIENT] Recibido paquete de ASIGNACIÓN DE IP del servidor. Esto es inesperado en el bucle principal. Descartando.\n")
				default:
					log.Printf("⚠️ [CLIENT] Recibido paquete VPN de tipo desconocido (0x%02x) del servidor. Descartando. Tamaño: %d\n", packetType, n)
				}
			} else {
				log.Println("⚠️ [TLS -> CLIENT] Recibido paquete vacío de TLS.")
			}
		}
	}
}

func netshOutputContains(output []byte, s string) bool {
	return bytes.Contains(output, []byte(s))
}
