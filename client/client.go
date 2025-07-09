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
	clientTunMask = "255.255.255.0"
	serverTunIPv4 = "10.8.0.1"
	serverTunIPv6 = "fd00::1"
)

func main() {
	caCertPEM, err := ioutil.ReadFile("../certs/ca.crt")
	if err != nil {
		log.Fatalf("❌ Error al cargar el certificado de la CA: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		log.Fatalf("❌ Error al agregar el certificado de la CA al pool")
	}
	fmt.Println("✅ Certificado de la CA cargado para verificación del servidor.")

	clientCert, err := tls.LoadX509KeyPair("../certs/client.crt", "../certs/client.key")
	if err != nil {
		log.Fatalf("❌ Error al cargar el certificado o la clave del cliente: %v", err)
	}
	fmt.Println("✅ Certificado y clave del cliente cargados.")

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
	fmt.Printf("🚀 Conectado al servidor VPN en %s:%s con TLS (mTLS activo).\n", serverHost, serverPort)

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
	if n < 1+4+16 {
		log.Fatalf("❌ Paquete de asignación de IP demasiado corto. Longitud: %d", n)
	}

	assignedIPv4 := net.IPv4(ipAssignmentBuffer[1], ipAssignmentBuffer[2], ipAssignmentBuffer[3], ipAssignmentBuffer[4])
	assignedIPv6 := make(net.IP, 16)
	copy(assignedIPv6, ipAssignmentBuffer[5:21])

	displayIPv6 := assignedIPv6.String()

	log.Printf("✅ IPs asignadas por el servidor: IPv4 %s, IPv6 %s\n", assignedIPv4.String(), displayIPv6)

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

	currentClientTunIPv4 := assignedIPv4.String()
	currentClientTunIPv6NoPrefix := strings.Split(assignedIPv6.String()+"/64", "/")[0]
	currentClientTunIPv6WithPrefix := assignedIPv6.String() + "/64"

	if runtime.GOOS == "windows" {
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
		out, _ = cmd.CombinedOutput()
		log.Printf("ℹ️ Intento de limpiar ruta ::/0 en interfaz TUN. Salida: %s\n", string(out))

		log.Println("Limpiando rutas antiguas a 10.8.0.1...")
		cmd = exec.Command("route", "DELETE", serverTunIPv4)
		out, _ = cmd.CombinedOutput()
		log.Printf("ℹ️ Intento de limpiar ruta para %s. Salida: %s\n", serverTunIPv4, string(out))

		log.Println("Limpiando rutas por defecto antiguas creadas por VPN...")
		cmd = exec.Command("route", "DELETE", "0.0.0.0", "MASK", "0.0.0.0", serverTunIPv4)
		out, _ = cmd.CombinedOutput()
		log.Printf("ℹ️ Intento de limpiar ruta por defecto a través de %s. Salida: %s\n", serverTunIPv4, string(out))

		log.Println("Limpiando rutas IPv6 por defecto antiguas creadas por VPN (via gateway)...")
		cmd = exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", ifce.Name(), serverTunIPv6)
		out, _ = cmd.CombinedOutput()
		log.Printf("ℹ️ Intento de limpiar ruta IPv6 por defecto a través de %s. Salida: %s\n", ifce.Name(), string(out))

		log.Printf("Limpiando dirección IPv6 antigua %s de la interfaz %s...", currentClientTunIPv6NoPrefix, ifce.Name())
		cmd = exec.Command("netsh", "interface", "ipv6", "delete", "address", ifce.Name(), currentClientTunIPv6NoPrefix)
		out, _ = cmd.CombinedOutput()
		if err != nil && !netshOutputContains(out, "Element not found.") && !netshOutputContains(out, "no se encontr") {
			log.Printf("⚠ Advertencia: Error al intentar limpiar dirección IPv6 en cliente: %v. Salida: %s", err, string(out))
		} else {
			log.Printf("ℹ️ Intento de limpiar dirección IPv6 en cliente. Salida: %s", string(out))
		}

		cmd = exec.Command("netsh", "interface", "ip", "set", "address", ifce.Name(), "static", currentClientTunIPv4, clientTunMask)
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv4 de la interfaz TUN en Windows: %v", err)
		}
		cmd = exec.Command("netsh", "interface", "ipv6", "add", "address", ifce.Name(), currentClientTunIPv6NoPrefix)
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv6 de la interfaz TUN en Windows: %v", err)
		}
		cmd = exec.Command("netsh", "interface", "set", "interface", "name="+ifce.Name(), "admin=enable")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Advertencia: No se pudo activar la interfaz %s en Windows. Error: %v\n", ifce.Name(), err)
		}

		time.Sleep(1 * time.Second)

		log.Printf("Configurando ruta IPv4 específica para el servidor VPN (%s) directamente en la interfaz TUN con métrica 5...", serverTunIPv4)
		cmd = exec.Command("route", "ADD", serverTunIPv4, "MASK", "255.255.255.255", "0.0.0.0", "METRIC", "5", "IF", strconv.Itoa(ifaceIndex))
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("❌ Error al añadir ruta IPv4 para %s usando índice %d: %s\n", serverTunIPv4, ifaceIndex, string(out))
		} else {
			log.Printf("✅ Ruta IPv4 para %s añadida a través de la interfaz (índice %d) con métrica 5. Salida: %s\n", serverTunIPv4, ifaceIndex, string(out))
		}

		log.Println("Configurando ruta IPv4 por defecto a través de la VPN con métrica 10...")
		cmd = exec.Command("route", "ADD", "0.0.0.0", "MASK", "0.0.0.0", serverTunIPv4, "METRIC", "10", "IF", strconv.Itoa(ifaceIndex))
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("❌ Error al configurar la ruta IPv4 por defecto a través de la VPN: %s", string(out))
		} else {
			log.Printf("✅ Ruta IPv4 por defecto configurada a través de la VPN con métrica 10. Salida: %s\n", string(out))
		}

		log.Printf("Configurando ruta IPv6 por defecto a través de la VPN (%s) con métrica 10...", serverTunIPv6)
		cmd = exec.Command("netsh", "interface", "ipv6", "add", "route", "::/0", ifce.Name(), serverTunIPv6, "metric=10")
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("❌ Error al configurar la ruta IPv6 por defecto a través de la VPN: %s", string(out))
		} else {
			log.Printf("✅ Ruta IPv6 por defecto configurada a través de la VPN con métrica 10. Salida: %s\n", string(out))
		}

	} else {
		cmd = exec.Command("ifconfig", ifce.Name(), currentClientTunIPv4+"/24", "up")
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv4 de la interfaz TUN: %v", err)
		}
		cmd = exec.Command("ip", "-6", "addr", "add", currentClientTunIPv6WithPrefix, "dev", ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv6 de la interfaz TUN: %v", err)
		}
		cmd = exec.Command("ip", "route", "del", serverTunIPv4, "dev", ifce.Name())
		cmd.Run()
		cmd = exec.Command("ip", "route", "add", serverTunIPv4, "dev", ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Error al añadir ruta IPv4 para el servidor VPN: %v", err)
		}
		cmd = exec.Command("route", "del", "default")
		cmd.Run()
		cmd = exec.Command("route", "add", "default", "gw", serverTunIPv4, ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Error al agregar la ruta IPv4 por defecto a la VPN: %v", err)
		}
		cmd = exec.Command("ip", "-6", "route", "del", "::/0", "via", serverTunIPv6, "dev", ifce.Name())
		cmd.Run()
		cmd = exec.Command("ip", "-6", "route", "add", "::/0", "via", serverTunIPv6, "dev", ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la ruta IPv6 por defecto a través de la VPN: %v", err)
		}
	}

	fmt.Printf("✅ Interfaz TUN %s configurada dinámicamente con IP IPv4 %s e IP IPv6 %s\n", ifce.Name(), currentClientTunIPv4, currentClientTunIPv6WithPrefix)
	fmt.Println("⚠ Advertencia: Todo el tráfico de la red puede ser enrutado a través de la VPN.")

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
					log.Printf("⚠ Error al leer del TUN del cliente: %v\n", err)
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
				fmt.Printf("[CLIENT -> TLS] Leídos %d bytes del TUN. Tipo IP: %s\n", n, ipVersion)

				vpnPacket := make([]byte, 1+n)
				vpnPacket[0] = VPN_PACKET_TYPE_DATA
				copy(vpnPacket[1:], packet[:n])

				_, err = conn.Write(vpnPacket)
				if err != nil {
					log.Printf("⚠ Error al escribir en TLS del cliente: %v\n", err)
					close(quit)
					return
				}
				fmt.Printf("[CLIENT -> TLS] Escritos %d bytes (incl. encabezado) a la conexión TLS.\n", len(vpnPacket))
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
					fmt.Println("Servidor cerró la conexión.")
				} else {
					log.Printf("⚠ Error al leer del servidor TLS en cliente: %v\n", err)
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
						if n > 1 && (buffer[1]>>4) == 4 {
							ipVersion = "0x40"
						} else if n > 1 && (buffer[1]>>4) == 6 {
							ipVersion = "0x60"
						}
						_, err = ifce.Write(buffer[1:n])
						if err != nil {
							log.Printf("⚠ Error al escribir al TUN del cliente: %v\n", err)
							close(quit)
							return
						}
						fmt.Printf("[TLS -> CLIENT] Escritos %d bytes (datos IP) al TUN. Tipo IP del payload: %s\n", n-1, ipVersion)
					} else {
						log.Printf("⚠ [TLS -> CLIENT] Recibido paquete de DATOS sin payload. Tamaño total: %d\n", n)
					}
				case VPN_PACKET_TYPE_TERMINATE:
					log.Printf("ℹ️ [CLIENT] Recibido mensaje de TERMINACIÓN del servidor. Cerrando conexión.\n")
					close(quit)
					return
				case VPN_PACKET_TYPE_KEEPALIVE:
					log.Printf("ℹ️ [CLIENT] Recibido KEEPALIVE del servidor.\n")
				case VPN_PACKET_TYPE_IP_ASSIGNMENT:
					log.Printf("⚠ [CLIENT] Recibido paquete de ASIGNACIÓN DE IP del servidor. Esto es inesperado en el bucle principal. Descartando.\n")
				default:
					log.Printf("⚠ [CLIENT] Recibido paquete VPN de tipo desconocido (0x%02x) del servidor. Descartando. Tamaño: %d\n", packetType, n)
				}
			} else {
				log.Println("⚠ [TLS -> CLIENT] Recibido paquete vacío de TLS.")
			}
		}
	}
}

func netshOutputContains(output []byte, s string) bool {
	return bytes.Contains(output, []byte(s))
}
