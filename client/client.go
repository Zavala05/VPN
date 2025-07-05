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

// Constantes para los tipos de paquete de la VPN (DEBEN COINCIDIR CON EL SERVIDOR)
const (
	VPN_PACKET_TYPE_DATA          byte = 0x01 // Paquete que contiene datos IP (IPv4 o IPv6)
	VPN_PACKET_TYPE_TERMINATE     byte = 0x02 // Mensaje para indicar terminación de conexión
	VPN_PACKET_TYPE_KEEPALIVE     byte = 0x03 // Mensaje para mantener la conexión viva
	VPN_PACKET_TYPE_IP_ASSIGNMENT byte = 0x04 // Nuevo: Mensaje para asignar IP al cliente
)

const (
	serverHost = "192.168.0.27" // IP pública del servidor VPN
	serverPort = "8443"
	// clientTunIPv4 y clientTunIPv6 ya no son constantes fijas, se asignarán dinámicamente.
	clientTunMask = "255.255.255.0" // Máscara de subred IPv4 (puede ser fija para la VPN)
	serverTunIPv4 = "10.8.0.1"      // IP IPv4 del servidor en la red VPN (gateway)
	serverTunIPv6 = "fd00::1"       // IP IPv6 del servidor en la red VPN (gateway)
)

func main() {
	// 1. Cargar el certificado de la CA y el certificado/clave del cliente
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
		ServerName:   "MyVPN_Server", // Debe coincidir con el CN del certificado del servidor
	}

	// 2. Conectar al servidor TLS
	conn, err := tls.Dial("tcp", serverHost+":"+serverPort, tlsConfig)
	if err != nil {
		log.Fatalf("❌ Error al conectar al servidor TLS en %s:%s: %v", serverHost, serverPort, err)
	}
	defer conn.Close()
	fmt.Printf("🚀 Conectado al servidor VPN en %s:%s con TLS (mTLS activo).\n", serverHost, serverPort)

	// --- NUEVO: Esperar y recibir IPs del servidor ---
	log.Println("Esperando asignación de IP del servidor...")
	ipAssignmentBuffer := make([]byte, 2000)
	n, err := conn.Read(ipAssignmentBuffer) // Intentar leer el primer paquete (debería ser la asignación de IP)
	if err != nil {
		log.Fatalf("❌ Error al leer la asignación de IP del servidor: %v", err)
	}
	if n < 1 { // Asegurarse de que el paquete no está vacío
		log.Fatalf("❌ Recibido paquete de asignación de IP vacío.")
	}

	packetType := ipAssignmentBuffer[0]
	if packetType != VPN_PACKET_TYPE_IP_ASSIGNMENT {
		log.Fatalf("❌ Se esperaba paquete de asignación de IP (0x%02x), pero se recibió 0x%02x", VPN_PACKET_TYPE_IP_ASSIGNMENT, packetType)
	}
	if n < 1+4+16 { // Longitud mínima: Tipo (1 byte) + IPv4 (4 bytes) + IPv6 (16 bytes)
		log.Fatalf("❌ Paquete de asignación de IP demasiado corto. Longitud: %d", n)
	}

	// Extraer IPs del payload del paquete de asignación
	assignedIPv4 := net.IPv4(ipAssignmentBuffer[1], ipAssignmentBuffer[2], ipAssignmentBuffer[3], ipAssignmentBuffer[4])
	assignedIPv6 := make(net.IP, 16)
	copy(assignedIPv6, ipAssignmentBuffer[5:21]) // Del byte 5 al 20 son los 16 bytes de IPv6

	// Para fines de depuración, convertimos assignedIPv6 a su representación de cadena
	displayIPv6 := assignedIPv6.String()

	log.Printf("✅ IPs asignadas por el servidor: IPv4 %s, IPv6 %s\n", assignedIPv4.String(), displayIPv6)

	// 3. Crear y configurar la interfaz TUN del cliente (AHORA CON LAS IPS ASIGNADAS)
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

	// Asignamos las IPs dinámicas a variables locales para la configuración del TUN
	currentClientTunIPv4 := assignedIPv4.String()
	// Para netsh, el add address requiere solo la IP, no el /64
	currentClientTunIPv6NoPrefix := strings.Split(assignedIPv6.String()+"/64", "/")[0]
	currentClientTunIPv6WithPrefix := assignedIPv6.String() + "/64" // Para Linux/macOS, que sí lo necesita

	if runtime.GOOS == "windows" {
		// Obtener el índice de la interfaz
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

		// --- NUEVO: Limpieza agresiva de TODAS las rutas por defecto IPv6 antes de añadir las nuestras ---
		log.Println("Limpiando rutas IPv6 por defecto existentes (::/0)...")
		cmd = exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", "interface="+strconv.Itoa(ifaceIndex))
		out, _ = cmd.CombinedOutput()
		log.Printf("ℹ️ Intento de limpiar ruta ::/0 en interfaz TUN. Salida: %s\n", string(out))

		// Limpiar rutas IPv4 antiguas a 10.8.0.1 (serverTunIPv4)
		log.Println("Limpiando rutas antiguas a 10.8.0.1...")
		cmd = exec.Command("route", "DELETE", serverTunIPv4)
		out, _ = cmd.CombinedOutput()
		log.Printf("ℹ️ Intento de limpiar ruta para %s. Salida: %s\n", serverTunIPv4, string(out))

		// Limpiar rutas IPv4 por defecto antiguas creadas por VPN
		log.Println("Limpiando rutas por defecto antiguas creadas por VPN...")
		cmd = exec.Command("route", "DELETE", "0.0.0.0", "MASK", "0.0.0.0", serverTunIPv4)
		out, _ = cmd.CombinedOutput()
		log.Printf("ℹ️ Intento de limpiar ruta por defecto a través de %s. Salida: %s\n", serverTunIPv4, string(out))

		// Limpiar rutas IPv6 por defecto antiguas a través del gateway de la VPN (por si acaso)
		log.Println("Limpiando rutas IPv6 por defecto antiguas creadas por VPN (via gateway)...")
		cmd = exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", ifce.Name(), serverTunIPv6)
		out, _ = cmd.CombinedOutput()
		log.Printf("ℹ️ Intento de limpiar ruta IPv6 por defecto a través de %s. Salida: %s\n", ifce.Name(), string(out))

		// Limpiar dirección IPv6 antigua (si existiera una estática preconfigurada en la interfaz TUN por una ejecución previa)
		log.Printf("Limpiando dirección IPv6 antigua %s de la interfaz %s...", currentClientTunIPv6NoPrefix, ifce.Name())
		cmd = exec.Command("netsh", "interface", "ipv6", "delete", "address", ifce.Name(), currentClientTunIPv6NoPrefix)
		out, _ = cmd.CombinedOutput()
		// Ignoramos el error si la dirección no se encuentra, pero registramos otros errores.
		if err != nil && !netshOutputContains(out, "Element not found.") && !netshOutputContains(out, "no se encontr") {
			log.Printf("⚠ Advertencia: Error al intentar limpiar dirección IPv6 en cliente: %v. Salida: %s", err, string(out))
		} else {
			log.Printf("ℹ️ Intento de limpiar dirección IPv6 en cliente. Salida: %s", string(out))
		}

		// Configurar IP IPv4 dinámica en la interfaz TUN
		cmd = exec.Command("netsh", "interface", "ip", "set", "address", ifce.Name(), "static", currentClientTunIPv4, clientTunMask)
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv4 de la interfaz TUN en Windows: %v", err)
		}
		// Configurar IP IPv6 dinámica en la interfaz TUN
		cmd = exec.Command("netsh", "interface", "ipv6", "add", "address", ifce.Name(), currentClientTunIPv6NoPrefix)
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv6 de la interfaz TUN en Windows: %v", err)
		}
		// Activar la interfaz
		cmd = exec.Command("netsh", "interface", "set", "interface", "name="+ifce.Name(), "admin=enable")
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Advertencia: No se pudo activar la interfaz %s en Windows. Error: %v\n", ifce.Name(), err)
		}

		// Pequeño retraso para que la interfaz se asiente
		time.Sleep(1 * time.Second)

		// Configurar ruta IPv4 específica para el servidor VPN
		log.Printf("Configurando ruta IPv4 específica para el servidor VPN (%s) directamente en la interfaz TUN con métrica 5...", serverTunIPv4)
		cmd = exec.Command("route", "ADD", serverTunIPv4, "MASK", "255.255.255.255", "0.0.0.0", "METRIC", "5", "IF", strconv.Itoa(ifaceIndex))
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("❌ Error al añadir ruta IPv4 para %s usando índice %d: %s\n", serverTunIPv4, ifaceIndex, string(out))
		} else {
			log.Printf("✅ Ruta IPv4 para %s añadida a través de la interfaz (índice %d) con métrica 5. Salida: %s\n", serverTunIPv4, ifaceIndex, string(out))
		}

		// Configurar ruta IPv4 por defecto a través de la VPN
		log.Println("Configurando ruta IPv4 por defecto a través de la VPN con métrica 10...")
		cmd = exec.Command("route", "ADD", "0.0.0.0", "MASK", "0.0.0.0", serverTunIPv4, "METRIC", "10", "IF", strconv.Itoa(ifaceIndex))
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("❌ Error al configurar la ruta IPv4 por defecto a través de la VPN: %s", string(out))
		} else {
			log.Printf("✅ Ruta IPv4 por defecto configurada a través de la VPN con métrica 10. Salida: %s\n", string(out))
		}

		// Configurar ruta IPv6 por defecto a través de la VPN
		// ¡IMPORTANTE! Aseguramos que esta ruta tenga una métrica que la haga preferida
		log.Printf("Configurando ruta IPv6 por defecto a través de la VPN (%s) con métrica 10...", serverTunIPv6)
		cmd = exec.Command("netsh", "interface", "ipv6", "add", "route", "::/0", ifce.Name(), serverTunIPv6, "metric=10") // Métrica 10
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("❌ Error al configurar la ruta IPv6 por defecto a través de la VPN: %s", string(out))
		} else {
			log.Printf("✅ Ruta IPv6 por defecto configurada a través de la VPN con métrica 10. Salida: %s\n", string(out))
		}

	} else { // Asumimos Linux/macOS
		cmd = exec.Command("ifconfig", ifce.Name(), currentClientTunIPv4+"/24", "up")
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv4 de la interfaz TUN: %v", err)
		}
		cmd = exec.Command("ip", "-6", "addr", "add", currentClientTunIPv6WithPrefix, "dev", ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la IP IPv6 de la interfaz TUN: %v", err)
		}
		// Limpiar y añadir rutas, similar a como se hace en Windows para un inicio limpio
		cmd = exec.Command("ip", "route", "del", serverTunIPv4, "dev", ifce.Name())
		cmd.Run() // Ignorar errores si la ruta no existe
		cmd = exec.Command("ip", "route", "add", serverTunIPv4, "dev", ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Error al añadir ruta IPv4 para el servidor VPN: %v", err)
		}
		cmd = exec.Command("route", "del", "default")
		cmd.Run() // Ignorar errores si la ruta no existe
		cmd = exec.Command("route", "add", "default", "gw", serverTunIPv4, ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Printf("⚠ Error al agregar la ruta IPv4 por defecto a la VPN: %v", err)
		}
		cmd = exec.Command("ip", "-6", "route", "del", "::/0", "via", serverTunIPv6, "dev", ifce.Name())
		cmd.Run() // Ignorar errores si la ruta no existe
		cmd = exec.Command("ip", "-6", "route", "add", "::/0", "via", serverTunIPv6, "dev", ifce.Name())
		if err := cmd.Run(); err != nil {
			log.Fatalf("❌ Error al configurar la ruta IPv6 por defecto a través de la VPN: %v", err)
		}
	}

	fmt.Printf("✅ Interfaz TUN %s configurada dinámicamente con IP IPv4 %s e IP IPv6 %s\n", ifce.Name(), currentClientTunIPv4, currentClientTunIPv6WithPrefix)
	fmt.Println("⚠ Advertencia: Todo el tráfico de la red puede ser enrutado a través de la VPN.")

	quit := make(chan struct{})
	// Goroutine para leer del TUN del cliente y enviar por la conexión TLS al servidor
	go func() {
		packet := make([]byte, 2000)
		for {
			select {
			case <-quit:
				return
			default:
				// fmt.Println("[CLIENT] Esperando paquetes del TUN...") // Demasiado ruidoso
				n, err := ifce.Read(packet)
				if err != nil {
					log.Printf("⚠ Error al leer del TUN del cliente: %v\n", err)
					close(quit)
					return
				}
				// Determinar el tipo de IP para depuración
				ipVersion := "Desconocido"
				if n > 0 {
					if (packet[0] >> 4) == 4 { // IPv4
						ipVersion = "0x40"
					} else if (packet[0] >> 4) == 6 { // IPv6
						ipVersion = "0x60"
					}
				}
				fmt.Printf("[CLIENT -> TLS] Leídos %d bytes del TUN. Tipo IP: %s\n", n, ipVersion)

				// --- Prepend el encabezado de tipo de paquete ---
				vpnPacket := make([]byte, 1+n)      // 1 byte para el tipo + n bytes del paquete IP
				vpnPacket[0] = VPN_PACKET_TYPE_DATA // El primer byte es nuestro tipo de paquete (DATOS)
				copy(vpnPacket[1:], packet[:n])     // Copiamos el paquete IP real después del encabezado

				_, err = conn.Write(vpnPacket) // Enviamos el paquete con nuestro encabezado
				if err != nil {
					log.Printf("⚠ Error al escribir en TLS del cliente: %v\n", err)
					close(quit)
					return
				}
				fmt.Printf("[CLIENT -> TLS] Escritos %d bytes (incl. encabezado) a la conexión TLS.\n", len(vpnPacket))
			}
		}
	}()

	// Bucle principal para leer de la conexión TLS del servidor y escribir al TUN del cliente
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
			// --- MODIFICADO: Leer el encabezado del paquete VPN ---
			if n > 0 {
				packetType := buffer[0] // El primer byte es el tipo de paquete
				// fmt.Printf("[TLS -> CLIENT] Leídos %d bytes de la conexión TLS. Tipo de Paquete VPN: 0x%02x\n", n, packetType) // Demasiado ruidoso

				// Procesar según el tipo de paquete
				switch packetType {
				case VPN_PACKET_TYPE_DATA:
					if n > 1 { // Asegurarse de que hay datos después del tipo
						// Determinar el tipo de IP para depuración del payload (paquete IP)
						ipVersion := "Desconocido"
						if n > 1 && (buffer[1]>>4) == 4 { // IPv4
							ipVersion = "0x40"
						} else if n > 1 && (buffer[1]>>4) == 6 { // IPv6
							ipVersion = "0x60"
						}
						_, err = ifce.Write(buffer[1:n]) // Escribir solo los datos IP (después del primer byte de tipo)
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
					// No se hace nada más que registrar para un keep-alive simple.
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

// netshOutputContains es una función de utilidad para verificar la salida de netsh
func netshOutputContains(output []byte, s string) bool {
	return bytes.Contains(output, []byte(s))
}
