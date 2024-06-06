package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

var (
	targetIP     string
	targetPorts  string
	silentMode   bool
	device       string
	timeout      time.Duration = 10 * time.Second
)

var rootCmd = &cobra.Command{
	Use:   "portscanner",
	Short: "A simple port scanner CLI",
	Long: `Portscanner is a CLI tool to scan ports on specified IP addresses.
It supports scanning multiple ports and IPs concurrently.`,
	Run: func(cmd *cobra.Command, args []string) {
		runPortScanner()
	},
}

func init() {
	rootCmd.Flags().StringVarP(&targetIP, "ip", "i", "", "IP address or range to scan (e.g., 192.168.1.1/24)")
	rootCmd.Flags().StringVarP(&targetPorts, "ports", "p", "", "Ports to scan (e.g., 80,443,1000-2000)")
	rootCmd.Flags().BoolVarP(&silentMode, "silent", "s", false, "Enable silent mode (only print open ports)")
	rootCmd.Flags().StringVarP(&device, "interface", "d", "", "Network interface to use for scanning")
	rootCmd.MarkFlagRequired("ip")
	rootCmd.MarkFlagRequired("ports")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runPortScanner() {
	if !silentMode {
		fmt.Printf("Starting port scan on IP: %s, ports: %s\n", targetIP, targetPorts)
	}

	ipRange := expandIPRange(targetIP)
	ports := parsePortList(targetPorts)
	scanPorts(ipRange, ports)
}

func expandIPRange(ip string) []string {
	ips := make([]string, 0)
	ip, ipnet, err := net.ParseCIDR(ip)
	if err != nil {
		log.Fatal(err)
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parsePortList(ports string) []int {
	portList := make([]int, 0)
	portRanges := strings.Split(ports, ",")
	for _, portRange := range portRanges {
		if strings.Contains(portRange, "-") {
			rangeLimits := strings.Split(portRange, "-")
			startPort := parseInt(rangeLimits[0])
			endPort := parseInt(rangeLimits[1])
			for port := startPort; port <= endPort; port++ {
				portList = append(portList, port)
			}
		} else {
			port := parseInt(portRange)
			portList = append(portList, port)
		}
	}
	return portList
}

func parseInt(portStr string) int {
	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil {
		log.Fatalf("Invalid port number: %s", portStr)
	}
	return port
}

func scanPorts(ips []string, ports []int) {
	var wg sync.WaitGroup
	for _, ip := range ips {
		for _, port := range ports {
			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				scanPort(ip, port)
			}(ip, port)
		}
	}
	wg.Wait()
}

func scanPort(ip string, port int) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return // Port is closed or filtered
	}
	defer conn.Close()

	service := getService(port)
	fmt.Printf("IP: %s, Port: %d - Open, Service: %s\n", ip, port, service)
}

func getService(port int) string {
	switch port {
	case 20:
		return "FTP Data"
	case 21:
		return "FTP Control"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	default:
		return "Unknown"
	}
}
