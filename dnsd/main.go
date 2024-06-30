package main

import (
	"log"
	"net"
	"os"

	"github.com/KarpelesLab/goupd"
	"github.com/KarpelesLab/shutdown"
)

func main() {
	shutdown.SetupSignals()
	log.Printf("[main] Initializing dnsd...")
	goupd.AutoUpdate(false)

	// we perform db init first because we need it
	err := initDb()
	if err != nil {
		log.Printf("[main] database init failed: %s", err)
		os.Exit(1)
	}

	log.Printf("[main] API access key for this instance is: %s", getApiKey())

	ips := getIps()

	go initUdp(ips)
	go initTcp(ips)
	go initHttps(ips)

	shutdown.Wait()

	log.Printf("[main] Bye bye")
}

func getIps() []net.IP {
	ips := []net.IP{}

	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet: // default
				ip := v.IP
				if !ip.IsGlobalUnicast() {
					log.Printf("[main] ignoring local ip %s", ip)
					continue
				}
				ips = append(ips, ip)
			default:
				log.Printf("[main] failed to analyze machine ip: unhandled addr type %T", v)
			}
		}
	}

	return ips
}
