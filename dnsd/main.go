package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/KarpelesLab/goupd"
)

var (
	shutdownChannel = make(chan struct{})
)

func shutdown() {
	log.Println("[main] shutting down...")
	close(shutdownChannel)
}

func setupSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	go func() {
		<-c
		shutdown()
	}()
}

func main() {
	setupSignals()
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

	errch := make(chan error)

	go initUdp(ips, errch)
	go initTcp(ips, errch)
	go initHttps(ips, errch)

	select {
	case err := <-errch:
		log.Printf("[main] init failed: %s", err)
		os.Exit(1)
	case <-shutdownChannel:
	}

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
