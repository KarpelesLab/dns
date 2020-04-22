package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
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

	errch := make(chan error)

	go initUdp(errch)

	select {
	case err := <-errch:
		log.Printf("[main] init failed: %s", err)
		return
	case <-shutdownChannel:
	}

	log.Printf("[main] Bye bye")
}
