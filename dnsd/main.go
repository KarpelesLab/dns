package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/TrisTech/goupd"
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

	errch := make(chan error)

	go initUdp(errch)
	go initTcp(errch)

	select {
	case err := <-errch:
		log.Printf("[main] init failed: %s", err)
		os.Exit(1)
	case <-shutdownChannel:
	}

	log.Printf("[main] Bye bye")
}
