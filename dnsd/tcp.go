package main

import (
	"fmt"
	"log"
	"net"
	"runtime"
)

func initTcp(errch chan<- error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 53})
	if err != nil {
		// retry on port 8053 (probably not root)
		l, err = net.ListenTCP("tcp", &net.TCPAddr{Port: 8053})
		if err != nil {
			errch <- fmt.Errorf("failed to listen TCP: %w", err)
			return
		}
	}

	// one thread per cpu since we'll spawn extra threads per connected clients
	cnt := runtime.NumCPU()

	for i := 0; i < cnt; i++ {
		go tcpThread(l)
	}
	log.Printf("[tcp] listening on port %s with %d goroutines", l.Addr().String(), cnt)
}

func tcpThread(l *net.TCPListener) {
}
