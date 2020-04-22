package main

import (
	"fmt"
	"log"
	"net"
	"runtime"
)

func initUdp(errch chan<- error) {
	laddr := &net.UDPAddr{Port: 53}

	l, err := net.ListenUDP("udp", laddr)
	if err != nil {
		// retry on port 8053 (probably not root)
		laddr.Port = 8053
		l, err = net.ListenUDP("udp", laddr)
		if err != nil {
			errch <- fmt.Errorf("failed to listen UDP: %w", err)
			return
		}
	}

	// two threads per cpu
	cnt := runtime.NumCPU() * 2

	for i := 0; i < cnt; i++ {
		go udpThread(l)
	}
	log.Printf("[udp] listening on port %s with %d threads", l.LocalAddr().String(), cnt)
}

func udpThread(l *net.UDPConn) {
	buf := make([]byte, 1500)

	for {
		n, addr, err := l.ReadFromUDP(buf)

		if err != nil {
			log.Printf("[udp] failed to read: %s", err)
			return
		}

		handleUdpPacket(buf[:n], addr)
	}
}

func handleUdpPacket(buf []byte, addr *net.UDPAddr) {
	// TODO
}
