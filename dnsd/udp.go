package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"

	"github.com/KarpelesLab/dns/dnsmsg"
)

func initUdp(errch chan<- error) {
	cfg := &net.ListenConfig{Control: udpControl}

	l, err := cfg.ListenPacket(context.Background(), "udp", ":53")
	if err != nil {
		// retry on port 8053 (probably not root)
		l, err = cfg.ListenPacket(context.Background(), "udp", ":8053")
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

func udpThread(l net.PacketConn) {
	buf := make([]byte, 1500)

	for {
		n, addr, err := l.ReadFrom(buf)

		if err != nil {
			log.Printf("[udp] failed to read: %s", err)
			return
		}

		handleUdpPacket(buf[:n], addr)
	}
}

func handleUdpPacket(buf []byte, addr net.Addr) {
	// parse pkg
	msg, err := dnsmsg.Parse(buf)
	if err != nil {
		log.Printf("[udp] failed to parse msg from %s: %s", addr, err)
		return
	}

	log.Printf("[udp] msg: %s", msg)
}
