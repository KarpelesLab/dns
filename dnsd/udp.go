package main

import (
	"context"
	"log"
	"net"
	"runtime"

	"github.com/KarpelesLab/dns/dnsmsg"
	"github.com/KarpelesLab/shutdown"
)

func initUdp(ips []net.IP) {
	if len(ips) == 0 {
		listenUdp(nil)
	}
	for _, ip := range ips {
		listenUdp(ip)
	}
}

func listenUdp(ip net.IP) {
	cfg := &net.ListenConfig{Control: udpControl}

	var ipstr string
	if ip4 := ip.To4(); ip4 != nil {
		ipstr = ip4.String()
	} else if ip != nil {
		ipstr = "[" + ip.String() + "]"
	}

	l, err := cfg.ListenPacket(context.Background(), "udp", ipstr+":53")
	if err != nil {
		// retry on port 8053 (probably not root)
		l, err = cfg.ListenPacket(context.Background(), "udp", ipstr+":8053")
		if err != nil {
			shutdown.Fatalf("failed to listen UDP: %w", err)
			return
		}
	}

	// two threads per cpu
	cnt := runtime.NumCPU() * 2

	for i := 0; i < cnt; i++ {
		go udpThread(l)
	}
	log.Printf("[udp] listening on port %s with %d goroutines", l.LocalAddr().String(), cnt)
}

func udpThread(l net.PacketConn) {
	buf := make([]byte, 1500)
	laddr := l.LocalAddr()

	for {
		n, addr, err := l.ReadFrom(buf)

		if err != nil {
			log.Printf("[udp] failed to read: %s", err)
			return
		}

		handleUdpPacket(buf[:n], l, laddr, addr)
	}
}

func handleUdpPacket(buf []byte, l net.PacketConn, laddr, raddr net.Addr) {
	// parse pkg
	msg, err := dnsmsg.Parse(buf)
	if err != nil {
		log.Printf("[udp] failed to parse msg from %s: %s", raddr, err)
		return
	}

	res, err := handleQuery(msg, laddr, raddr)
	if err != nil {
		log.Printf("[udp] failed to respond to %s: %s", raddr, err)
		return
	}
	if res == nil {
		// no response needed
		return
	}

	buf, err = res.MarshalBinary()
	if err != nil {
		log.Printf("[udp] failed to make response to %s: %s", raddr, err)
		return
	}

	l.WriteTo(buf, raddr)
}
