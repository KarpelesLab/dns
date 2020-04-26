package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"

	"github.com/KarpelesLab/dns/dnsmsg"
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
	for {
		c, err := l.AcceptTCP()
		if err != nil {
			log.Printf("[tcp] failed to accept connection: %s", err)
			return
		}

		go tcpClient(c)
	}
}

func tcpClient(c *net.TCPConn) {
	defer c.Close()

	for {
		// tcp packet first has 2 bytes packet len
		var l uint16

		err := binary.Read(c, binary.BigEndian, &l)
		if err != nil {
			if err == io.EOF {
				// not an error
				return
			}
			log.Printf("[tcp] failed to read packet len from %s: %s", c.RemoteAddr(), err)
			return
		}

		buf := make([]byte, l)
		_, err = io.ReadFull(c, buf)
		if err != nil {
			log.Printf("[tcp] failed to read packet from %s: %s", c.RemoteAddr(), err)
			return
		}

		handleTcpPacket(buf, c)
	}
}

func handleTcpPacket(buf []byte, c *net.TCPConn) {
	// parse pkg
	msg, err := dnsmsg.Parse(buf)
	if err != nil {
		log.Printf("[tcp] failed to parse msg from %s: %s", c.RemoteAddr(), err)
		return
	}

	res, err := handleQuery(msg, c.RemoteAddr())
	if err != nil {
		log.Printf("[tcp] failed to respond to %s: %s", c.RemoteAddr(), err)
		return
	}
	if res == nil {
		// no response needed
		return
	}

	buf, err = res.MarshalBinary()
	if err != nil {
		log.Printf("[tcp] failed to make response to %s: %s", c.RemoteAddr(), err)
		return
	}

	// write packet len + packet
	if len(buf) > 65535 {
		log.Printf("[tcp] failed to respond (packet too big) to %s", c.RemoteAddr())
		return
	}

	binary.Write(c, binary.BigEndian, uint16(len(buf)))
	_, err = c.Write(buf)
	if err != nil {
		log.Printf("[tcp] failed to write to %s: %s", c.RemoteAddr(), err)
		c.Close()
		return
	}
}
