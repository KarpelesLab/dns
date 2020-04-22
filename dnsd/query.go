package main

import (
	"errors"
	"log"
	"net"

	"github.com/KarpelesLab/dns/dnsmsg"
)

func handleQuery(pkt *dnsmsg.Message, addr net.Addr) (*dnsmsg.Message, error) {
	log.Printf("handle query: %s", pkt)

	if pkt.Bits.IsResponse() || pkt.Bits.OpCode() != dnsmsg.Query {
		return nil, errors.New("not a query")
	}
	return nil, nil
}
