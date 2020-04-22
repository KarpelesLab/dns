package main

import (
	"errors"
	"log"
	"net"

	"github.com/KarpelesLab/dns/dnsmsg"
)

func handleQuery(pkt *dnsmsg.Message, addr net.Addr) (*dnsmsg.Message, error) {
	log.Printf("handle query: %s", pkt)

	if pkt.Bits.IsResponse() || pkt.Bits.OpCode() != dnsmsg.Query || len(pkt.Question) != 1 {
		return nil, errors.New("not a query")
	}

	q := pkt.Question[0]
	_ = q

	pkt.Bits.SetResponse(true)
	pkt.Bits.SetRCode(dnsmsg.ErrName)

	return pkt, nil
}
