package main

import (
	"errors"
	"log"
	"net"

	"github.com/KarpelesLab/dns/dnsmsg"
)

func handleQuery(pkt *dnsmsg.Message, laddr, raddr net.Addr) (*dnsmsg.Message, error) {
	log.Printf("handle query: %s", pkt)

	if pkt.Bits.IsResponse() || pkt.Bits.OpCode() != dnsmsg.Query || len(pkt.Question) != 1 {
		return nil, errors.New("not a query")
	}

	q := pkt.Question[0]
	pkt.Bits.SetResponse(true)

	zone, name, sub, err := getZone(q.Name, laddr)
	if err != nil {
		// not found
		pkt.Bits.SetRCode(dnsmsg.ErrName)
		return pkt, nil
	}

	// we have authority
	pkt.Bits.SetAuth(true)
	pkt.Base = string(reverseDnsName(name))
	err = zone.handleQuery(pkt, q, sub)

	if err != nil {
		// not found, or something?
		pkt.Bits.SetRCode(dnsmsg.ErrName)
	}

	return pkt, nil
}
