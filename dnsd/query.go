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

	// test
	switch q.Name {
	case "ns1.zedns.net.":
		pkt.Bits.SetAuth(true)
		if q.Class == dnsmsg.IN && q.Type == dnsmsg.A {
			pkt.Answer = append(pkt.Answer, &dnsmsg.Resource{
				Name:  "ns1.zedns.net.",
				Class: dnsmsg.IN,
				Type:  dnsmsg.A,
				TTL:   86400,

				Data: &dnsmsg.RDataIP{IP: net.IPv4(18, 181, 102, 53), Type: dnsmsg.A},
			})
		}
		return pkt, nil
	case "ns2.zedns.net.":
		pkt.Bits.SetAuth(true)
		if q.Class == dnsmsg.IN && q.Type == dnsmsg.A {
			pkt.Answer = append(pkt.Answer, &dnsmsg.Resource{
				Name:  "ns2.zedns.net.",
				Class: dnsmsg.IN,
				Type:  dnsmsg.A,
				TTL:   86400,

				Data: &dnsmsg.RDataIP{IP: net.IPv4(34, 237, 237, 237), Type: dnsmsg.A},
			})
		}
		return pkt, nil
	case "ns3.zedns.net.":
		pkt.Bits.SetAuth(true)
		if q.Class == dnsmsg.IN && q.Type == dnsmsg.A {
			pkt.Answer = append(pkt.Answer, &dnsmsg.Resource{
				Name:  "ns3.zedns.net.",
				Class: dnsmsg.IN,
				Type:  dnsmsg.A,
				TTL:   86400,

				Data: &dnsmsg.RDataIP{IP: net.IPv4(3, 11, 47, 103), Type: dnsmsg.A},
			})
		}
		return pkt, nil
	}

	pkt.Bits.SetRCode(dnsmsg.ErrName)

	return pkt, nil
}
