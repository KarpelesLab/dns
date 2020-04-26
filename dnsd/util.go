package main

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/KarpelesLab/dns/dnsmsg"
)

func reverseDnsName(n []byte) []byte {
	// reverse dns name, make lowercase, etc
	n = bytes.ToLower(n)

	var res []byte

	for {
		if res != nil {
			res = append(res, '.')
		}

		p := bytes.LastIndexByte(n, '.')
		if p == -1 {
			res = append(res, n...)
			return res
		}

		res = append(res, n[p+1:]...)
		n = n[:p]
	}
}

// bdup is a simple byte duplication function used for bolt results
func bdup(v []byte) []byte {
	if len(v) == 0 {
		return nil
	}

	r := make([]byte, len(v))
	copy(r, v)
	return r
}

func now() []byte {
	// return now as a 12 bytes slice. Big endian is important for ordering
	now := time.Now()
	res := make([]byte, 12)

	binary.BigEndian.PutUint64(res[:8], uint64(now.Unix()))       // no way "now" can be negative
	binary.BigEndian.PutUint32(res[8:], uint32(now.Nanosecond())) // max=3b9ac9ff
	return res
}

func makeSOA() *dnsmsg.RDataSOA {
	// tbqh serial is quite meaningless since we do not use AXFR. Let's just set it to today for now.
	now := time.Now()
	serial := now.Year()*10000 + int(now.Month())*100 + now.Day()

	return &dnsmsg.RDataSOA{
		MName:   "ns1", // ?
		RName:   "admin",
		Serial:  uint32(serial),
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minimum: 60,
	}
}
