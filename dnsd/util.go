package main

import (
	"encoding/binary"
	"strings"
	"time"
)

func reverseDnsName(n string) []byte {
	// reverse dns name, make lowercase, etc
	n = strings.ToLower(n)

	var res []byte

	for {
		if res != nil {
			res = append(res, '.')
		}

		p := strings.LastIndexByte(n, '.')
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
