package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/KarpelesLab/dns/dnsmsg"
	"github.com/boltdb/bolt"
	"github.com/google/uuid"
)

func handleApi(rw http.ResponseWriter, req *http.Request) {
	p := req.URL.Path
	p = strings.TrimPrefix(p, "/api/")

	switch p {
	case "export-all":
		// export all records
		rw.Header().Set("Content-Type", "text/plain")

		db.View(func(tx *bolt.Tx) error {
			var id uuid.UUID

			b := tx.Bucket([]byte("ip-domain"))

			if b != nil {
				c := b.Cursor()

				for k, v := c.First(); k != nil; k, v = c.Next() {
					ip := net.IP(k[:16])
					dom := k[16:]
					copy(id[:], v[12:])

					fmt.Fprintf(rw, "ip-domain:%s:%s = %s (%s)\n", ip, dom, id, hex.EncodeToString(v[:12]))
				}
			}

			b = tx.Bucket([]byte("domain"))

			if b != nil {
				c := b.Cursor()

				for k, v := c.First(); k != nil; k, v = c.Next() {
					copy(id[:], v[12:])

					fmt.Fprintf(rw, "domain:%s = %s (%s)\n", k, id, hex.EncodeToString(v[:12]))
				}
			}

			b = tx.Bucket([]byte("record"))

			if b != nil {
				c := b.Cursor()

				for k, v := c.First(); k != nil; k, v = c.Next() {
					// key=zone+name+0+type
					copy(id[:], k[:16])
					k = k[16:]
					pos := bytes.IndexByte(k, 0)
					name := k[:pos]
					k = k[pos+1:]

					typ := dnsmsg.Type(uint16(k[0])<<8 | uint16(k[1]))

					fmt.Fprintf(rw, "record:%s:%s:%s (%s)\n", id, name, typ, hex.EncodeToString(v[:12]))

					// decode
					ttl, rd, err := dnsmsg.UnmarshalRData(v[12:])
					if err == nil {
						for _, rec := range rd {
							fmt.Fprintf(rw, "  %s (ttl=%d)\n", rec, ttl)
						}
					}
				}
			}
			return nil
		})
	default:
		http.NotFound(rw, req)
	}
}
