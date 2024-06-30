package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/KarpelesLab/dns/dnsmsg"
	"github.com/KarpelesLab/rndstr"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

func handleApi(rw http.ResponseWriter, req *http.Request) {
	p := req.URL.Path
	p = strings.TrimPrefix(p, "/api/")

	switch p {
	case "connect":
		// hijack connection
		hj, ok := rw.(http.Hijacker)
		if !ok {
			http.Error(rw, "please use http/1.1", http.StatusBadRequest)
			return
		}

		conn, b, err := hj.Hijack()
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		defer conn.Close()
		defer b.Flush()

		fmt.Fprintf(b, "HTTP/1.0 200 OK\r\n\r\n")

		// TODO
		fmt.Fprintf(b, "Hello test\n")
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

func getApiKey() string {
	v, err := simpleGet([]byte("local"), []byte("apikey"))
	if err == nil {
		return string(bdup(v))
	}

	// generate random key
	apikey, err := rndstr.SimpleReader(16, rndstr.Alnum, rand.Reader)
	if err != nil {
		panic(err)
	}

	// store key
	err = simpleSet([]byte("local"), []byte("apikey"), []byte(apikey))
	if err != nil {
		panic(err)
	}

	return apikey
}
