package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"os"

	"github.com/KarpelesLab/dns/dnsmsg"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

var db *bolt.DB

func initDb() error {
	var err error

	dbFile := []string{
		"/etc/go-dnsd.db",
		"go-dnsd.db",
	}

	for _, f := range dbFile {
		os.Remove(f) // XXX REMOVE ME UPON GOING LIVE SO WE DON'T ALWAYS MAKE A NEW DB
		db, err = bolt.Open(f, 0600, nil)
		if err == nil {
			log.Printf("[db] opened database file %s", f)
			makeDb()
			return nil
		}
	}

	return err
}

func makeDb() {
	// XXX for testing only, create a basic zone+entries:
	// * zone: shellsnet.com
	// * entry: SOA (automatic)
	// * entry: NS (ns0.shells.com ns1.shells.com)
	// * HTTP
	z, err := getOrCreateZone("shellsnet.com")
	if err != nil {
		log.Printf("[db] failed run test: %s", err)
		return
	}

	// add records
	z.setRecord("", 86400, dnsmsg.NS, "ns0.shells.com.", "ns1.shells.com.")
	z.setRecord("", 86400, dnsmsg.TXT, "\"hello world\"")

	z, err = getOrCreateZone("g-dns.net")
	if err != nil {
		log.Printf("[db] failed run test: %s", err)
		return
	}

	z.setHandlerRecord("*", 86400, dnsmsg.A, "base32addr")
}

func getOrCreateZone(dns string) (dnsZone, error) {
	z, _, _, err := getZone(dns, nil)
	if err == nil {
		return z, nil
	}
	if err != os.ErrNotExist {
		return dnsZone{}, err
	}

	z, err = createZone()
	if err != nil {
		return dnsZone{}, err
	}

	// create SOA (minimum)
	err = z.setRecord("", 60, dnsmsg.SOA, makeSOA())
	if err != nil {
		return dnsZone{}, err
	}

	err = createDomain(dns, z, nil)
	if err != nil {
		return dnsZone{}, err
	}

	return z, nil
}

func createDomain(dns string, zone dnsZone, ip net.IP) error {
	var key []byte
	if ip == nil {
		key = reverseDnsName([]byte(dns))
	} else {
		key = append([]byte(ip.To16()), reverseDnsName([]byte(dns))...)
	}

	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("domain"))
		if err != nil {
			return err
		}

		// check if exists
		v := b.Get(key)
		if v != nil {
			return os.ErrExist
		}

		// set
		return b.Put(key, append(now(), zone[:]...))
	})
}

func getZone(dns string, laddr net.Addr) (dnsZone, []byte, []byte, error) {
	var ip net.IP

	switch v := laddr.(type) {
	case *net.TCPAddr:
		ip = v.IP.To16()
	case *net.UDPAddr:
		ip = v.IP.To16()
	case nil:
		// do nothing
	default:
		return dnsZone(uuid.Nil), nil, nil, errors.New("invalid address")
	}

	name := reverseDnsName([]byte(dns))

	// find zone matching dns
	var res dnsZone
	var l int

	err := db.View(func(tx *bolt.Tx) error {
		if ip != nil {
			b := tx.Bucket([]byte("ip-domain"))
			if b != nil {
				c := b.Cursor()

				target := append([]byte(ip), name...)

				// perform two lookups
				k, v := c.Seek(target)
				if !bytes.Equal(target, k) {
					k, v = c.Prev()
				}
				if len(k) > 0 && bytes.HasPrefix(target, k) {
					// match
					copy(res[:], v[12:])
					l = len(k) - 16
					return nil
				}
			}
		}

		b := tx.Bucket([]byte("domain"))
		if b == nil {
			// no bucket, no need to look further
			return os.ErrNotExist
		}

		c := b.Cursor()

		k, v := c.Seek(name)
		if !bytes.Equal(name, k) {
			k, v = c.Prev()
		}
		if len(k) > 0 && bytes.HasPrefix(name, k) {
			// match
			copy(res[:], v[12:])
			l = len(k)
			return nil
		}
		return os.ErrNotExist
	})

	domain := name[:l]
	name = name[l:]
	if len(name) > 0 {
		// should be "." since not end of name
		name = name[1:]
	}

	return res, domain, name, err
}

func simpleGet(bucket, key []byte) (r []byte, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return os.ErrNotExist
		}
		v := b.Get(key)
		if v == nil {
			return os.ErrNotExist
		}
		r = bdup(v)
		return nil
	})
	return
}

func simpleSet(bucket, key, val []byte) error {
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return err
		}
		return b.Put(key, val)
	})
}
