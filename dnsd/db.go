package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"os"

	"github.com/KarpelesLab/dns/dnsmsg"
	"github.com/boltdb/bolt"
	"github.com/google/uuid"
)

var db *bolt.DB

func initDb() error {
	var err error

	dbFile := []string{
		"/etc/go-dnsd.db",
		"go-dnsd.db",
	}

	for _, f := range dbFile {
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
	// * zone: zedns.net
	// * entry: SOA (automatic)
	// * entry: ns1 A 18.181.102.53
	// * entry: ns2 A 34.237.237.237
	// * entry: ns3 A 3.11.47.103
	z, _, _, err := getZone("zedns.net", nil)
	if err == nil {
		log.Printf("zone id = %s", z)
		return
	}
	if err != os.ErrNotExist {
		// this is not the expected error
		log.Printf("[db] failed run test: %s", err)
		return
	}

	// create zone
	z, err = createZone()
	if err != nil {
		log.Printf("[db] failed to create zone: %s", err)
	}

	// add records
	z.setRecord("", 60, []dnsmsg.RData{makeSOA()})
	z.setRecord("ns1", 86400, []dnsmsg.RData{&dnsmsg.RDataIP{IP: net.IPv4(18, 181, 102, 53), Type: dnsmsg.A}})
	z.setRecord("ns2", 86400, []dnsmsg.RData{&dnsmsg.RDataIP{IP: net.IPv4(34, 237, 237, 237), Type: dnsmsg.A}})
	z.setRecord("ns3", 86400, []dnsmsg.RData{&dnsmsg.RDataIP{IP: net.IPv4(3, 11, 47, 103), Type: dnsmsg.A}})

	// set domain
	err = createDomain("zedns.net", z, nil)
	if err != nil {
		log.Printf("[db] failed to create domain: %s", err)
	}
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
