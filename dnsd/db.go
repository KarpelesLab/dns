package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"os"

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
	z, _, err := getZone("zedns.net", nil)
	if err == nil {
		log.Printf("zone id = %s", z)
		return
	}
	if err != os.ErrNotExist {
		// this is not the expected error
		log.Printf("[db] failed run test: %s", err)
		return
	}

	z, err = createZone()
	if err != nil {
		log.Printf("[db] failed to create zone: %s", err)
	}

	// create zone
	err = createDomain("zedns.net", z, nil)
	log.Printf("err = %s", err)
}

type dnsZone uuid.UUID

func (z dnsZone) String() string {
	return uuid.UUID(z).String()
}

func createZone() (dnsZone, error) {
	// there's actually nothing we need to do to create a zone
	r, err := uuid.NewRandom() // NewUUID() ?
	return dnsZone(r), err
}

func createDomain(dns string, zone dnsZone, ip net.IP) error {
	var key []byte
	if ip == nil {
		key = reverseDnsName(dns)
	} else {
		key = append([]byte(ip.To16()), reverseDnsName(dns)...)
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
		return b.Put(key, zone[:])
	})
}

func getZone(dns string, laddr net.Addr) (dnsZone, []byte, error) {
	var ip net.IP

	switch v := laddr.(type) {
	case *net.TCPAddr:
		ip = v.IP.To16()
	case *net.UDPAddr:
		ip = v.IP.To16()
	case nil:
		// do nothing
	default:
		return dnsZone(uuid.Nil), nil, errors.New("invalid address")
	}

	name := reverseDnsName(dns)

	// find zone matching dns
	var res dnsZone
	var l int

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("domain"))
		if b == nil {
			// no bucket, no need to look further
			return os.ErrNotExist
		}

		c := b.Cursor()

		if ip != nil {
			target := append([]byte(ip), name...)

			// perform two lookups
			k, v := c.Seek(target)
			if bytes.HasPrefix(target, k) {
				log.Printf("found, tgt=%s k=%s", target, k)
				// match
				copy(res[:], v)
				l = len(k) - 16
				return nil
			}
		}

		k, v := c.Seek(name)
		if bytes.HasPrefix(name, k) {
			// match
			copy(res[:], v)
			l = len(k)
			return nil
		}
		return os.ErrNotExist
	})
	return res, name[l:], err
}
