package main

import (
	"bytes"
	"errors"
	"os"

	"github.com/KarpelesLab/dns/dnsmsg"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

type dnsZone uuid.UUID

func (z dnsZone) String() string {
	return uuid.UUID(z).String()
}

func createZone() (dnsZone, error) {
	// there's actually nothing we need to do to create a zone
	r, err := uuid.NewRandom() // NewUUID() ?
	return dnsZone(r), err
}

func (z dnsZone) handleQuery(pkt *dnsmsg.Message, q *dnsmsg.Question, sub []byte) error {
	if len(sub) > 0 {
		// check for cname
		rec, err := z.getRecord(sub, dnsmsg.CNAME)
		if err == nil && len(rec) > 0 {
			pkt.Answer = append(pkt.Answer, rec...)
			return nil
		}
	}

	rec, err := z.getRecord(sub, q.Type)
	if err != nil {
		// attempt to find authority
		auth, err := z.getRecord(nil, dnsmsg.SOA)
		if err == nil {
			pkt.Authority = append(pkt.Authority, auth...)
		}
		return err
	}

	// found responses
	pkt.Answer = append(pkt.Answer, rec...)
	return nil
}

// getRecord will attempt to fetch records for name, and will fallback to * lookup if not found
func (z dnsZone) getRecord(name []byte, typ dnsmsg.Type) ([]*dnsmsg.Resource, error) {
	res, err := z.getExactRecord(name, name, typ)
	if len(res) == 0 && err != nil {
		err = os.ErrNotExist
	}
	if err == os.ErrNotExist && len(name) > 0 {
		originalName := name
		if pos := bytes.LastIndexByte(name, '.'); pos > 0 {
			name = append(name[:pos+1], '*')
		} else {
			name = []byte{'*'}
		}
		res, err = z.getExactRecord(name, originalName, typ)
		if len(res) == 0 && err != nil {
			err = os.ErrNotExist
		}
	}
	return res, err
}

// getExactRecord will return one exact record
func (z dnsZone) getExactRecord(name, originalName []byte, typ dnsmsg.Type) ([]*dnsmsg.Resource, error) {
	var res []*dnsmsg.Resource
	var err error

	key := append(z[:], name...)

	if typ == dnsmsg.ANY {
		key = append(key, 0)

		err = db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("record"))
			if b == nil {
				return os.ErrNotExist
			}

			c := b.Cursor()
			k, v := c.Seek(key)

			for bytes.HasPrefix(k, key) {
				// decodo
				rec, err := ReadRecord(v[12:])
				if err != nil {
					return err
				}
				rdata, err := rec.RData(originalName, typ)
				if err != nil {
					return err
				}

				for _, r := range rdata {
					res = append(res, &dnsmsg.Resource{
						Name:  string(originalName),
						Class: dnsmsg.IN,
						Type:  r.GetType(),
						TTL:   rec.TTL,
						Data:  r,
					})
				}

				k, v = c.Next()
			}

			return nil
		})
	} else {
		key = append(key, 0, byte(typ>>8), byte(typ))

		err = db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("record"))
			if b == nil {
				return os.ErrNotExist
			}

			v := b.Get(key)
			if v == nil {
				return os.ErrNotExist
			}

			// decode
			rec, err := ReadRecord(v[12:])
			if err != nil {
				return err
			}
			rdata, err := rec.RData(originalName, typ)
			if err != nil {
				return err
			}

			for _, r := range rdata {
				res = append(res, &dnsmsg.Resource{
					Name:  string(originalName),
					Class: dnsmsg.IN,
					Type:  r.GetType(),
					TTL:   rec.TTL,
					Data:  r,
				})
			}

			return nil
		})
	}

	return res, err
}

func (z dnsZone) setRecord(name string, ttl uint32, typ dnsmsg.Type, value ...string) error {
	key := reverseDnsName([]byte(name))
	key = append(z[:], key...)
	if len(value) == 0 {
		return errors.New("invalid record set")
	}
	key = append(key, 0, byte(typ>>8), byte(typ))

	rec := &Record{
		Type:  typ,
		TTL:   ttl,
		Value: value,
	}

	// encode val
	buf := rec.Bytes()

	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("record"))
		if err != nil {
			return err
		}

		return b.Put(key, append(now(), buf...))
	})
}

func (z dnsZone) setHandlerRecord(name string, ttl uint32, typ dnsmsg.Type, value ...string) error {
	if len(value) == 0 {
		return errors.New("invalid record set")
	}

	key := reverseDnsName([]byte(name))
	key = append(z[:], key...)
	key = append(key, 0, byte(typ>>8), byte(typ))

	rec := &Record{
		Type:    typ,
		Handler: true,
		TTL:     ttl,
		Value:   value,
	}

	// encode val
	buf := rec.Bytes()

	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("record"))
		if err != nil {
			return err
		}

		return b.Put(key, append(now(), buf...))
	})
}
