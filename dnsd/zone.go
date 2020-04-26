package main

import (
	"errors"
	"os"

	"github.com/KarpelesLab/dns/dnsmsg"
	"github.com/boltdb/bolt"
	"github.com/google/uuid"
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
	rec, err := z.getRecord(sub, q.Type)
	if err != nil {
		return err
	}

	// found responses
	pkt.Answer = append(pkt.Answer, rec...)
	return nil
}

func (z dnsZone) getRecord(name []byte, typ dnsmsg.Type) ([]*dnsmsg.Resource, error) {
	var res []*dnsmsg.Resource

	key := append(z[:], name...)

	if typ != dnsmsg.ANY {
		key = append(key, byte(typ>>8), byte(typ))
	}

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("record"))
		if b == nil {
			return os.ErrNotExist
		}

		v := b.Get(key)
		if v == nil {
			return os.ErrNotExist
		}

		// decode
		ttl, tmp, err := dnsmsg.UnmarshalRData(v)
		if err != nil {
			return err
		}

		for _, r := range tmp {
			res = append(res, &dnsmsg.Resource{
				Name:  string(name),
				Class: dnsmsg.IN,
				Type:  r.GetType(),
				TTL:   ttl,
				Data:  r,
			})
		}

		return nil
	})

	return res, err
}

func (z dnsZone) setRecord(name string, ttl uint32, val []dnsmsg.RData) error {
	key := reverseDnsName([]byte(name))
	key = append(z[:], key...)
	if len(val) == 0 {
		return errors.New("invalid record set")
	}
	typ := val[0].GetType()
	key = append(key, byte(typ>>8), byte(typ))

	// encode val
	buf, err := dnsmsg.MarshalRData(ttl, val)
	if err != nil {
		return err
	}

	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("record"))
		if err != nil {
			return err
		}

		return b.Put(key, buf)
	})
}
