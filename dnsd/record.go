package main

import (
	"bytes"
	"encoding/gob"

	"github.com/KarpelesLab/dns/dnsmsg"
)

type Record struct {
	Type  dnsmsg.Type
	Value []string
	TTL   uint32
}

func ReadRecord(v []byte) (*Record, error) {
	r := &Record{}

	dec := gob.NewDecoder(bytes.NewReader(v))
	err := dec.Decode(r)

	return r, err
}

func (r *Record) Bytes() []byte {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	enc.Encode(r)

	return buf.Bytes()
}

func (r *Record) RData() (res []dnsmsg.RData, err error) {
	var t dnsmsg.RData

	for _, v := range r.Value {
		t, err = dnsmsg.RDataFromString(r.Type, v)
		if err != nil {
			return
		}
		res = append(res, t)
	}
	return
}
