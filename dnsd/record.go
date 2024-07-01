package main

import (
	"bytes"
	"encoding/gob"
	"errors"

	"github.com/KarpelesLab/dns/dnsmsg"
)

type Record struct {
	Type    dnsmsg.Type
	Handler bool // if true, value is a handler, not a raw value
	Value   []string
	TTL     uint32
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

func (r *Record) RData(name []byte, typ dnsmsg.Type) (res []dnsmsg.RData, err error) {
	var t dnsmsg.RData

	if r.Handler {
		if len(r.Value) == 0 {
			// invalid
			err = errors.New("handler missing")
			return
		}
		return performHandler(r.Value, name, typ)
	}

	for _, v := range r.Value {
		t, err = dnsmsg.RDataFromString(r.Type, v)
		if err != nil {
			return
		}
		res = append(res, t)
	}
	return
}
