package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type DnsOpt struct {
	Code uint16
	Data []byte
}

func (opt *DnsOpt) String() string {
	return fmt.Sprintf("OPT(code=%d)", opt.Code)
}

type OptRCode uint32

type RDataOPT struct {
	Opts []DnsOpt
}

func (opt *RDataOPT) decode(c *context, d []byte) error {
	r := bytes.NewReader(d)
	var err error

	for r.Len() > 0 {
		o := &DnsOpt{}
		var l uint16
		err = binary.Read(r, binary.BigEndian, &o.Code)
		if err != nil {
			return err
		}
		err = binary.Read(r, binary.BigEndian, &l)
		if err != nil {
			return err
		}

		o.Data = make([]byte, l)
		_, err = io.ReadFull(r, o.Data)
		if err != nil {
			return err
		}
		opt.Opts = append(opt.Opts, *o)
	}
	return nil
}

func (opt *RDataOPT) GetType() Type {
	return OPT
}

func (opt *RDataOPT) String() string {
	// This shouldn't happen
	return "OPT(...)"
}

func (opt *RDataOPT) encode(c *context) error {
	for _, o := range opt.Opts {
		l := len(o.Data)
		if l > 0xffff {
			return ErrInvalidLen
		}

		err := binary.Write(c, binary.BigEndian, o.Code)
		if err != nil {
			return err
		}
		err = binary.Write(c, binary.BigEndian, uint16(l))
		if err != nil {
			return err
		}

		_, err = c.Write(o.Data)
		if err != nil {
			return err
		}
	}
	return nil
}
