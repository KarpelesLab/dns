package dnsmsg

import (
	"encoding/binary"
	"fmt"
)

type RDataTXT string

func (txt RDataTXT) GetType() Type {
	return TXT
}

func (txt RDataTXT) String() string {
	return string(txt)
}

func (txt RDataTXT) encode(c *context) error {
	_, err := c.Write([]byte(txt))
	return err
}

type RDataMX struct {
	Pref   uint16
	Server string
}

func (mx *RDataMX) GetType() Type {
	return MX
}

func (mx *RDataMX) String() string {
	return fmt.Sprintf("%d %s", mx.Pref, mx.Server)
}

func (mx *RDataMX) encode(c *context) error {
	err := binary.Write(c, binary.BigEndian, mx.Pref)
	if err != nil {
		return err
	}

	return c.appendLabel(mx.Server)
}

type RDataSOA struct {
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

func (soa *RDataSOA) decode(c *context, d []byte) error {
	var err error
	var n int

	soa.MName, n, err = c.readLabel(d)
	if err != nil {
		return err
	}
	d = d[n:]

	soa.RName, n, err = c.readLabel(d)
	if err != nil {
		return err
	}
	d = d[n:]

	if len(d) < 20 {
		return ErrInvalidLen
	}

	soa.Serial = binary.BigEndian.Uint32(d[:4])
	soa.Refresh = binary.BigEndian.Uint32(d[4:8])
	soa.Retry = binary.BigEndian.Uint32(d[8:12])
	soa.Expire = binary.BigEndian.Uint32(d[12:16])
	soa.Minimum = binary.BigEndian.Uint32(d[16:20])
	return nil
}

func (soa *RDataSOA) GetType() Type {
	return SOA
}

func (soa *RDataSOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", soa.MName, soa.RName, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)
}

func (soa *RDataSOA) encode(c *context) error {
	err := c.appendLabel(soa.MName)
	if err != nil {
		return err
	}

	err = c.appendLabel(soa.RName)
	if err != nil {
		return err
	}

	err = binary.Write(c, binary.BigEndian, soa.Serial)
	if err != nil {
		return err
	}
	err = binary.Write(c, binary.BigEndian, soa.Refresh)
	if err != nil {
		return err
	}
	err = binary.Write(c, binary.BigEndian, soa.Retry)
	if err != nil {
		return err
	}
	err = binary.Write(c, binary.BigEndian, soa.Expire)
	if err != nil {
		return err
	}
	err = binary.Write(c, binary.BigEndian, soa.Minimum)
	if err != nil {
		return err
	}

	return nil
}
