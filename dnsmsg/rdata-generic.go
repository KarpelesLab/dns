package dnsmsg

import (
	"encoding/hex"
	"errors"
	"net"
)

type RDataIP struct {
	net.IP
	Type Type
}

func (ip *RDataIP) GetType() Type {
	return ip.Type
}

func (ip *RDataIP) encode(c *context) error {
	// write IP
	switch ip.Type {
	case A:
		i := ip.IP.To4()
		if i == nil {
			return errors.New("attempted to write something that is not IPv4 into A record")
		}
		_, err := c.Write(i)
		return err
	case AAAA:
		i := ip.IP.To16()
		if i == nil {
			return errors.New("attempted to write something that is not IPv6 into AAAA record")
		}
		_, err := c.Write(i)
		return err
	}
	return errors.New("invalid record type for IP record")
}

type RDataLabel struct {
	Label string
	Type  Type
}

func (lbl *RDataLabel) GetType() Type {
	return lbl.Type
}

func (lbl *RDataLabel) String() string {
	return lbl.Label
}

func (lbl *RDataLabel) encode(c *context) error {
	return c.appendLabel(lbl.Label)
}

type RDataRaw struct {
	Data []byte
	Type Type
}

func (rd *RDataRaw) GetType() Type {
	return rd.Type
}

func (rd *RDataRaw) String() string {
	return hex.EncodeToString(rd.Data)
}

func (rd *RDataRaw) encode(c *context) error {
	_, err := c.Write(rd.Data)
	return err
}
