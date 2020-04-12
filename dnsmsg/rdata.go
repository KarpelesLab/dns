package dnsmsg

import (
	"encoding/binary"
	"fmt"
)

type RData interface {
	// TODO
	String() string
	GetType() Type
	encode(c *context) error
}

func (c *context) parseRData(t Type, d []byte) (RData, error) {
	// Parse rdata.
	// Anything short enough (max 5 lines) can be put in here to avoid too many method?
	// This might change in the future, in which case this will be refactored.

	switch t {
	// RFC 1035
	case A:
		if len(d) != 4 {
			return nil, ErrInvalidLen
		}
		return &RDataIP{d, t}, nil
	case NS:
		lbl, _, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case MD:
		lbl, _, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case MF:
		lbl, _, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case CNAME:
		lbl, _, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case SOA:
		res := &RDataSOA{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	case MB:
		lbl, _, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case MG:
		lbl, _, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case MR:
		lbl, _, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case NULL:
		return &RDataRaw{d, t}, nil
	case WKS:
	case PTR:
		lbl, _, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case HINFO:
	case MINFO:
	case MX:
		if len(d) < 3 {
			return nil, ErrInvalidLen
		}
		lbl, _, err := c.readLabel(d[2:])
		if err != nil {
			return nil, err
		}
		return &RDataMX{binary.BigEndian.Uint16(d[:2]), lbl}, nil
	case TXT:
		return RDataTXT(d), nil
	// RFC 3596
	case AAAA:
		if len(d) != 16 {
			return nil, ErrInvalidLen
		}
		return &RDataIP{d, t}, nil
	// RFC 6891
	case OPT:
		res := &RDataOPT{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	}
	return nil, fmt.Errorf("while parsing %s: %w", t.String(), ErrNotSupport)
}
