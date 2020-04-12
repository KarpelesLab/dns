package dnsmsg

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
		lbl, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case MD:
		lbl, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case MF:
		lbl, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case CNAME:
		lbl, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case SOA:
	case MB:
		lbl, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case MG:
		lbl, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case MR:
		lbl, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case NULL:
		return &RDataRaw{d, t}, nil
	case WKS:
	case PTR:
		lbl, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	case HINFO:
	case MINFO:
	case MX:
	case TXT:
		return RDataTXT(d), nil
	}
	return nil, ErrNotSupport
}
