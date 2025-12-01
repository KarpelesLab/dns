package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// RData is the interface implemented by all DNS resource record data types.
// Each record type (A, AAAA, MX, TXT, etc.) has its own implementation.
type RData interface {
	// String returns a human-readable representation of the record data.
	String() string
	// GetType returns the DNS record type (e.g., A, AAAA, MX).
	GetType() Type
	// encode writes the record data in wire format to the context.
	encode(c *context) error
}

// RDataFromString parses a string representation into the appropriate RData type.
// The format depends on the record type:
//   - A: IPv4 address (e.g., "192.168.1.1")
//   - AAAA: IPv6 address (e.g., "2001:db8::1")
//   - MX: "preference server" (e.g., "10 mail.example.com.")
//   - SOA: "mname rname serial refresh retry expire minimum"
//   - TXT: quoted string (e.g., "\"hello world\"")
//   - NS, CNAME, PTR: domain name (e.g., "ns1.example.com.")
func RDataFromString(t Type, str string) (RData, error) {
	switch t {
	// RFC 1035
	case A:
		ip := net.ParseIP(str).To4()
		if len(ip) != 4 {
			return nil, errors.New("could not parse ip")
		}
		return &RDataIP{ip, t}, nil
	case NS, MD, MF, CNAME:
		return &RDataLabel{str, t}, nil
	case SOA:
		soa := &RDataSOA{}
		_, err := fmt.Sscanf(str, "%s %s %d %d %d %d %d", &soa.MName, &soa.RName, &soa.Serial, &soa.Refresh, &soa.Retry, &soa.Expire, &soa.Minimum)
		return soa, err
	case MG, MB, MR:
		return &RDataLabel{str, t}, nil
	case NULL:
		return &RDataRaw{nil, t}, nil
	case PTR:
		return &RDataLabel{str, t}, nil
	case HINFO:
		hi := &RDataHINFO{}
		_, err := fmt.Sscanf(str, "%q %q", &hi.CPU, &hi.OS)
		return hi, err
	case MX:
		mx := &RDataMX{}
		_, err := fmt.Sscanf(str, "%d %s", &mx.Pref, &mx.Server)
		return mx, err
	case TXT:
		s, err := strconv.Unquote(str)
		return RDataTXT(s), err
	// RFC 3596
	case AAAA:
		ip := net.ParseIP(str).To16()
		if len(ip) != 16 {
			return nil, errors.New("could not parse ipv6")
		}
		return &RDataIP{ip, t}, nil
	// RFC 6672
	case DNAME:
		return &RDataLabel{str, t}, nil
	// RFC 2782
	case SRV:
		srv := &RDataSRV{}
		_, err := fmt.Sscanf(str, "%d %d %d %s", &srv.Priority, &srv.Weight, &srv.Port, &srv.Target)
		return srv, err
	// RFC 8659
	case CAA:
		caa := &RDataCAA{}
		_, err := fmt.Sscanf(str, "%d %s %q", &caa.Flags, &caa.Tag, &caa.Value)
		return caa, err
	// RFC 7553
	case URI:
		uri := &RDataURI{}
		_, err := fmt.Sscanf(str, "%d %d %q", &uri.Priority, &uri.Weight, &uri.Target)
		return uri, err
	// RFC 1183
	case RP:
		rp := &RDataRP{}
		_, err := fmt.Sscanf(str, "%s %s", &rp.Mbox, &rp.Txt)
		return rp, err
	case AFSDB:
		afsdb := &RDataAFSDB{}
		_, err := fmt.Sscanf(str, "%d %s", &afsdb.Subtype, &afsdb.Hostname)
		return afsdb, err
	}
	return nil, fmt.Errorf("while parsing %s string: %w", t.String(), ErrNotSupport)
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
	case PTR:
		lbl, _, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
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
		return parseTXT(d)
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
	// RFC 4034 - DNSSEC
	case DNSKEY:
		res := &RDataDNSKEY{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	case RRSIG:
		res := &RDataRRSIG{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	case DS:
		res := &RDataDS{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	case NSEC:
		res := &RDataNSEC{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 5155 - NSEC3
	case NSEC3:
		res := &RDataNSEC3{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	case NSEC3PARAM:
		res := &RDataNSEC3PARAM{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 4398 - CERT
	case CERT:
		res := &RDataCERT{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 8945 - TSIG
	case TSIG:
		res := &RDataTSIG{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 2930 - TKEY
	case TKEY:
		res := &RDataTKEY{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 2782 - SRV
	case SRV:
		res := &RDataSRV{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 6698 - TLSA
	case TLSA:
		res := &RDataTLSA{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 4255 - SSHFP
	case SSHFP:
		res := &RDataSSHFP{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 8659 - CAA
	case CAA:
		res := &RDataCAA{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 7553 - URI
	case URI:
		res := &RDataURI{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 3403 - NAPTR
	case NAPTR:
		res := &RDataNAPTR{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 1035 - HINFO
	case HINFO:
		res := &RDataHINFO{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 1183 - RP
	case RP:
		res := &RDataRP{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 1183 - AFSDB
	case AFSDB:
		res := &RDataAFSDB{}
		if err := res.decode(c, d); err != nil {
			return nil, err
		}
		return res, nil
	// RFC 6672 - DNAME (same structure as CNAME)
	case DNAME:
		lbl, _, err := c.readLabel(d)
		if err != nil {
			return nil, err
		}
		return &RDataLabel{lbl, t}, nil
	}
	return nil, fmt.Errorf("while parsing %s: %w", t.String(), ErrNotSupport)
}
