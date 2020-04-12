package dnsmsg

import (
	"encoding/binary"
	"strconv"
	"strings"
)

type Message struct {
	// Header
	ID   uint16
	Bits HeaderBits

	Question   []*Question // QD
	Answer     []*Resource // AN
	Authority  []*Resource // NS
	Additional []*Resource // AR

	HasEDNS    bool     // If true, has EDNS options
	Opts       []DnsOpt // EDNS Options
	ReqUDPSize uint16   // requestor's UDP payload size
	OptRCode   OptRCode // extended RCODE and flags
}

func (m *Message) MarshalBinary() ([]byte, error) {
	c := &context{
		labelMap: make(map[string]uint16),
	}

	err := binary.Write(c, binary.BigEndian, m.ID)
	if err != nil {
		return nil, err
	}
	err = binary.Write(c, binary.BigEndian, m.Bits)
	if err != nil {
		return nil, err
	}
	err = binary.Write(c, binary.BigEndian, uint16(len(m.Question)))
	if err != nil {
		return nil, err
	}
	err = binary.Write(c, binary.BigEndian, uint16(len(m.Answer)))
	if err != nil {
		return nil, err
	}
	err = binary.Write(c, binary.BigEndian, uint16(len(m.Authority)))
	if err != nil {
		return nil, err
	}
	err = binary.Write(c, binary.BigEndian, uint16(len(m.Additional)))
	if err != nil {
		return nil, err
	}

	for _, q := range m.Question {
		if err = q.encode(c); err != nil {
			return nil, err
		}
	}
	for _, r := range m.Answer {
		if err = r.encode(c); err != nil {
			return nil, err
		}
	}
	for _, r := range m.Authority {
		if err = r.encode(c); err != nil {
			return nil, err
		}
	}
	for _, r := range m.Additional {
		if err = r.encode(c); err != nil {
			return nil, err
		}
	}

	return c.rawMsg, nil
}

func (m *Message) String() string {
	res := []string{
		"ID: " + strconv.FormatUint(uint64(m.ID), 10),
		m.Bits.String(),
	}

	for _, q := range m.Question {
		res = append(res, "QD:", q.String())
	}
	for _, r := range m.Answer {
		res = append(res, "AN:", r.String())
	}
	for _, r := range m.Authority {
		res = append(res, "NS:", r.String())
	}
	for _, r := range m.Additional {
		res = append(res, "AR:", r.String())
	}

	if m.HasEDNS {
		res = append(res, "ReqUDPSize="+strconv.FormatUint(uint64(m.ReqUDPSize), 10))
		for _, opt := range m.Opts {
			res = append(res, opt.String())
		}
	}

	return strings.Join(res, " ")
}
