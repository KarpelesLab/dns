package dnsmsg

import (
	"encoding/binary"
	"math/rand"
	"strconv"
	"strings"
)

// Message represents a DNS message as defined in RFC 1035.
// It contains the header fields, question section, and resource record sections
// (answer, authority, additional). EDNS options (RFC 6891) are also supported.
type Message struct {
	// ID is a 16-bit identifier assigned by the program that generates the query.
	ID uint16
	// Bits contains the header flags including QR, OPCODE, AA, TC, RD, RA, and RCODE.
	Bits HeaderBits

	// Question contains the question section (queries being asked).
	Question []*Question
	// Answer contains the answer section (resource records answering the question).
	Answer []*Resource
	// Authority contains the authority section (NS records pointing to authoritative servers).
	Authority []*Resource
	// Additional contains the additional section (resource records with additional info).
	Additional []*Resource

	// HasEDNS indicates whether EDNS (RFC 6891) options are present.
	HasEDNS bool
	// Opts contains EDNS options when HasEDNS is true.
	Opts []DnsOpt
	// ReqUDPSize is the requestor's UDP payload size from EDNS.
	ReqUDPSize uint16
	// OptRCode contains extended RCODE and flags from EDNS.
	OptRCode OptRCode

	// Base is the default domain suffix for encoding (empty for parsed messages).
	Base string
}

// New creates a new DNS message with a random transaction ID.
func New() *Message {
	msg := &Message{
		ID: uint16(rand.Int31n(0xffff) + 1),
	}

	return msg
}

// MarshalBinary encodes the DNS message into wire format as defined in RFC 1035.
// It implements the encoding.BinaryMarshaler interface.
func (m *Message) MarshalBinary() ([]byte, error) {
	c := &context{
		labelMap: make(map[string]uint16),
		name:     m.Base,
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

func (m *Message) QueryString() string {
	var res []string
	for _, q := range m.Question {
		res = append(res, q.String())
	}

	return strings.Join(res, " ")
}
