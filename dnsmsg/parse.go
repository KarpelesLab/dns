package dnsmsg

import (
	"encoding/binary"
)

// Parse decodes a DNS message from wire format as defined in RFC 1035.
// It returns the parsed Message or an error if the data is malformed.
func Parse(d []byte) (*Message, error) {
	msg := &Message{}
	err := msg.UnmarshalBinary(d)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// UnmarshalBinary decodes a DNS message from wire format.
// It implements the encoding.BinaryUnmarshaler interface.
func (msg *Message) UnmarshalBinary(d []byte) error {
	c := &context{rawMsg: d}

	// read stuff
	err := binary.Read(c, binary.BigEndian, &msg.ID)
	if err != nil {
		return err
	}
	err = binary.Read(c, binary.BigEndian, &msg.Bits)
	if err != nil {
		return err
	}

	// count of the various types
	var QD, AN, NS, AR uint16

	err = binary.Read(c, binary.BigEndian, &QD)
	if err != nil {
		return err
	}
	err = binary.Read(c, binary.BigEndian, &AN)
	if err != nil {
		return err
	}
	err = binary.Read(c, binary.BigEndian, &NS)
	if err != nil {
		return err
	}
	err = binary.Read(c, binary.BigEndian, &AR)
	if err != nil {
		return err
	}

	for i := 0; i < int(QD); i++ {
		q, err := c.parseQuestion()
		if err != nil {
			return err
		}
		msg.Question = append(msg.Question, q)
	}
	for i := 0; i < int(AN); i++ {
		r, err := c.parseResource()
		if err != nil {
			return err
		}
		msg.Answer = append(msg.Answer, r)
	}
	for i := 0; i < int(NS); i++ {
		r, err := c.parseResource()
		if err != nil {
			return err
		}
		msg.Authority = append(msg.Authority, r)
	}
	for i := 0; i < int(AR); i++ {
		r, err := c.parseResource()
		if err != nil {
			return err
		}
		if r.Type == OPT {
			// RFC 6891 - Special case
			msg.HasEDNS = true
			msg.Opts = r.Data.(*RDataOPT).Opts
			msg.ReqUDPSize = uint16(r.Class)
			msg.OptRCode = OptRCode(r.TTL)
			continue
		}
		msg.Additional = append(msg.Additional, r)
	}

	return nil
}
