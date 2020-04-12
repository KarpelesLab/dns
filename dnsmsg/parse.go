package dnsmsg

import "encoding/binary"

func Parse(d []byte) (*Message, error) {
	c := &context{rawMsg: d}

	msg := &Message{}

	// read stuff
	err := binary.Read(c, binary.BigEndian, &msg.ID)
	if err != nil {
		return nil, err
	}
	err = binary.Read(c, binary.BigEndian, &msg.Bits)
	if err != nil {
		return nil, err
	}

	// count of the various types
	var QD, AN, NS, AR uint16

	err = binary.Read(c, binary.BigEndian, &QD)
	if err != nil {
		return nil, err
	}
	err = binary.Read(c, binary.BigEndian, &AN)
	if err != nil {
		return nil, err
	}
	err = binary.Read(c, binary.BigEndian, &NS)
	if err != nil {
		return nil, err
	}
	err = binary.Read(c, binary.BigEndian, &AR)
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(QD); i++ {
		q, err := c.parseQuestion()
		if err != nil {
			return nil, err
		}
		msg.Question = append(msg.Question, q)
	}
	for i := 0; i < int(AN); i++ {
		r, err := c.parseResource()
		if err != nil {
			return nil, err
		}
		msg.Answer = append(msg.Answer, r)
	}
	for i := 0; i < int(NS); i++ {
		r, err := c.parseResource()
		if err != nil {
			return nil, err
		}
		msg.Authority = append(msg.Authority, r)
	}
	for i := 0; i < int(AR); i++ {
		r, err := c.parseResource()
		if err != nil {
			return nil, err
		}
		msg.Additional = append(msg.Additional, r)
	}

	return msg, nil
}
