package dnsmsg

import "encoding/binary"

type Message struct {
	// Header
	ID   uint16
	Bits HeaderBits

	Question   []*Question // QD
	Answer     []*Resource // AN
	Authority  []*Resource // NS
	Additional []*Resource // AR
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
