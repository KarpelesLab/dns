package dnsmsg

import "encoding/binary"

type Question struct {
	Name  string
	Type  Type
	Class Class
}

func (c *context) parseQuestion() (*Question, error) {
	lbl, err := c.parseLabel()
	if err != nil {
		return nil, err
	}
	q := &Question{Name: lbl}

	err = binary.Read(c, binary.BigEndian, &q.Type)
	if err != nil {
		return nil, err
	}
	err = binary.Read(c, binary.BigEndian, &q.Class)
	if err != nil {
		return nil, err
	}

	return q, nil
}
