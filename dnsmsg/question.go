package dnsmsg

import (
	"encoding/binary"
	"strings"
)

type Question struct {
	Name  string
	Type  Type
	Class Class
}

func NewQuery(name string, class Class, typ Type) *Message {
	msg := New()
	msg.Bits |= hRecD // recursion desired
	msg.Question = []*Question{
		{
			Name:  name,
			Class: class,
			Type:  typ,
		},
	}

	return msg
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

func (q *Question) encode(c *context) error {
	err := c.appendLabel(q.Name)
	if err != nil {
		return err
	}

	err = binary.Write(c, binary.BigEndian, q.Type)
	if err != nil {
		return err
	}
	return binary.Write(c, binary.BigEndian, q.Class)
}

func (q *Question) String() string {
	return strings.Join([]string{q.Name, q.Class.String(), q.Type.String()}, " ")
}
