package dnsmsg

import (
	"encoding/binary"
	"strings"
)

// Question represents a DNS question as defined in RFC 1035 Section 4.1.2.
// It specifies the domain name being queried, the query type, and the query class.
type Question struct {
	// Name is the domain name being queried (QNAME).
	Name string
	// Type specifies the type of query (QTYPE), e.g., A, AAAA, MX, etc.
	Type Type
	// Class specifies the class of query (QCLASS), typically IN for internet.
	Class Class
}

// NewQuery creates a new DNS query message for the specified domain name, class, and type.
// The recursion desired (RD) flag is automatically set.
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
