package dnsmsg

import "encoding/binary"

type Resource struct {
	Name  string
	Type  Type
	Class Class
	TTL   uint32

	Data RData
}

func (c *context) parseResource() (*Resource, error) {
	lbl, err := c.parseLabel()
	if err != nil {
		return nil, err
	}
	r := &Resource{Name: lbl}

	err = binary.Read(c, binary.BigEndian, &r.Type)
	if err != nil {
		return nil, err
	}
	err = binary.Read(c, binary.BigEndian, &r.Class)
	if err != nil {
		return nil, err
	}
	err = binary.Read(c, binary.BigEndian, &r.TTL)
	if err != nil {
		return nil, err
	}

	var l uint16 // RDLENGTH
	err = binary.Read(c, binary.BigEndian, &l)
	if err != nil {
		return nil, err
	}

	rdbuf, err := c.readLen(int(l))
	if err != nil {
		return nil, err
	}

	r.Data, err = c.parseRData(r.Type, rdbuf)
	if err != nil {
		return nil, err
	}

	return r, nil
}
