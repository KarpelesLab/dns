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

func (r *Resource) encode(c *context) error {
	err := c.appendLabel(r.Name)
	if err != nil {
		return err
	}

	err = binary.Write(c, binary.BigEndian, r.Type)
	if err != nil {
		return err
	}
	err = binary.Write(c, binary.BigEndian, r.Class)
	if err != nil {
		return err
	}
	err = binary.Write(c, binary.BigEndian, r.TTL)
	if err != nil {
		return err
	}

	pos := c.Len()                 // position of RDLENGTH
	_, err = c.Write([]byte{0, 0}) // RDLENGTH
	if err != nil {
		return err
	}

	start := c.Len()
	err = r.Data.encode(c)

	// this tells us how many bytes were written by r.Data.encode()
	rdlen := c.Len() - start
	if rdlen > 0xffff {
		return ErrInvalidLen
	}

	// store RDLENGTH based on actually written bytes
	c.putUint16(pos, uint16(rdlen))

	return nil
}
