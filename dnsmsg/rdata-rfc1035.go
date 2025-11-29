package dnsmsg

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// RDataTXT represents a DNS TXT record.
// Per RFC 1035, TXT records contain one or more character-strings,
// each prefixed with a length byte (max 255 bytes per string).
type RDataTXT string

func (txt RDataTXT) GetType() Type {
	return TXT
}

func (txt RDataTXT) String() string {
	return strconv.QuoteToASCII(string(txt))
}

func (txt RDataTXT) encode(c *context) error {
	// Per RFC 1035, TXT RDATA consists of one or more character-strings.
	// Each character-string is a length byte followed by that many characters.
	// Maximum length per string is 255 bytes.
	data := []byte(txt)
	for len(data) > 0 {
		chunkLen := len(data)
		if chunkLen > 255 {
			chunkLen = 255
		}
		// Write length byte
		if _, err := c.Write([]byte{byte(chunkLen)}); err != nil {
			return err
		}
		// Write chunk data
		if _, err := c.Write(data[:chunkLen]); err != nil {
			return err
		}
		data = data[chunkLen:]
	}
	return nil
}

// parseTXT parses TXT record data from wire format.
// TXT RDATA is one or more <character-string>s, each prefixed with a length byte.
func parseTXT(d []byte) (RDataTXT, error) {
	var result []byte
	pos := 0
	for pos < len(d) {
		if pos >= len(d) {
			break
		}
		strLen := int(d[pos])
		pos++
		if pos+strLen > len(d) {
			return "", ErrInvalidLen
		}
		result = append(result, d[pos:pos+strLen]...)
		pos += strLen
	}
	return RDataTXT(result), nil
}

type RDataMX struct {
	Pref   uint16
	Server string
}

func (mx *RDataMX) GetType() Type {
	return MX
}

func (mx *RDataMX) String() string {
	return fmt.Sprintf("%d %s", mx.Pref, mx.Server)
}

func (mx *RDataMX) encode(c *context) error {
	err := binary.Write(c, binary.BigEndian, mx.Pref)
	if err != nil {
		return err
	}

	return c.appendLabel(mx.Server)
}

type RDataSOA struct {
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

func (soa *RDataSOA) decode(c *context, d []byte) error {
	var err error
	var n int

	soa.MName, n, err = c.readLabel(d)
	if err != nil {
		return err
	}
	d = d[n:]

	soa.RName, n, err = c.readLabel(d)
	if err != nil {
		return err
	}
	d = d[n:]

	if len(d) < 20 {
		return ErrInvalidLen
	}

	soa.Serial = binary.BigEndian.Uint32(d[:4])
	soa.Refresh = binary.BigEndian.Uint32(d[4:8])
	soa.Retry = binary.BigEndian.Uint32(d[8:12])
	soa.Expire = binary.BigEndian.Uint32(d[12:16])
	soa.Minimum = binary.BigEndian.Uint32(d[16:20])
	return nil
}

func (soa *RDataSOA) GetType() Type {
	return SOA
}

func (soa *RDataSOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", soa.MName, soa.RName, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)
}

func (soa *RDataSOA) encode(c *context) error {
	err := c.appendLabel(soa.MName)
	if err != nil {
		return err
	}

	err = c.appendLabel(soa.RName)
	if err != nil {
		return err
	}

	err = binary.Write(c, binary.BigEndian, soa.Serial)
	if err != nil {
		return err
	}
	err = binary.Write(c, binary.BigEndian, soa.Refresh)
	if err != nil {
		return err
	}
	err = binary.Write(c, binary.BigEndian, soa.Retry)
	if err != nil {
		return err
	}
	err = binary.Write(c, binary.BigEndian, soa.Expire)
	if err != nil {
		return err
	}
	err = binary.Write(c, binary.BigEndian, soa.Minimum)
	if err != nil {
		return err
	}

	return nil
}
