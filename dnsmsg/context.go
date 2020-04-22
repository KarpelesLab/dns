package dnsmsg

import (
	"encoding/binary"
	"io"
	"strings"
)

// context is used when parsing or generating a message in order to handle
// label compression, etc.
type context struct {
	rawMsg   []byte
	labelMap map[string]uint16 // cache for label compression
	rpos     int               // read position
}

func (c *context) Write(p []byte) (int, error) {
	c.rawMsg = append(c.rawMsg, p...)
	return len(p), nil
}

func (c *context) Read(p []byte) (int, error) {
	if c.rpos >= len(c.rawMsg) {
		return 0, io.EOF
	}
	// attempt to read
	n := copy(p, c.rawMsg[c.rpos:])
	c.rpos += n
	return n, nil
}

func (c *context) Len() int {
	return len(c.rawMsg)
}

func (c *context) putUint16(pos int, v uint16) {
	// simple overwrite function
	binary.BigEndian.PutUint16(c.rawMsg[pos:pos+2], v)
}

func (c *context) readLen(l int) ([]byte, error) {
	if l == 0 {
		// shouldn't happen, but...
		return nil, nil
	}
	// read X bytes
	if c.rpos+l > len(c.rawMsg) {
		return nil, io.EOF
	}

	pos := c.rpos
	c.rpos += l

	return c.rawMsg[pos:c.rpos], nil
}

func (c *context) appendLabel(lbl string) error {
	if len(lbl) > 255 {
		return ErrNameTooLong
	}

	if !strings.HasSuffix(lbl, ".") {
		return ErrLabelInvalid
	}
	lbl = lbl[:len(lbl)-1]

	// append label to msg, compress if possible
	for {
		if p, ok := c.labelMap[strings.ToLower(lbl)]; ok {
			// found label in cache!
			// (cache offset already includes bits 0xc000)
			return binary.Write(c, binary.BigEndian, p)
		}

		if cachePos := len(c.rawMsg); cachePos < 0x3fff {
			// store this pointer into cache so we can compress future labels
			c.labelMap[strings.ToLower(lbl)] = uint16(cachePos | 0xc000)
		}

		pos := strings.IndexByte(lbl, '.')
		if pos == 0 {
			// got ".." in label?
			return ErrLabelInvalid
		}
		if pos == -1 {
			// we reached end of label
			if len(lbl) == 0 {
				return ErrLabelInvalid
			}
			if len(lbl) > 63 {
				return ErrLabelTooLong
			}

			// append
			c.rawMsg = append(append(append(c.rawMsg, byte(len(lbl))), []byte(lbl)...), 0)
			return nil
		}

		// encode, move forward
		if pos > 63 {
			return ErrLabelTooLong
		}

		// append
		c.rawMsg = append(append(c.rawMsg, byte(pos)), []byte(lbl[:pos])...)
		lbl = lbl[pos+1:]
	}
}

func (c *context) parseLabel() (string, error) {
	// read label at current position
	if c.rpos >= len(c.rawMsg) {
		return "", io.EOF
	}
	lbl, n, err := c.readLabel(c.rawMsg[c.rpos:])
	if err != nil {
		return lbl, err
	}

	c.rpos += n
	return lbl, err
}

func (c *context) readLabel(buf []byte) (string, int, error) {
	var res []byte
	var read int
	readMode := true

	for {
		v := int(buf[0])
		if readMode {
			read += 1
		}
		if v == 0 {
			return string(res), read, nil
		}
		if v&0xc0 == 0xc0 {
			if len(buf) < 2 {
				return string(res), read, ErrInvalidLabel
			}
			if readMode {
				read += 1
				readMode = false
			}
			// this is a label pointer
			pos := int(binary.BigEndian.Uint16(buf[:2]) & ^uint16(0xc000))
			if pos >= len(c.rawMsg) {
				return string(res), read, ErrInvalidLabel
			}
			buf = c.rawMsg[pos:]
			continue
		}
		if v > 63 {
			return string(res), read, ErrInvalidLabel
		}

		buf = buf[1:] // move buffer forward to skip len byte
		if v >= len(buf) {
			return string(res), read, ErrInvalidLabel
		}

		if readMode {
			read += v
		}

		res = append(res, buf[:v]...)
		res = append(res, '.')

		buf = buf[v:]
	}
}
