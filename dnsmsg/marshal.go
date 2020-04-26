package dnsmsg

import (
	"encoding/binary"
	"io"
)

func MarshalRData(ttl uint32, in []RData) ([]byte, error) {
	ctx := &context{marshal: true}
	binary.Write(ctx, binary.BigEndian, ttl)

	for _, v := range in {
		pos := ctx.Len()
		binary.Write(ctx, binary.BigEndian, uint16(v.GetType()))
		binary.Write(ctx, binary.BigEndian, uint16(0)) // len

		err := v.encode(ctx)
		if err != nil {
			return nil, err
		}

		// write size of record
		siz := ctx.Len() - pos - 4
		ctx.putUint16(pos+2, uint16(siz))
	}
	return ctx.rawMsg, nil
}

func UnmarshalRData(in []byte) (uint32, []RData, error) {
	ctx := &context{rawMsg: in, marshal: true}
	var res []RData
	var typ Type
	var l uint16
	var ttl uint32

	binary.Read(ctx, binary.BigEndian, &ttl)

	for {
		err := binary.Read(ctx, binary.BigEndian, (*uint16)(&typ))
		if err != nil {
			if err == io.EOF {
				return ttl, res, nil
			}
			return ttl, nil, err
		}
		err = binary.Read(ctx, binary.BigEndian, &l)
		if err != nil {
			return ttl, nil, err
		}

		buf, err := ctx.readLen(int(l))
		if err != nil {
			return ttl, nil, err
		}
		v, err := ctx.parseRData(typ, buf)
		if err != nil {
			return ttl, nil, err
		}

		res = append(res, v)
	}
}
