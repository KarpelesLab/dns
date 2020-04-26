package dnsmsg

import (
	"encoding/binary"
	"io"
)

func MarshalRData(in []RData) ([]byte, error) {
	ctx := &context{marshal: true}

	for _, v := range in {
		pos := ctx.Len()
		binary.Write(ctx, binary.BigEndian, uint16(v.GetType()))
		binary.Write(ctx, binary.BigEndian, uint16(0)) // len

		err := v.encode(ctx)
		if err != nil {
			return nil, err
		}

		siz := ctx.Len() - pos - 4
		ctx.putUint16(pos+2, uint16(siz))
	}
	return ctx.rawMsg, nil
}

func UnmarshalRData(in []byte) ([]RData, error) {
	ctx := &context{rawMsg: in, marshal: true}
	var res []RData
	var typ Type
	var l uint16

	for {
		err := binary.Read(ctx, binary.BigEndian, (*uint16)(&typ))
		if err != nil {
			if err == io.EOF {
				return res, nil
			}
			return nil, err
		}
		err = binary.Read(ctx, binary.BigEndian, &l)
		if err != nil {
			return nil, err
		}

		buf, err := ctx.readLen(int(l))
		if err != nil {
			return nil, err
		}
		v, err := ctx.parseRData(typ, buf)
		if err != nil {
			return nil, err
		}

		res = append(res, v)
	}
}
