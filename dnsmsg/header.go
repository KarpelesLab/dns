package dnsmsg

import "strings"

type HeaderBits uint16

const (
	// private consts to make code easier to read
	hQuery HeaderBits = 0x8000
	hAuth  HeaderBits = 0x0400
	hTrunc HeaderBits = 0x0200
	hRecD  HeaderBits = 0x0100
	hRecA  HeaderBits = 0x0080
)

func (h HeaderBits) IsQuery() bool {
	return h&hQuery == hQuery
}

func (h *HeaderBits) SetQuery(q bool) {
	if q {
		*h |= hQuery
	} else {
		*h &= ^hQuery
	}
}

func (h HeaderBits) OpCode() OpCode {
	v := (h >> 11) & 0xf
	return OpCode(v)
}

func (h *HeaderBits) SetOpCode(q OpCode) {
	v := (HeaderBits(q) & 0xf) << 11
	*h = (*h & ^HeaderBits(0x7800)) | v
}

func (h HeaderBits) IsAuth() bool {
	return h&hAuth == hAuth
}

func (h *HeaderBits) SetAuth(auth bool) {
	if auth {
		*h |= hAuth
	} else {
		*h &= ^hAuth
	}
}

func (h HeaderBits) IsTrunc() bool {
	return h&hTrunc == hTrunc
}

func (h *HeaderBits) SetTrunc(trunc bool) {
	if trunc {
		*h |= hTrunc
	} else {
		*h &= ^hTrunc
	}
}

func (h HeaderBits) IsRecDesired() bool {
	return h&hRecD == hRecD
}

func (h *HeaderBits) SetRecDesired(recd bool) {
	if recd {
		*h |= hRecD
	} else {
		*h &= ^hRecD
	}
}

func (h HeaderBits) IsRecAvailable() bool {
	return h&hRecA == hRecA
}

func (h *HeaderBits) SetRecAvailable(reca bool) {
	if reca {
		*h |= hRecA
	} else {
		*h &= ^hRecA
	}
}

func (h HeaderBits) GetRCode() RCode {
	return RCode(h & 0xf)
}

func (h *HeaderBits) SetRCode(rc RCode) {
	*h = (*h & ^HeaderBits(0xf)) | HeaderBits(rc)
}

func (h HeaderBits) String() string {
	res := []string{
		h.OpCode().String(),
	}

	if h.IsQuery() {
		res = append(res, "qr")
	}
	if h.IsAuth() {
		res = append(res, "aa")
	}
	if h.IsTrunc() {
		res = append(res, "tc")
	}
	if h.IsRecDesired() {
		res = append(res, "rd")
	}
	if h.IsRecAvailable() {
		res = append(res, "ra")
	}
	res = append(res, h.GetRCode().String())

	return strings.Join(res, " ")
}
