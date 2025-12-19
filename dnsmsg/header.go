package dnsmsg

import "strings"

// HeaderBits represents the flags and codes in a DNS message header.
// It contains the QR (query/response), OPCODE, AA (authoritative answer),
// TC (truncation), RD (recursion desired), RA (recursion available),
// and RCODE (response code) fields as defined in RFC 1035 Section 4.1.1.
type HeaderBits uint16

const (
	// private consts to make code easier to read
	hQResp HeaderBits = 0x8000
	hAuth  HeaderBits = 0x0400
	hTrunc HeaderBits = 0x0200
	hRecD  HeaderBits = 0x0100
	hRecA  HeaderBits = 0x0080
	// hZMask covers the reserved Z bits (bits 4-6) which must be zero per RFC 1035 §4.1.1
	hZMask HeaderBits = 0x0070
)

func (h HeaderBits) IsResponse() bool {
	return h&hQResp == hQResp
}

func (h *HeaderBits) SetResponse(q bool) {
	if q {
		*h |= hQResp
	} else {
		*h &= ^hQResp
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

// ClearZ explicitly zeroes the reserved Z bits (bits 4-6) as required by RFC 1035 §4.1.1.
func (h *HeaderBits) ClearZ() {
	*h &= ^hZMask
}

// Sanitized returns the header bits with the reserved Z bits cleared for wire encoding.
func (h HeaderBits) Sanitized() HeaderBits {
	return h & ^hZMask
}

func (h HeaderBits) String() string {
	res := []string{
		h.OpCode().String(),
	}

	if h.IsResponse() {
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
