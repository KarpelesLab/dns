// Package dnssec provides DNSSEC cryptographic operations including signature
// verification, signing, and DS record computation.
package dnssec

import (
	"encoding/binary"

	"github.com/KarpelesLab/dns/dnsmsg"
)

// KeyTag computes the key tag for a DNSKEY record as specified in RFC 4034 Appendix B.
// The key tag is used to efficiently match RRSIG records to their corresponding DNSKEYs.
func KeyTag(key *dnsmsg.RDataDNSKEY) uint16 {
	// Special case for algorithm 1 (RSAMD5) - use different calculation
	if key.Algorithm == dnsmsg.AlgorithmRSAMD5 {
		return keyTagAlg1(key)
	}

	// Standard key tag calculation (RFC 4034 Appendix B.1)
	var ac uint32

	// Add flags (2 bytes)
	ac += uint32(key.Flags>>8) + uint32(key.Flags&0xFF)<<8
	ac += uint32(key.Flags & 0xFF)
	ac += uint32(key.Flags >> 8)

	// Recompute properly: accumulate all bytes
	// Wire format: Flags (2) + Protocol (1) + Algorithm (1) + PublicKey
	wire := make([]byte, 4+len(key.PublicKey))
	binary.BigEndian.PutUint16(wire[0:2], key.Flags)
	wire[2] = key.Protocol
	wire[3] = byte(key.Algorithm)
	copy(wire[4:], key.PublicKey)

	ac = 0
	for i := 0; i < len(wire); i++ {
		if i&1 == 0 {
			ac += uint32(wire[i]) << 8
		} else {
			ac += uint32(wire[i])
		}
	}
	ac += ac >> 16
	return uint16(ac & 0xFFFF)
}

// keyTagAlg1 computes key tag for RSAMD5 algorithm (algorithm 1).
// This uses a different calculation - the last 2 bytes of the public key.
func keyTagAlg1(key *dnsmsg.RDataDNSKEY) uint16 {
	if len(key.PublicKey) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(key.PublicKey[len(key.PublicKey)-2:])
}
