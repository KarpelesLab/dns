package dnsmsg

import "strconv"

// Algorithm represents a DNSSEC algorithm number as defined in RFC 4034 and RFC 8624.
type Algorithm uint8

const (
	// DNSSEC Algorithm Numbers (RFC 8624)
	AlgorithmRSAMD5       Algorithm = 1  // Deprecated (RFC 6725)
	AlgorithmDH           Algorithm = 2  // Not for DNSSEC
	AlgorithmDSA          Algorithm = 3  // Deprecated (RFC 8624)
	AlgorithmRSASHA1      Algorithm = 5  // Not recommended (RFC 8624)
	AlgorithmDSANSEC3SHA1 Algorithm = 6  // Deprecated (RFC 8624)
	AlgorithmRSASHA1NSEC3 Algorithm = 7  // Not recommended (RFC 8624)
	AlgorithmRSASHA256    Algorithm = 8  // MUST implement (RFC 5702)
	AlgorithmRSASHA512    Algorithm = 10 // MUST implement (RFC 5702)
	AlgorithmECDSAP256    Algorithm = 13 // MUST implement (RFC 6605)
	AlgorithmECDSAP384    Algorithm = 14 // MAY implement (RFC 6605)
	AlgorithmED25519      Algorithm = 15 // RECOMMENDED (RFC 8080)
	AlgorithmED448        Algorithm = 16 // MAY implement (RFC 8080)
	AlgorithmPrivateDNS   Algorithm = 253
	AlgorithmPrivateOID   Algorithm = 254
)

func (a Algorithm) String() string {
	switch a {
	case AlgorithmRSAMD5:
		return "RSAMD5"
	case AlgorithmDH:
		return "DH"
	case AlgorithmDSA:
		return "DSA"
	case AlgorithmRSASHA1:
		return "RSASHA1"
	case AlgorithmDSANSEC3SHA1:
		return "DSA-NSEC3-SHA1"
	case AlgorithmRSASHA1NSEC3:
		return "RSASHA1-NSEC3-SHA1"
	case AlgorithmRSASHA256:
		return "RSASHA256"
	case AlgorithmRSASHA512:
		return "RSASHA512"
	case AlgorithmECDSAP256:
		return "ECDSAP256SHA256"
	case AlgorithmECDSAP384:
		return "ECDSAP384SHA384"
	case AlgorithmED25519:
		return "ED25519"
	case AlgorithmED448:
		return "ED448"
	case AlgorithmPrivateDNS:
		return "PRIVATEDNS"
	case AlgorithmPrivateOID:
		return "PRIVATEOID"
	default:
		return "Algorithm" + strconv.Itoa(int(a))
	}
}

// DigestType represents a DS record digest algorithm number (RFC 4034, RFC 4509, RFC 6605).
type DigestType uint8

const (
	DigestSHA1   DigestType = 1 // SHA-1 (RFC 4034) - legacy, not recommended
	DigestSHA256 DigestType = 2 // SHA-256 (RFC 4509) - MUST implement
	DigestSHA384 DigestType = 4 // SHA-384 (RFC 6605)
)

func (d DigestType) String() string {
	switch d {
	case DigestSHA1:
		return "SHA-1"
	case DigestSHA256:
		return "SHA-256"
	case DigestSHA384:
		return "SHA-384"
	default:
		return "DigestType" + strconv.Itoa(int(d))
	}
}

// NSEC3HashAlg represents the hash algorithm used in NSEC3 records (RFC 5155).
type NSEC3HashAlg uint8

const (
	NSEC3HashSHA1 NSEC3HashAlg = 1 // SHA-1 (RFC 5155)
)

func (h NSEC3HashAlg) String() string {
	switch h {
	case NSEC3HashSHA1:
		return "SHA-1"
	default:
		return "NSEC3Hash" + strconv.Itoa(int(h))
	}
}
