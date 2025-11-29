package dnsmsg

import "strconv"

// Algorithm represents a DNSSEC algorithm number as defined in RFC 4034 and RFC 8624.
type Algorithm uint8

const (
	// DNSSEC Algorithm Numbers
	// https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
	AlgorithmDELETE       Algorithm = 0   // Delete DS (RFC 8087)
	AlgorithmRSAMD5       Algorithm = 1   // Deprecated (RFC 6725)
	AlgorithmDH           Algorithm = 2   // Diffie-Hellman (RFC 2539)
	AlgorithmDSA          Algorithm = 3   // Deprecated (RFC 8624)
	AlgorithmRSASHA1      Algorithm = 5   // Deprecated (RFC 8624)
	AlgorithmDSANSEC3SHA1 Algorithm = 6   // Deprecated (RFC 8624)
	AlgorithmRSASHA1NSEC3 Algorithm = 7   // Deprecated (RFC 8624)
	AlgorithmRSASHA256    Algorithm = 8   // MUST implement (RFC 5702)
	AlgorithmRSASHA512    Algorithm = 10  // MUST implement (RFC 5702)
	AlgorithmGOST         Algorithm = 12  // Deprecated - GOST R 34.10-2001 (RFC 5933)
	AlgorithmECDSAP256    Algorithm = 13  // MUST implement (RFC 6605)
	AlgorithmECDSAP384    Algorithm = 14  // MAY implement (RFC 6605)
	AlgorithmED25519      Algorithm = 15  // RECOMMENDED (RFC 8080)
	AlgorithmED448        Algorithm = 16  // MAY implement (RFC 8080)
	AlgorithmSM2SM3       Algorithm = 17  // SM2/SM3 (RFC 8998)
	AlgorithmGOST12       Algorithm = 23  // GOST R 34.10-2012 (RFC 9558)
	AlgorithmINDIRECT     Algorithm = 252 // Reserved for Indirect Keys (RFC 4034)
	AlgorithmPrivateDNS   Algorithm = 253 // Private algorithm (RFC 4034)
	AlgorithmPrivateOID   Algorithm = 254 // Private algorithm OID (RFC 4034)
)

func (a Algorithm) String() string {
	switch a {
	case AlgorithmDELETE:
		return "DELETE"
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
	case AlgorithmGOST:
		return "ECC-GOST"
	case AlgorithmECDSAP256:
		return "ECDSAP256SHA256"
	case AlgorithmECDSAP384:
		return "ECDSAP384SHA384"
	case AlgorithmED25519:
		return "ED25519"
	case AlgorithmED448:
		return "ED448"
	case AlgorithmSM2SM3:
		return "SM2SM3"
	case AlgorithmGOST12:
		return "ECC-GOST12"
	case AlgorithmINDIRECT:
		return "INDIRECT"
	case AlgorithmPrivateDNS:
		return "PRIVATEDNS"
	case AlgorithmPrivateOID:
		return "PRIVATEOID"
	default:
		return "Algorithm" + strconv.Itoa(int(a))
	}
}

// DigestType represents a DS record digest algorithm number.
// https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
type DigestType uint8

const (
	DigestSHA1   DigestType = 1 // SHA-1 (RFC 4034) - deprecated for delegation
	DigestSHA256 DigestType = 2 // SHA-256 (RFC 4509) - MUST implement
	DigestGOST   DigestType = 3 // GOST R 34.11-94 (RFC 5933) - deprecated
	DigestSHA384 DigestType = 4 // SHA-384 (RFC 6605)
	DigestGOST12 DigestType = 5 // GOST R 34.11-2012 (RFC 9558)
	DigestSM3    DigestType = 6 // SM3 (RFC 8998)
)

func (d DigestType) String() string {
	switch d {
	case DigestSHA1:
		return "SHA-1"
	case DigestSHA256:
		return "SHA-256"
	case DigestGOST:
		return "GOST94"
	case DigestSHA384:
		return "SHA-384"
	case DigestGOST12:
		return "GOST12"
	case DigestSM3:
		return "SM3"
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
