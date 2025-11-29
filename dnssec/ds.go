package dnssec

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"github.com/KarpelesLab/dns/dnsmsg"
)

var (
	// ErrUnsupportedDigestType indicates the digest algorithm is not supported.
	ErrUnsupportedDigestType = errors.New("dnssec: unsupported digest type")
)

// ComputeDS creates a DS record from a DNSKEY record.
// The owner parameter should be the fully qualified domain name (with trailing dot).
func ComputeDS(owner string, key *dnsmsg.RDataDNSKEY, digestType dnsmsg.DigestType) (*dnsmsg.RDataDS, error) {
	digest, err := computeDSDigest(owner, key, digestType)
	if err != nil {
		return nil, err
	}

	return &dnsmsg.RDataDS{
		KeyTag:     KeyTag(key),
		Algorithm:  key.Algorithm,
		DigestType: digestType,
		Digest:     digest,
	}, nil
}

// computeDSDigest computes the digest for a DS record.
// digest = digest_algorithm(owner || DNSKEY RDATA)
func computeDSDigest(owner string, key *dnsmsg.RDataDNSKEY, digestType dnsmsg.DigestType) ([]byte, error) {
	// Build data to hash: canonical owner name + DNSKEY RDATA
	var buf bytes.Buffer
	buf.Write(CanonicalName(owner))

	// DNSKEY RDATA: Flags (2) + Protocol (1) + Algorithm (1) + PublicKey
	binary.Write(&buf, binary.BigEndian, key.Flags)
	buf.WriteByte(key.Protocol)
	buf.WriteByte(byte(key.Algorithm))
	buf.Write(key.PublicKey)

	data := buf.Bytes()

	switch digestType {
	case dnsmsg.DigestSHA1:
		hash := sha1.Sum(data)
		return hash[:], nil
	case dnsmsg.DigestSHA256:
		hash := sha256.Sum256(data)
		return hash[:], nil
	case dnsmsg.DigestSHA384:
		hash := sha512.Sum384(data)
		return hash[:], nil
	default:
		return nil, ErrUnsupportedDigestType
	}
}

// VerifyDS checks if a DS record correctly authenticates a DNSKEY.
// Returns true if the DS digest matches the computed digest from the DNSKEY.
func VerifyDS(ds *dnsmsg.RDataDS, owner string, key *dnsmsg.RDataDNSKEY) bool {
	// Quick checks
	if ds.KeyTag != KeyTag(key) {
		return false
	}
	if ds.Algorithm != key.Algorithm {
		return false
	}

	// Compute digest and compare
	digest, err := computeDSDigest(owner, key, ds.DigestType)
	if err != nil {
		return false
	}

	return bytes.Equal(ds.Digest, digest)
}

// ValidateDelegation validates that a DS record set properly authenticates
// at least one DNSKEY in the child zone's DNSKEY set.
func ValidateDelegation(dsRecords []*dnsmsg.RDataDS, owner string, keys []*dnsmsg.RDataDNSKEY) (*dnsmsg.RDataDNSKEY, error) {
	for _, ds := range dsRecords {
		for _, key := range keys {
			if VerifyDS(ds, owner, key) && key.IsKSK() {
				return key, nil
			}
		}
	}
	return nil, errors.New("dnssec: no DS record matches any KSK")
}
