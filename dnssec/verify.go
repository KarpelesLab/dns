package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"time"

	"github.com/KarpelesLab/dns/dnsmsg"
)

var (
	// ErrSignatureExpired indicates the RRSIG has expired.
	ErrSignatureExpired = errors.New("dnssec: signature expired")
	// ErrSignatureNotYetValid indicates the RRSIG inception time is in the future.
	ErrSignatureNotYetValid = errors.New("dnssec: signature not yet valid")
	// ErrNoMatchingKey indicates no DNSKEY matched the RRSIG key tag.
	ErrNoMatchingKey = errors.New("dnssec: no matching DNSKEY for RRSIG")
	// ErrInvalidSignature indicates cryptographic verification failed.
	ErrInvalidSignature = errors.New("dnssec: signature verification failed")
	// ErrUnsupportedAlgorithm indicates the algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("dnssec: unsupported algorithm")
	// ErrInvalidKey indicates the public key format is invalid.
	ErrInvalidKey = errors.New("dnssec: invalid public key")
	// ErrTypeMismatch indicates the RRset type doesn't match RRSIG TypeCovered.
	ErrTypeMismatch = errors.New("dnssec: RRset type does not match RRSIG TypeCovered")
)

// VerifyRRSIG verifies an RRSIG signature over an RRset using the provided DNSKEY.
// It checks time validity and performs cryptographic verification.
func VerifyRRSIG(rrsig *dnsmsg.RDataRRSIG, key *dnsmsg.RDataDNSKEY, rrset []*dnsmsg.Resource) error {
	return VerifyRRSIGAt(rrsig, key, rrset, time.Now())
}

// VerifyRRSIGAt verifies an RRSIG signature at a specific time.
// This is useful for testing or verifying historical records.
func VerifyRRSIGAt(rrsig *dnsmsg.RDataRRSIG, key *dnsmsg.RDataDNSKEY, rrset []*dnsmsg.Resource, at time.Time) error {
	// Check time validity
	now := uint32(at.Unix())
	if now > rrsig.Expiration {
		return ErrSignatureExpired
	}
	if now < rrsig.Inception {
		return ErrSignatureNotYetValid
	}

	// Verify key tag matches
	if KeyTag(key) != rrsig.KeyTag {
		return ErrNoMatchingKey
	}

	// Verify algorithm matches
	if key.Algorithm != rrsig.Algorithm {
		return ErrNoMatchingKey
	}

	// Verify RRset type matches TypeCovered
	if len(rrset) > 0 && rrset[0].Type != rrsig.TypeCovered {
		return ErrTypeMismatch
	}

	// Build the signed data
	signedData, err := BuildSignedData(rrsig, rrset)
	if err != nil {
		return err
	}

	// Verify signature based on algorithm
	switch rrsig.Algorithm {
	case dnsmsg.AlgorithmRSASHA256:
		return verifyRSA(key.PublicKey, signedData, rrsig.Signature, crypto.SHA256)
	case dnsmsg.AlgorithmRSASHA512:
		return verifyRSA(key.PublicKey, signedData, rrsig.Signature, crypto.SHA512)
	case dnsmsg.AlgorithmECDSAP256:
		return verifyECDSA(key.PublicKey, signedData, rrsig.Signature, crypto.SHA256, 32)
	case dnsmsg.AlgorithmECDSAP384:
		return verifyECDSA(key.PublicKey, signedData, rrsig.Signature, crypto.SHA384, 48)
	case dnsmsg.AlgorithmED25519:
		return verifyEd25519(key.PublicKey, signedData, rrsig.Signature)
	default:
		return ErrUnsupportedAlgorithm
	}
}

// verifyRSA verifies an RSA signature.
func verifyRSA(pubKeyData, data, sig []byte, hashFunc crypto.Hash) error {
	pubKey, err := parseRSAPublicKey(pubKeyData)
	if err != nil {
		return err
	}

	var hash []byte
	switch hashFunc {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		hash = h[:]
	case crypto.SHA512:
		h := sha512.Sum512(data)
		hash = h[:]
	default:
		return ErrUnsupportedAlgorithm
	}

	err = rsa.VerifyPKCS1v15(pubKey, hashFunc, hash, sig)
	if err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// parseRSAPublicKey parses an RSA public key from DNSKEY RDATA format (RFC 3110).
// Format: 1-byte or 3-byte exponent length prefix, then exponent, then modulus.
func parseRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	if len(data) < 3 {
		return nil, ErrInvalidKey
	}

	var expLen int
	var offset int

	if data[0] == 0 {
		// 3-byte length prefix
		if len(data) < 4 {
			return nil, ErrInvalidKey
		}
		expLen = int(data[1])<<8 | int(data[2])
		offset = 3
	} else {
		// 1-byte length prefix
		expLen = int(data[0])
		offset = 1
	}

	if len(data) < offset+expLen {
		return nil, ErrInvalidKey
	}

	expBytes := data[offset : offset+expLen]
	modBytes := data[offset+expLen:]

	if len(modBytes) == 0 {
		return nil, ErrInvalidKey
	}

	exp := new(big.Int).SetBytes(expBytes)
	mod := new(big.Int).SetBytes(modBytes)

	// Exponent must fit in an int
	if !exp.IsInt64() || exp.Int64() > int64(1<<31-1) {
		return nil, ErrInvalidKey
	}

	return &rsa.PublicKey{
		N: mod,
		E: int(exp.Int64()),
	}, nil
}

// verifyECDSA verifies an ECDSA signature.
func verifyECDSA(pubKeyData, data, sig []byte, hashFunc crypto.Hash, coordLen int) error {
	pubKey, err := parseECDSAPublicKey(pubKeyData, coordLen)
	if err != nil {
		return err
	}

	// Signature is r || s, each coordLen bytes
	if len(sig) != coordLen*2 {
		return ErrInvalidSignature
	}

	r := new(big.Int).SetBytes(sig[:coordLen])
	s := new(big.Int).SetBytes(sig[coordLen:])

	var hash []byte
	switch hashFunc {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		hash = h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		hash = h[:]
	default:
		return ErrUnsupportedAlgorithm
	}

	if !ecdsa.Verify(pubKey, hash, r, s) {
		return ErrInvalidSignature
	}
	return nil
}

// parseECDSAPublicKey parses an ECDSA public key from DNSKEY RDATA format (RFC 6605).
// Format: X coordinate (coordLen bytes) || Y coordinate (coordLen bytes).
func parseECDSAPublicKey(data []byte, coordLen int) (*ecdsa.PublicKey, error) {
	if len(data) != coordLen*2 {
		return nil, ErrInvalidKey
	}

	var curve elliptic.Curve
	switch coordLen {
	case 32:
		curve = elliptic.P256()
	case 48:
		curve = elliptic.P384()
	default:
		return nil, ErrInvalidKey
	}

	x := new(big.Int).SetBytes(data[:coordLen])
	y := new(big.Int).SetBytes(data[coordLen:])

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, ErrInvalidKey
	}

	return pubKey, nil
}

// verifyEd25519 verifies an Ed25519 signature.
func verifyEd25519(pubKeyData, data, sig []byte) error {
	if len(pubKeyData) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}

	pubKey := ed25519.PublicKey(pubKeyData)
	if !ed25519.Verify(pubKey, data, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// FindMatchingKey searches a list of DNSKEYs for one that matches the RRSIG.
// Returns nil if no matching key is found.
func FindMatchingKey(rrsig *dnsmsg.RDataRRSIG, keys []*dnsmsg.RDataDNSKEY) *dnsmsg.RDataDNSKEY {
	for _, key := range keys {
		if KeyTag(key) == rrsig.KeyTag && key.Algorithm == rrsig.Algorithm {
			return key
		}
	}
	return nil
}
