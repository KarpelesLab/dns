package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"time"

	"github.com/KarpelesLab/dns/dnsmsg"
)

var (
	// ErrKeyMismatch indicates the private key doesn't match the DNSKEY.
	ErrKeyMismatch = errors.New("dnssec: private key does not match DNSKEY")
	// ErrSigningFailed indicates the signing operation failed.
	ErrSigningFailed = errors.New("dnssec: signing failed")
)

// Signer holds a DNSKEY and its corresponding private key for signing.
type Signer struct {
	Key     *dnsmsg.RDataDNSKEY
	Private crypto.Signer
	keyTag  uint16
}

// NewSigner creates a new Signer from a DNSKEY and its private key.
func NewSigner(key *dnsmsg.RDataDNSKEY, priv crypto.Signer) (*Signer, error) {
	// Verify the private key matches the public key in DNSKEY
	if err := verifyKeyPair(key, priv); err != nil {
		return nil, err
	}

	return &Signer{
		Key:     key,
		Private: priv,
		keyTag:  KeyTag(key),
	}, nil
}

// KeyTag returns the key tag for this signer's DNSKEY.
func (s *Signer) KeyTag() uint16 {
	return s.keyTag
}

// SignRRset creates an RRSIG for an RRset.
func (s *Signer) SignRRset(rrset []*dnsmsg.Resource, signerName string, ttl uint32, inception, expiration uint32) (*dnsmsg.RDataRRSIG, error) {
	if len(rrset) == 0 {
		return nil, errors.New("dnssec: empty RRset")
	}

	// Create RRSIG record (without signature initially)
	rrsig := &dnsmsg.RDataRRSIG{
		TypeCovered: rrset[0].Type,
		Algorithm:   s.Key.Algorithm,
		Labels:      CountLabels(rrset[0].Name),
		OrigTTL:     ttl,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      s.keyTag,
		SignerName:  signerName,
	}

	// Build the data to sign
	signedData, err := BuildSignedData(rrsig, rrset)
	if err != nil {
		return nil, err
	}

	// Sign based on algorithm
	sig, err := s.sign(signedData)
	if err != nil {
		return nil, err
	}

	rrsig.Signature = sig
	return rrsig, nil
}

// SignRRsetWithDuration creates an RRSIG with inception at the current time
// and expiration after the specified duration.
func (s *Signer) SignRRsetWithDuration(rrset []*dnsmsg.Resource, signerName string, ttl uint32, validity time.Duration) (*dnsmsg.RDataRRSIG, error) {
	now := time.Now()
	inception := uint32(now.Unix())
	expiration := uint32(now.Add(validity).Unix())
	return s.SignRRset(rrset, signerName, ttl, inception, expiration)
}

// sign performs the actual signing operation.
func (s *Signer) sign(data []byte) ([]byte, error) {
	switch s.Key.Algorithm {
	case dnsmsg.AlgorithmRSASHA256:
		hash := sha256.Sum256(data)
		return s.Private.Sign(rand.Reader, hash[:], crypto.SHA256)
	case dnsmsg.AlgorithmRSASHA512:
		hash := sha512.Sum512(data)
		return s.Private.Sign(rand.Reader, hash[:], crypto.SHA512)
	case dnsmsg.AlgorithmECDSAP256:
		return s.signECDSA(data, crypto.SHA256, 32)
	case dnsmsg.AlgorithmECDSAP384:
		return s.signECDSA(data, crypto.SHA384, 48)
	case dnsmsg.AlgorithmED25519:
		return s.Private.Sign(rand.Reader, data, crypto.Hash(0))
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// signECDSA performs ECDSA signing and converts to DNS wire format (r || s).
func (s *Signer) signECDSA(data []byte, hashFunc crypto.Hash, coordLen int) ([]byte, error) {
	ecKey, ok := s.Private.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrKeyMismatch
	}

	var hash []byte
	switch hashFunc {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		hash = h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		hash = h[:]
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	r, sVal, err := ecdsa.Sign(rand.Reader, ecKey, hash)
	if err != nil {
		return nil, ErrSigningFailed
	}

	// Convert to wire format: r || s, each padded to coordLen
	sig := make([]byte, coordLen*2)
	rBytes := r.Bytes()
	sBytes := sVal.Bytes()
	copy(sig[coordLen-len(rBytes):coordLen], rBytes)
	copy(sig[coordLen*2-len(sBytes):], sBytes)

	return sig, nil
}

// verifyKeyPair checks that the private key matches the DNSKEY public key.
func verifyKeyPair(key *dnsmsg.RDataDNSKEY, priv crypto.Signer) error {
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		// Extract public key from DNSKEY and compare
		pubKey, err := parseRSAPublicKey(key.PublicKey)
		if err != nil {
			return err
		}
		if priv.N.Cmp(pubKey.N) != 0 || priv.E != pubKey.E {
			return ErrKeyMismatch
		}
	case *ecdsa.PrivateKey:
		var coordLen int
		switch key.Algorithm {
		case dnsmsg.AlgorithmECDSAP256:
			coordLen = 32
		case dnsmsg.AlgorithmECDSAP384:
			coordLen = 48
		default:
			return ErrKeyMismatch
		}
		pubKey, err := parseECDSAPublicKey(key.PublicKey, coordLen)
		if err != nil {
			return err
		}
		if priv.X.Cmp(pubKey.X) != 0 || priv.Y.Cmp(pubKey.Y) != 0 {
			return ErrKeyMismatch
		}
	case ed25519.PrivateKey:
		if len(key.PublicKey) != ed25519.PublicKeySize {
			return ErrKeyMismatch
		}
		pubKey := priv.Public().(ed25519.PublicKey)
		for i := 0; i < ed25519.PublicKeySize; i++ {
			if key.PublicKey[i] != pubKey[i] {
				return ErrKeyMismatch
			}
		}
	default:
		return errors.New("dnssec: unsupported private key type")
	}
	return nil
}

// GenerateKey generates a new DNSSEC key pair.
// For RSA, bits should be 2048 or 4096. For ECDSA and Ed25519, bits is ignored.
func GenerateKey(algorithm dnsmsg.Algorithm, bits int) (*dnsmsg.RDataDNSKEY, crypto.Signer, error) {
	var priv crypto.Signer
	var pubKeyData []byte
	var err error

	switch algorithm {
	case dnsmsg.AlgorithmRSASHA256, dnsmsg.AlgorithmRSASHA512:
		priv, pubKeyData, err = generateRSAKey(bits)
	case dnsmsg.AlgorithmECDSAP256:
		priv, pubKeyData, err = generateECDSAKey(elliptic.P256(), 32)
	case dnsmsg.AlgorithmECDSAP384:
		priv, pubKeyData, err = generateECDSAKey(elliptic.P384(), 48)
	case dnsmsg.AlgorithmED25519:
		priv, pubKeyData, err = generateEd25519Key()
	default:
		return nil, nil, ErrUnsupportedAlgorithm
	}

	if err != nil {
		return nil, nil, err
	}

	key := &dnsmsg.RDataDNSKEY{
		Flags:     256, // Zone key (ZSK)
		Protocol:  3,   // DNSSEC
		Algorithm: algorithm,
		PublicKey: pubKeyData,
	}

	return key, priv, nil
}

// GenerateKSK generates a Key Signing Key (KSK) with the SEP flag set.
func GenerateKSK(algorithm dnsmsg.Algorithm, bits int) (*dnsmsg.RDataDNSKEY, crypto.Signer, error) {
	key, priv, err := GenerateKey(algorithm, bits)
	if err != nil {
		return nil, nil, err
	}
	key.Flags = 257 // Zone key + SEP (KSK)
	return key, priv, nil
}

// generateRSAKey generates an RSA key pair and returns the public key in DNS wire format.
func generateRSAKey(bits int) (*rsa.PrivateKey, []byte, error) {
	if bits < 2048 {
		bits = 2048
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	// Encode public key in RFC 3110 format
	pubKeyData := encodeRSAPublicKey(&priv.PublicKey)
	return priv, pubKeyData, nil
}

// encodeRSAPublicKey encodes an RSA public key in DNS wire format (RFC 3110).
func encodeRSAPublicKey(pub *rsa.PublicKey) []byte {
	expBytes := big.NewInt(int64(pub.E)).Bytes()
	modBytes := pub.N.Bytes()

	var data []byte
	if len(expBytes) <= 255 {
		data = make([]byte, 1+len(expBytes)+len(modBytes))
		data[0] = byte(len(expBytes))
		copy(data[1:], expBytes)
		copy(data[1+len(expBytes):], modBytes)
	} else {
		data = make([]byte, 3+len(expBytes)+len(modBytes))
		data[0] = 0
		binary.BigEndian.PutUint16(data[1:3], uint16(len(expBytes)))
		copy(data[3:], expBytes)
		copy(data[3+len(expBytes):], modBytes)
	}

	return data
}

// generateECDSAKey generates an ECDSA key pair.
func generateECDSAKey(curve elliptic.Curve, coordLen int) (*ecdsa.PrivateKey, []byte, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Encode public key: X || Y, each padded to coordLen
	pubKeyData := make([]byte, coordLen*2)
	xBytes := priv.X.Bytes()
	yBytes := priv.Y.Bytes()
	copy(pubKeyData[coordLen-len(xBytes):coordLen], xBytes)
	copy(pubKeyData[coordLen*2-len(yBytes):], yBytes)

	return priv, pubKeyData, nil
}

// generateEd25519Key generates an Ed25519 key pair.
func generateEd25519Key() (ed25519.PrivateKey, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}
