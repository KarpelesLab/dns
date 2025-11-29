package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/KarpelesLab/dns/dnsmsg"
)

func TestKeyTag(t *testing.T) {
	// Test key tag calculation with a known DNSKEY
	key := &dnsmsg.RDataDNSKEY{
		Flags:     257,
		Protocol:  3,
		Algorithm: dnsmsg.AlgorithmECDSAP256,
		PublicKey: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
			0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
			0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
		},
	}

	tag := KeyTag(key)
	if tag == 0 {
		t.Error("key tag should not be zero")
	}

	// Key tag should be consistent
	tag2 := KeyTag(key)
	if tag != tag2 {
		t.Errorf("key tag should be consistent: got %d and %d", tag, tag2)
	}

	// Different key should have different tag (usually)
	key2 := &dnsmsg.RDataDNSKEY{
		Flags:     256,
		Protocol:  3,
		Algorithm: dnsmsg.AlgorithmECDSAP256,
		PublicKey: []byte{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
			0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
			0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
			0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
			0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
			0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
		},
	}
	tag3 := KeyTag(key2)
	if tag == tag3 {
		t.Log("warning: different keys have same tag (collision)")
	}
}

func TestCanonicalName(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"example.com.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"Example.COM.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"www.example.com.", []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
	}

	for _, tt := range tests {
		result := CanonicalName(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("CanonicalName(%q): length mismatch: got %d, want %d", tt.input, len(result), len(tt.expected))
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("CanonicalName(%q): byte %d mismatch: got %d, want %d", tt.input, i, result[i], tt.expected[i])
			}
		}
	}
}

func TestCountLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels uint8
	}{
		{"example.com.", 2},
		{"www.example.com.", 3},
		{".", 0},
		{"com.", 1},
		{"a.b.c.d.e.f.", 6},
	}

	for _, tt := range tests {
		got := CountLabels(tt.name)
		if got != tt.labels {
			t.Errorf("CountLabels(%q) = %d, want %d", tt.name, got, tt.labels)
		}
	}
}

func TestGenerateKeyECDSAP256(t *testing.T) {
	key, priv, err := GenerateKey(dnsmsg.AlgorithmECDSAP256, 0)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key.Algorithm != dnsmsg.AlgorithmECDSAP256 {
		t.Errorf("expected algorithm %d, got %d", dnsmsg.AlgorithmECDSAP256, key.Algorithm)
	}
	if key.Protocol != 3 {
		t.Errorf("expected protocol 3, got %d", key.Protocol)
	}
	if key.Flags != 256 {
		t.Errorf("expected ZSK flags 256, got %d", key.Flags)
	}
	if len(key.PublicKey) != 64 {
		t.Errorf("expected 64-byte P-256 public key, got %d bytes", len(key.PublicKey))
	}

	_, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", priv)
	}
}

func TestGenerateKeyED25519(t *testing.T) {
	key, priv, err := GenerateKey(dnsmsg.AlgorithmED25519, 0)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key.Algorithm != dnsmsg.AlgorithmED25519 {
		t.Errorf("expected algorithm %d, got %d", dnsmsg.AlgorithmED25519, key.Algorithm)
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("expected %d-byte Ed25519 public key, got %d bytes", ed25519.PublicKeySize, len(key.PublicKey))
	}

	_, ok := priv.(ed25519.PrivateKey)
	if !ok {
		t.Errorf("expected ed25519.PrivateKey, got %T", priv)
	}
}

func TestGenerateKeyRSA(t *testing.T) {
	key, priv, err := GenerateKey(dnsmsg.AlgorithmRSASHA256, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key.Algorithm != dnsmsg.AlgorithmRSASHA256 {
		t.Errorf("expected algorithm %d, got %d", dnsmsg.AlgorithmRSASHA256, key.Algorithm)
	}

	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", priv)
	}
	if rsaPriv.N.BitLen() < 2048 {
		t.Errorf("expected at least 2048-bit key, got %d bits", rsaPriv.N.BitLen())
	}
}

func TestGenerateKSK(t *testing.T) {
	key, _, err := GenerateKSK(dnsmsg.AlgorithmECDSAP256, 0)
	if err != nil {
		t.Fatalf("GenerateKSK failed: %v", err)
	}

	if key.Flags != 257 {
		t.Errorf("expected KSK flags 257, got %d", key.Flags)
	}
	if !key.IsKSK() {
		t.Error("key should be KSK")
	}
	if !key.IsSEP() {
		t.Error("KSK should have SEP flag")
	}
}

func TestSignAndVerifyECDSA(t *testing.T) {
	// Generate a key
	key, priv, err := GenerateKey(dnsmsg.AlgorithmECDSAP256, 0)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create a signer
	signer, err := NewSigner(key, priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Create an RRset to sign
	rrset := []*dnsmsg.Resource{
		{
			Name:  "example.com.",
			Type:  dnsmsg.A,
			Class: dnsmsg.IN,
			TTL:   300,
			Data:  &dnsmsg.RDataIP{IP: []byte{192, 0, 2, 1}, Type: dnsmsg.A},
		},
	}

	// Sign the RRset
	now := time.Now()
	inception := uint32(now.Unix())
	expiration := uint32(now.Add(24 * time.Hour).Unix())

	rrsig, err := signer.SignRRset(rrset, "example.com.", 300, inception, expiration)
	if err != nil {
		t.Fatalf("SignRRset failed: %v", err)
	}

	// Verify the signature
	err = VerifyRRSIG(rrsig, key, rrset)
	if err != nil {
		t.Fatalf("VerifyRRSIG failed: %v", err)
	}
}

func TestSignAndVerifyED25519(t *testing.T) {
	// Generate a key
	key, priv, err := GenerateKey(dnsmsg.AlgorithmED25519, 0)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create a signer
	signer, err := NewSigner(key, priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Create an RRset to sign
	rrset := []*dnsmsg.Resource{
		{
			Name:  "test.example.com.",
			Type:  dnsmsg.AAAA,
			Class: dnsmsg.IN,
			TTL:   600,
			Data:  &dnsmsg.RDataIP{IP: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Type: dnsmsg.AAAA},
		},
	}

	// Sign with duration
	rrsig, err := signer.SignRRsetWithDuration(rrset, "example.com.", 600, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignRRsetWithDuration failed: %v", err)
	}

	// Verify
	err = VerifyRRSIG(rrsig, key, rrset)
	if err != nil {
		t.Fatalf("VerifyRRSIG failed: %v", err)
	}
}

func TestVerifyExpiredSignature(t *testing.T) {
	key, priv, err := GenerateKey(dnsmsg.AlgorithmED25519, 0)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	signer, err := NewSigner(key, priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	rrset := []*dnsmsg.Resource{
		{
			Name:  "example.com.",
			Type:  dnsmsg.A,
			Class: dnsmsg.IN,
			TTL:   300,
			Data:  &dnsmsg.RDataIP{IP: []byte{192, 0, 2, 1}, Type: dnsmsg.A},
		},
	}

	// Create an expired signature
	past := time.Now().Add(-48 * time.Hour)
	rrsig, err := signer.SignRRset(rrset, "example.com.", 300,
		uint32(past.Add(-24*time.Hour).Unix()),
		uint32(past.Unix()))
	if err != nil {
		t.Fatalf("SignRRset failed: %v", err)
	}

	// Verification should fail with expired error
	err = VerifyRRSIG(rrsig, key, rrset)
	if err != ErrSignatureExpired {
		t.Errorf("expected ErrSignatureExpired, got %v", err)
	}
}

func TestVerifyFutureSignature(t *testing.T) {
	key, priv, err := GenerateKey(dnsmsg.AlgorithmED25519, 0)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	signer, err := NewSigner(key, priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	rrset := []*dnsmsg.Resource{
		{
			Name:  "example.com.",
			Type:  dnsmsg.A,
			Class: dnsmsg.IN,
			TTL:   300,
			Data:  &dnsmsg.RDataIP{IP: []byte{192, 0, 2, 1}, Type: dnsmsg.A},
		},
	}

	// Create a future signature
	future := time.Now().Add(48 * time.Hour)
	rrsig, err := signer.SignRRset(rrset, "example.com.", 300,
		uint32(future.Unix()),
		uint32(future.Add(24*time.Hour).Unix()))
	if err != nil {
		t.Fatalf("SignRRset failed: %v", err)
	}

	// Verification should fail with not yet valid error
	err = VerifyRRSIG(rrsig, key, rrset)
	if err != ErrSignatureNotYetValid {
		t.Errorf("expected ErrSignatureNotYetValid, got %v", err)
	}
}

func TestComputeAndVerifyDS(t *testing.T) {
	// Generate a KSK
	key, _, err := GenerateKSK(dnsmsg.AlgorithmECDSAP256, 0)
	if err != nil {
		t.Fatalf("GenerateKSK failed: %v", err)
	}

	owner := "example.com."

	// Compute DS record
	ds, err := ComputeDS(owner, key, dnsmsg.DigestSHA256)
	if err != nil {
		t.Fatalf("ComputeDS failed: %v", err)
	}

	// Verify DS values
	if ds.KeyTag != KeyTag(key) {
		t.Errorf("DS KeyTag mismatch: got %d, want %d", ds.KeyTag, KeyTag(key))
	}
	if ds.Algorithm != key.Algorithm {
		t.Errorf("DS Algorithm mismatch: got %d, want %d", ds.Algorithm, key.Algorithm)
	}
	if ds.DigestType != dnsmsg.DigestSHA256 {
		t.Errorf("DS DigestType mismatch: got %d, want %d", ds.DigestType, dnsmsg.DigestSHA256)
	}
	if len(ds.Digest) != 32 { // SHA-256 produces 32 bytes
		t.Errorf("DS Digest length mismatch: got %d, want 32", len(ds.Digest))
	}

	// Verify DS against DNSKEY
	if !VerifyDS(ds, owner, key) {
		t.Error("VerifyDS should return true for matching DS and DNSKEY")
	}

	// Modify key and verify DS fails
	modifiedKey := *key
	modifiedKey.PublicKey = make([]byte, len(key.PublicKey))
	copy(modifiedKey.PublicKey, key.PublicKey)
	modifiedKey.PublicKey[0] ^= 0xFF
	if VerifyDS(ds, owner, &modifiedKey) {
		t.Error("VerifyDS should return false for modified DNSKEY")
	}
}

func TestComputeDSSHA384(t *testing.T) {
	key, _, err := GenerateKSK(dnsmsg.AlgorithmECDSAP384, 0)
	if err != nil {
		t.Fatalf("GenerateKSK failed: %v", err)
	}

	ds, err := ComputeDS("example.com.", key, dnsmsg.DigestSHA384)
	if err != nil {
		t.Fatalf("ComputeDS failed: %v", err)
	}

	if len(ds.Digest) != 48 { // SHA-384 produces 48 bytes
		t.Errorf("DS Digest length mismatch: got %d, want 48", len(ds.Digest))
	}
}

func TestFindMatchingKey(t *testing.T) {
	// Generate multiple keys
	key1, _, _ := GenerateKey(dnsmsg.AlgorithmECDSAP256, 0)
	key2, _, _ := GenerateKey(dnsmsg.AlgorithmED25519, 0)
	key3, _, _ := GenerateKSK(dnsmsg.AlgorithmECDSAP256, 0)

	keys := []*dnsmsg.RDataDNSKEY{key1, key2, key3}

	// Create an RRSIG that matches key2
	rrsig := &dnsmsg.RDataRRSIG{
		Algorithm: key2.Algorithm,
		KeyTag:    KeyTag(key2),
	}

	found := FindMatchingKey(rrsig, keys)
	if found != key2 {
		t.Error("FindMatchingKey should find key2")
	}

	// Try with non-matching RRSIG
	rrsigNoMatch := &dnsmsg.RDataRRSIG{
		Algorithm: dnsmsg.AlgorithmRSASHA256,
		KeyTag:    65535,
	}
	found = FindMatchingKey(rrsigNoMatch, keys)
	if found != nil {
		t.Error("FindMatchingKey should return nil for non-matching RRSIG")
	}
}

func TestRSAKeyRoundTrip(t *testing.T) {
	// Generate RSA key
	key, priv, err := GenerateKey(dnsmsg.AlgorithmRSASHA256, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Parse the public key from DNSKEY format
	parsed, err := parseRSAPublicKey(key.PublicKey)
	if err != nil {
		t.Fatalf("parseRSAPublicKey failed: %v", err)
	}

	rsaPriv := priv.(*rsa.PrivateKey)
	if parsed.N.Cmp(rsaPriv.N) != 0 {
		t.Error("parsed N does not match original")
	}
	if parsed.E != rsaPriv.E {
		t.Errorf("parsed E does not match: got %d, want %d", parsed.E, rsaPriv.E)
	}
}
