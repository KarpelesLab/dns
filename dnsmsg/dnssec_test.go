package dnsmsg

import (
	"encoding/hex"
	"testing"
)

func TestParseDNSKEY(t *testing.T) {
	// DNSKEY from example.com (constructed test vector)
	// Flags=257 (KSK), Protocol=3, Algorithm=13 (ECDSAP256)
	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "example.com.",
			Type:  DNSKEY,
			Class: IN,
			TTL:   3600,
			Data: &RDataDNSKEY{
				Flags:     257,
				Protocol:  3,
				Algorithm: AlgorithmECDSAP256,
				PublicKey: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal DNSKEY: %v", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse DNSKEY: %v", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	dnskey, ok := parsed.Answer[0].Data.(*RDataDNSKEY)
	if !ok {
		t.Fatalf("expected *RDataDNSKEY, got %T", parsed.Answer[0].Data)
	}

	if dnskey.Flags != 257 {
		t.Errorf("expected Flags=257, got %d", dnskey.Flags)
	}
	if dnskey.Protocol != 3 {
		t.Errorf("expected Protocol=3, got %d", dnskey.Protocol)
	}
	if dnskey.Algorithm != AlgorithmECDSAP256 {
		t.Errorf("expected Algorithm=13, got %d", dnskey.Algorithm)
	}
	if !dnskey.IsKSK() {
		t.Error("expected IsKSK()=true")
	}
	if dnskey.IsZSK() {
		t.Error("expected IsZSK()=false for KSK")
	}
}

func TestParseRRSIG(t *testing.T) {
	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "example.com.",
			Type:  RRSIG,
			Class: IN,
			TTL:   3600,
			Data: &RDataRRSIG{
				TypeCovered: A,
				Algorithm:   AlgorithmECDSAP256,
				Labels:      2,
				OrigTTL:     300,
				Expiration:  1700000000,
				Inception:   1699000000,
				KeyTag:      12345,
				SignerName:  "example.com.",
				Signature:   []byte{0xde, 0xad, 0xbe, 0xef},
			},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal RRSIG: %v", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse RRSIG: %v", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	rrsig, ok := parsed.Answer[0].Data.(*RDataRRSIG)
	if !ok {
		t.Fatalf("expected *RDataRRSIG, got %T", parsed.Answer[0].Data)
	}

	if rrsig.TypeCovered != A {
		t.Errorf("expected TypeCovered=A, got %s", rrsig.TypeCovered)
	}
	if rrsig.Algorithm != AlgorithmECDSAP256 {
		t.Errorf("expected Algorithm=13, got %d", rrsig.Algorithm)
	}
	if rrsig.Labels != 2 {
		t.Errorf("expected Labels=2, got %d", rrsig.Labels)
	}
	if rrsig.OrigTTL != 300 {
		t.Errorf("expected OrigTTL=300, got %d", rrsig.OrigTTL)
	}
	if rrsig.Expiration != 1700000000 {
		t.Errorf("expected Expiration=1700000000, got %d", rrsig.Expiration)
	}
	if rrsig.Inception != 1699000000 {
		t.Errorf("expected Inception=1699000000, got %d", rrsig.Inception)
	}
	if rrsig.KeyTag != 12345 {
		t.Errorf("expected KeyTag=12345, got %d", rrsig.KeyTag)
	}
	if rrsig.SignerName != "example.com." {
		t.Errorf("expected SignerName=example.com., got %s", rrsig.SignerName)
	}
}

func TestParseDS(t *testing.T) {
	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "example.com.",
			Type:  DS,
			Class: IN,
			TTL:   86400,
			Data: &RDataDS{
				KeyTag:     12345,
				Algorithm:  AlgorithmECDSAP256,
				DigestType: DigestSHA256,
				Digest:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal DS: %v", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse DS: %v", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	ds, ok := parsed.Answer[0].Data.(*RDataDS)
	if !ok {
		t.Fatalf("expected *RDataDS, got %T", parsed.Answer[0].Data)
	}

	if ds.KeyTag != 12345 {
		t.Errorf("expected KeyTag=12345, got %d", ds.KeyTag)
	}
	if ds.Algorithm != AlgorithmECDSAP256 {
		t.Errorf("expected Algorithm=13, got %d", ds.Algorithm)
	}
	if ds.DigestType != DigestSHA256 {
		t.Errorf("expected DigestType=2, got %d", ds.DigestType)
	}
	if hex.EncodeToString(ds.Digest) != "0102030405060708" {
		t.Errorf("unexpected digest: %x", ds.Digest)
	}
}

func TestParseNSEC(t *testing.T) {
	// Create type bitmap for A, AAAA, RRSIG, NSEC
	typeBitmap := EncodeTypeBitmap([]Type{A, AAAA, RRSIG, NSEC})

	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "alpha.example.com.",
			Type:  NSEC,
			Class: IN,
			TTL:   3600,
			Data: &RDataNSEC{
				NextDomain: "beta.example.com.",
				TypeBitMap: typeBitmap,
			},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal NSEC: %v", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse NSEC: %v", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	nsec, ok := parsed.Answer[0].Data.(*RDataNSEC)
	if !ok {
		t.Fatalf("expected *RDataNSEC, got %T", parsed.Answer[0].Data)
	}

	if nsec.NextDomain != "beta.example.com." {
		t.Errorf("expected NextDomain=beta.example.com., got %s", nsec.NextDomain)
	}

	types := nsec.Types()
	expectedTypes := []Type{A, AAAA, RRSIG, NSEC}
	if len(types) != len(expectedTypes) {
		t.Errorf("expected %d types, got %d", len(expectedTypes), len(types))
	}

	if !nsec.HasType(A) {
		t.Error("expected NSEC to have type A")
	}
	if !nsec.HasType(AAAA) {
		t.Error("expected NSEC to have type AAAA")
	}
	if nsec.HasType(MX) {
		t.Error("expected NSEC to NOT have type MX")
	}
}

func TestParseNSEC3(t *testing.T) {
	typeBitmap := EncodeTypeBitmap([]Type{A, AAAA, RRSIG})

	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "abc123.example.com.",
			Type:  NSEC3,
			Class: IN,
			TTL:   3600,
			Data: &RDataNSEC3{
				HashAlgorithm:   NSEC3HashSHA1,
				Flags:           1, // Opt-Out
				Iterations:      10,
				Salt:            []byte{0xaa, 0xbb},
				NextHashedOwner: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
				TypeBitMap:      typeBitmap,
			},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal NSEC3: %v", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse NSEC3: %v", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	nsec3, ok := parsed.Answer[0].Data.(*RDataNSEC3)
	if !ok {
		t.Fatalf("expected *RDataNSEC3, got %T", parsed.Answer[0].Data)
	}

	if nsec3.HashAlgorithm != NSEC3HashSHA1 {
		t.Errorf("expected HashAlgorithm=1, got %d", nsec3.HashAlgorithm)
	}
	if !nsec3.IsOptOut() {
		t.Error("expected IsOptOut()=true")
	}
	if nsec3.Iterations != 10 {
		t.Errorf("expected Iterations=10, got %d", nsec3.Iterations)
	}
	if hex.EncodeToString(nsec3.Salt) != "aabb" {
		t.Errorf("unexpected salt: %x", nsec3.Salt)
	}

	types := nsec3.Types()
	if len(types) != 3 {
		t.Errorf("expected 3 types, got %d", len(types))
	}
}

func TestParseNSEC3PARAM(t *testing.T) {
	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "example.com.",
			Type:  NSEC3PARAM,
			Class: IN,
			TTL:   0,
			Data: &RDataNSEC3PARAM{
				HashAlgorithm: NSEC3HashSHA1,
				Flags:         0,
				Iterations:    5,
				Salt:          []byte{0xde, 0xad},
			},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal NSEC3PARAM: %v", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse NSEC3PARAM: %v", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	nsec3param, ok := parsed.Answer[0].Data.(*RDataNSEC3PARAM)
	if !ok {
		t.Fatalf("expected *RDataNSEC3PARAM, got %T", parsed.Answer[0].Data)
	}

	if nsec3param.HashAlgorithm != NSEC3HashSHA1 {
		t.Errorf("expected HashAlgorithm=1, got %d", nsec3param.HashAlgorithm)
	}
	if nsec3param.Flags != 0 {
		t.Errorf("expected Flags=0, got %d", nsec3param.Flags)
	}
	if nsec3param.Iterations != 5 {
		t.Errorf("expected Iterations=5, got %d", nsec3param.Iterations)
	}
	if hex.EncodeToString(nsec3param.Salt) != "dead" {
		t.Errorf("unexpected salt: %x", nsec3param.Salt)
	}
}

func TestTypeBitmapRoundTrip(t *testing.T) {
	testCases := [][]Type{
		{A},
		{A, AAAA},
		{A, AAAA, MX, TXT, RRSIG, NSEC},
		{A, AAAA, NS, SOA, MX, TXT, DNSKEY, RRSIG, NSEC},
		{}, // Empty
	}

	for i, types := range testCases {
		encoded := EncodeTypeBitmap(types)
		decoded := decodeTypeBitmap(encoded)

		if len(decoded) != len(types) {
			t.Errorf("case %d: expected %d types, got %d", i, len(types), len(decoded))
			continue
		}

		// Check all expected types are present (order may differ - bitmap decodes in numerical order)
		typeSet := make(map[Type]bool)
		for _, typ := range decoded {
			typeSet[typ] = true
		}
		for _, typ := range types {
			if !typeSet[typ] {
				t.Errorf("case %d: missing type %s in decoded bitmap", i, typ)
			}
		}
	}
}

func TestDNSKEYFlags(t *testing.T) {
	// ZSK: Flags=256 (zone key, not SEP)
	zsk := &RDataDNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgorithmED25519}
	if !zsk.IsZoneKey() {
		t.Error("ZSK should be zone key")
	}
	if zsk.IsSEP() {
		t.Error("ZSK should not be SEP")
	}
	if !zsk.IsZSK() {
		t.Error("ZSK IsZSK() should be true")
	}
	if zsk.IsKSK() {
		t.Error("ZSK IsKSK() should be false")
	}

	// KSK: Flags=257 (zone key + SEP)
	ksk := &RDataDNSKEY{Flags: 257, Protocol: 3, Algorithm: AlgorithmED25519}
	if !ksk.IsZoneKey() {
		t.Error("KSK should be zone key")
	}
	if !ksk.IsSEP() {
		t.Error("KSK should be SEP")
	}
	if ksk.IsZSK() {
		t.Error("KSK IsZSK() should be false")
	}
	if !ksk.IsKSK() {
		t.Error("KSK IsKSK() should be true")
	}
}

func TestRRSIGTimeValidity(t *testing.T) {
	// Expired signature
	expired := &RDataRRSIG{
		Inception:  1000000000,
		Expiration: 1000000001,
	}
	if !expired.IsExpired() {
		t.Error("signature should be expired")
	}

	// Future signature
	future := &RDataRRSIG{
		Inception:  4000000000,
		Expiration: 4100000000,
	}
	if !future.IsNotYetValid() {
		t.Error("signature should not be valid yet")
	}
}

func TestAlgorithmString(t *testing.T) {
	tests := []struct {
		alg  Algorithm
		want string
	}{
		{AlgorithmRSASHA256, "RSASHA256"},
		{AlgorithmECDSAP256, "ECDSAP256SHA256"},
		{AlgorithmED25519, "ED25519"},
		{Algorithm(99), "Algorithm99"},
	}

	for _, tt := range tests {
		if got := tt.alg.String(); got != tt.want {
			t.Errorf("Algorithm(%d).String() = %s, want %s", tt.alg, got, tt.want)
		}
	}
}

func TestDigestTypeString(t *testing.T) {
	tests := []struct {
		dt   DigestType
		want string
	}{
		{DigestSHA1, "SHA-1"},
		{DigestSHA256, "SHA-256"},
		{DigestSHA384, "SHA-384"},
		{DigestType(99), "DigestType99"},
	}

	for _, tt := range tests {
		if got := tt.dt.String(); got != tt.want {
			t.Errorf("DigestType(%d).String() = %s, want %s", tt.dt, got, tt.want)
		}
	}
}
