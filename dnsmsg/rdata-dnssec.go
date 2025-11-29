package dnsmsg

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Base32 encoding for NSEC3 (RFC 4648, extended hex alphabet, no padding)
var base32HexNoPad = base32.HexEncoding.WithPadding(base32.NoPadding)

// RDataDNSKEY represents a DNSKEY resource record (RFC 4034 Section 2).
// DNSKEY records hold public keys used for DNSSEC signature verification.
type RDataDNSKEY struct {
	Flags     uint16    // Key flags (256=ZSK, 257=KSK)
	Protocol  uint8     // Must be 3 for DNSSEC
	Algorithm Algorithm // Cryptographic algorithm
	PublicKey []byte    // Public key material (algorithm-specific format)
}

func (k *RDataDNSKEY) GetType() Type { return DNSKEY }

func (k *RDataDNSKEY) String() string {
	return fmt.Sprintf("%d %d %d %s", k.Flags, k.Protocol, k.Algorithm,
		base64.StdEncoding.EncodeToString(k.PublicKey))
}

func (k *RDataDNSKEY) encode(c *context) error {
	if err := binary.Write(c, binary.BigEndian, k.Flags); err != nil {
		return err
	}
	if _, err := c.Write([]byte{k.Protocol, byte(k.Algorithm)}); err != nil {
		return err
	}
	_, err := c.Write(k.PublicKey)
	return err
}

func (k *RDataDNSKEY) decode(c *context, d []byte) error {
	if len(d) < 4 {
		return ErrInvalidLen
	}
	k.Flags = binary.BigEndian.Uint16(d[0:2])
	k.Protocol = d[2]
	k.Algorithm = Algorithm(d[3])
	k.PublicKey = make([]byte, len(d)-4)
	copy(k.PublicKey, d[4:])
	return nil
}

// IsZoneKey returns true if this is a zone key (bit 7 set, flag value includes 256).
func (k *RDataDNSKEY) IsZoneKey() bool {
	return k.Flags&0x0100 != 0
}

// IsSEP returns true if this is a Secure Entry Point / Key Signing Key (bit 15 set).
func (k *RDataDNSKEY) IsSEP() bool {
	return k.Flags&0x0001 != 0
}

// IsKSK returns true if this is a Key Signing Key (ZoneKey + SEP flags).
func (k *RDataDNSKEY) IsKSK() bool {
	return k.IsZoneKey() && k.IsSEP()
}

// IsZSK returns true if this is a Zone Signing Key (ZoneKey flag only, not SEP).
func (k *RDataDNSKEY) IsZSK() bool {
	return k.IsZoneKey() && !k.IsSEP()
}

// RDataRRSIG represents an RRSIG resource record (RFC 4034 Section 3).
// RRSIG records contain digital signatures over RRsets.
type RDataRRSIG struct {
	TypeCovered Type      // RRtype covered by this signature
	Algorithm   Algorithm // Algorithm used for signing
	Labels      uint8     // Number of labels in original owner name
	OrigTTL     uint32    // Original TTL of covered RRset
	Expiration  uint32    // Signature expiration (Unix timestamp)
	Inception   uint32    // Signature inception (Unix timestamp)
	KeyTag      uint16    // Key tag of signing DNSKEY
	SignerName  string    // Signer's domain name
	Signature   []byte    // Cryptographic signature
}

func (r *RDataRRSIG) GetType() Type { return RRSIG }

func (r *RDataRRSIG) String() string {
	return fmt.Sprintf("%s %d %d %d %s %s %d %s %s",
		r.TypeCovered, r.Algorithm, r.Labels, r.OrigTTL,
		formatDNSSECTime(r.Expiration), formatDNSSECTime(r.Inception),
		r.KeyTag, r.SignerName, base64.StdEncoding.EncodeToString(r.Signature))
}

func (r *RDataRRSIG) encode(c *context) error {
	if err := binary.Write(c, binary.BigEndian, r.TypeCovered); err != nil {
		return err
	}
	if _, err := c.Write([]byte{byte(r.Algorithm), r.Labels}); err != nil {
		return err
	}
	if err := binary.Write(c, binary.BigEndian, r.OrigTTL); err != nil {
		return err
	}
	if err := binary.Write(c, binary.BigEndian, r.Expiration); err != nil {
		return err
	}
	if err := binary.Write(c, binary.BigEndian, r.Inception); err != nil {
		return err
	}
	if err := binary.Write(c, binary.BigEndian, r.KeyTag); err != nil {
		return err
	}
	if err := c.appendLabel(r.SignerName); err != nil {
		return err
	}
	_, err := c.Write(r.Signature)
	return err
}

func (r *RDataRRSIG) decode(c *context, d []byte) error {
	if len(d) < 18 {
		return ErrInvalidLen
	}
	r.TypeCovered = Type(binary.BigEndian.Uint16(d[0:2]))
	r.Algorithm = Algorithm(d[2])
	r.Labels = d[3]
	r.OrigTTL = binary.BigEndian.Uint32(d[4:8])
	r.Expiration = binary.BigEndian.Uint32(d[8:12])
	r.Inception = binary.BigEndian.Uint32(d[12:16])
	r.KeyTag = binary.BigEndian.Uint16(d[16:18])

	signerName, n, err := c.readLabel(d[18:])
	if err != nil {
		return err
	}
	r.SignerName = signerName
	r.Signature = make([]byte, len(d)-18-n)
	copy(r.Signature, d[18+n:])
	return nil
}

// IsExpired returns true if the signature has expired.
func (r *RDataRRSIG) IsExpired() bool {
	return time.Now().Unix() > int64(r.Expiration)
}

// IsNotYetValid returns true if the signature is not yet within its validity window.
func (r *RDataRRSIG) IsNotYetValid() bool {
	return time.Now().Unix() < int64(r.Inception)
}

// ExpirationTime returns the expiration as a time.Time.
func (r *RDataRRSIG) ExpirationTime() time.Time {
	return time.Unix(int64(r.Expiration), 0)
}

// InceptionTime returns the inception as a time.Time.
func (r *RDataRRSIG) InceptionTime() time.Time {
	return time.Unix(int64(r.Inception), 0)
}

// RDataDS represents a DS (Delegation Signer) resource record (RFC 4034 Section 5).
// DS records are used to establish chain of trust between parent and child zones.
type RDataDS struct {
	KeyTag     uint16     // Key tag of referenced DNSKEY
	Algorithm  Algorithm  // Algorithm of referenced DNSKEY
	DigestType DigestType // Hash algorithm used
	Digest     []byte     // Hash of the DNSKEY
}

func (d *RDataDS) GetType() Type { return DS }

func (ds *RDataDS) String() string {
	return fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType,
		strings.ToUpper(hex.EncodeToString(ds.Digest)))
}

func (ds *RDataDS) encode(c *context) error {
	if err := binary.Write(c, binary.BigEndian, ds.KeyTag); err != nil {
		return err
	}
	if _, err := c.Write([]byte{byte(ds.Algorithm), byte(ds.DigestType)}); err != nil {
		return err
	}
	_, err := c.Write(ds.Digest)
	return err
}

func (ds *RDataDS) decode(c *context, d []byte) error {
	if len(d) < 4 {
		return ErrInvalidLen
	}
	ds.KeyTag = binary.BigEndian.Uint16(d[0:2])
	ds.Algorithm = Algorithm(d[2])
	ds.DigestType = DigestType(d[3])
	ds.Digest = make([]byte, len(d)-4)
	copy(ds.Digest, d[4:])
	return nil
}

// RDataNSEC represents an NSEC resource record (RFC 4034 Section 4).
// NSEC records provide authenticated denial of existence.
type RDataNSEC struct {
	NextDomain string // Next domain name in canonical order
	TypeBitMap []byte // Bitmap of types present at owner name
}

func (n *RDataNSEC) GetType() Type { return NSEC }

func (n *RDataNSEC) String() string {
	types := n.Types()
	typeStrs := make([]string, len(types))
	for i, t := range types {
		typeStrs[i] = t.String()
	}
	return fmt.Sprintf("%s %s", n.NextDomain, strings.Join(typeStrs, " "))
}

func (n *RDataNSEC) encode(c *context) error {
	if err := c.appendLabel(n.NextDomain); err != nil {
		return err
	}
	_, err := c.Write(n.TypeBitMap)
	return err
}

func (n *RDataNSEC) decode(c *context, d []byte) error {
	if len(d) < 1 {
		return ErrInvalidLen
	}
	nextDomain, read, err := c.readLabel(d)
	if err != nil {
		return err
	}
	n.NextDomain = nextDomain
	n.TypeBitMap = make([]byte, len(d)-read)
	copy(n.TypeBitMap, d[read:])
	return nil
}

// Types returns the list of DNS types present at the owner name.
func (n *RDataNSEC) Types() []Type {
	return decodeTypeBitmap(n.TypeBitMap)
}

// HasType returns true if the type bitmap includes the specified type.
func (n *RDataNSEC) HasType(t Type) bool {
	for _, bt := range n.Types() {
		if bt == t {
			return true
		}
	}
	return false
}

// RDataNSEC3 represents an NSEC3 resource record (RFC 5155 Section 3).
// NSEC3 provides authenticated denial of existence with hashed owner names.
type RDataNSEC3 struct {
	HashAlgorithm   NSEC3HashAlg // Hash algorithm (1 = SHA-1)
	Flags           uint8        // Opt-Out flag (bit 0)
	Iterations      uint16       // Number of hash iterations
	Salt            []byte       // Salt value
	NextHashedOwner []byte       // Next hashed owner name (binary)
	TypeBitMap      []byte       // Bitmap of types
}

func (n *RDataNSEC3) GetType() Type { return NSEC3 }

func (n *RDataNSEC3) String() string {
	types := n.Types()
	typeStrs := make([]string, len(types))
	for i, t := range types {
		typeStrs[i] = t.String()
	}
	saltHex := "-"
	if len(n.Salt) > 0 {
		saltHex = strings.ToUpper(hex.EncodeToString(n.Salt))
	}
	return fmt.Sprintf("%d %d %d %s %s %s",
		n.HashAlgorithm, n.Flags, n.Iterations, saltHex,
		strings.ToUpper(base32HexNoPad.EncodeToString(n.NextHashedOwner)),
		strings.Join(typeStrs, " "))
}

func (n *RDataNSEC3) encode(c *context) error {
	if _, err := c.Write([]byte{byte(n.HashAlgorithm), n.Flags}); err != nil {
		return err
	}
	if err := binary.Write(c, binary.BigEndian, n.Iterations); err != nil {
		return err
	}
	// Salt length + salt
	if _, err := c.Write([]byte{byte(len(n.Salt))}); err != nil {
		return err
	}
	if _, err := c.Write(n.Salt); err != nil {
		return err
	}
	// Hash length + hash
	if _, err := c.Write([]byte{byte(len(n.NextHashedOwner))}); err != nil {
		return err
	}
	if _, err := c.Write(n.NextHashedOwner); err != nil {
		return err
	}
	_, err := c.Write(n.TypeBitMap)
	return err
}

func (n *RDataNSEC3) decode(c *context, d []byte) error {
	if len(d) < 5 {
		return ErrInvalidLen
	}
	n.HashAlgorithm = NSEC3HashAlg(d[0])
	n.Flags = d[1]
	n.Iterations = binary.BigEndian.Uint16(d[2:4])

	saltLen := int(d[4])
	if len(d) < 5+saltLen+1 {
		return ErrInvalidLen
	}
	n.Salt = make([]byte, saltLen)
	copy(n.Salt, d[5:5+saltLen])

	hashLen := int(d[5+saltLen])
	if len(d) < 5+saltLen+1+hashLen {
		return ErrInvalidLen
	}
	n.NextHashedOwner = make([]byte, hashLen)
	copy(n.NextHashedOwner, d[6+saltLen:6+saltLen+hashLen])

	bitmapStart := 6 + saltLen + hashLen
	n.TypeBitMap = make([]byte, len(d)-bitmapStart)
	copy(n.TypeBitMap, d[bitmapStart:])
	return nil
}

// IsOptOut returns true if the Opt-Out flag is set.
func (n *RDataNSEC3) IsOptOut() bool {
	return n.Flags&0x01 != 0
}

// Types returns the list of DNS types present at the owner name.
func (n *RDataNSEC3) Types() []Type {
	return decodeTypeBitmap(n.TypeBitMap)
}

// HasType returns true if the type bitmap includes the specified type.
func (n *RDataNSEC3) HasType(t Type) bool {
	for _, bt := range n.Types() {
		if bt == t {
			return true
		}
	}
	return false
}

// RDataNSEC3PARAM represents an NSEC3PARAM resource record (RFC 5155 Section 4).
// NSEC3PARAM records indicate the NSEC3 parameters used for a zone.
type RDataNSEC3PARAM struct {
	HashAlgorithm NSEC3HashAlg // Hash algorithm
	Flags         uint8        // Flags (should be 0 for NSEC3PARAM)
	Iterations    uint16       // Hash iterations
	Salt          []byte       // Salt value
}

func (n *RDataNSEC3PARAM) GetType() Type { return NSEC3PARAM }

func (n *RDataNSEC3PARAM) String() string {
	saltHex := "-"
	if len(n.Salt) > 0 {
		saltHex = strings.ToUpper(hex.EncodeToString(n.Salt))
	}
	return fmt.Sprintf("%d %d %d %s", n.HashAlgorithm, n.Flags, n.Iterations, saltHex)
}

func (n *RDataNSEC3PARAM) encode(c *context) error {
	if _, err := c.Write([]byte{byte(n.HashAlgorithm), n.Flags}); err != nil {
		return err
	}
	if err := binary.Write(c, binary.BigEndian, n.Iterations); err != nil {
		return err
	}
	if _, err := c.Write([]byte{byte(len(n.Salt))}); err != nil {
		return err
	}
	_, err := c.Write(n.Salt)
	return err
}

func (n *RDataNSEC3PARAM) decode(c *context, d []byte) error {
	if len(d) < 5 {
		return ErrInvalidLen
	}
	n.HashAlgorithm = NSEC3HashAlg(d[0])
	n.Flags = d[1]
	n.Iterations = binary.BigEndian.Uint16(d[2:4])

	saltLen := int(d[4])
	if len(d) < 5+saltLen {
		return ErrInvalidLen
	}
	n.Salt = make([]byte, saltLen)
	copy(n.Salt, d[5:5+saltLen])
	return nil
}

// Helper functions

// formatDNSSECTime formats a Unix timestamp as YYYYMMDDHHmmss.
func formatDNSSECTime(t uint32) string {
	return time.Unix(int64(t), 0).UTC().Format("20060102150405")
}

// decodeTypeBitmap parses the NSEC/NSEC3 type bitmap format.
func decodeTypeBitmap(data []byte) []Type {
	var types []Type
	for len(data) >= 2 {
		window := int(data[0])
		bitmapLen := int(data[1])
		if len(data) < 2+bitmapLen {
			break
		}
		bitmap := data[2 : 2+bitmapLen]
		for i, b := range bitmap {
			for bit := 0; bit < 8; bit++ {
				if b&(0x80>>bit) != 0 {
					typeNum := window*256 + i*8 + bit
					types = append(types, Type(typeNum))
				}
			}
		}
		data = data[2+bitmapLen:]
	}
	return types
}

// EncodeTypeBitmap encodes a list of types to NSEC/NSEC3 bitmap format.
func EncodeTypeBitmap(types []Type) []byte {
	if len(types) == 0 {
		return nil
	}

	// Group types by window
	windows := make(map[uint8][]uint8)
	for _, t := range types {
		window := uint8(t >> 8)
		bit := uint8(t & 0xFF)
		windows[window] = append(windows[window], bit)
	}

	var result []byte
	// Process windows in order
	for window := 0; window <= 255; window++ {
		bits, ok := windows[uint8(window)]
		if !ok {
			continue
		}

		// Find the highest bit to determine bitmap length
		maxBit := uint8(0)
		for _, bit := range bits {
			if bit > maxBit {
				maxBit = bit
			}
		}
		bitmapLen := (maxBit / 8) + 1

		// Create bitmap
		bitmap := make([]byte, bitmapLen)
		for _, bit := range bits {
			byteIdx := bit / 8
			bitIdx := 7 - (bit % 8)
			bitmap[byteIdx] |= 1 << bitIdx
		}

		result = append(result, uint8(window), uint8(bitmapLen))
		result = append(result, bitmap...)
	}
	return result
}
