package dnsmsg

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// CERT record types as defined in RFC 4398
type CertType uint16

const (
	CertTypePKIX    CertType = 1 // X.509 certificate
	CertTypeSPKI    CertType = 2 // SPKI certificate
	CertTypePGP     CertType = 3 // OpenPGP packet
	CertTypeIPKIX   CertType = 4 // URL of X.509 certificate
	CertTypeISPKI   CertType = 5 // URL of SPKI certificate
	CertTypeIPGP    CertType = 6 // Fingerprint and URL of OpenPGP packet
	CertTypeACPKIX  CertType = 7 // Attribute Certificate
	CertTypeIACPKIX CertType = 8 // URL of Attribute Certificate
	CertTypeURI     CertType = 253
	CertTypeOID     CertType = 254
)

// RDataCERT represents a CERT resource record (RFC 4398).
// CERT records store certificates and related certificate information.
type RDataCERT struct {
	CertType    CertType  // Certificate type
	KeyTag      uint16    // Key tag value
	Algorithm   Algorithm // Algorithm number
	Certificate []byte    // Certificate or CRL data
}

func (c *RDataCERT) GetType() Type { return CERT }

func (c *RDataCERT) String() string {
	return fmt.Sprintf("%d %d %d %s", c.CertType, c.KeyTag, c.Algorithm,
		strings.ToUpper(hex.EncodeToString(c.Certificate)))
}

func (c *RDataCERT) encode(ctx *context) error {
	if err := binary.Write(ctx, binary.BigEndian, c.CertType); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, c.KeyTag); err != nil {
		return err
	}
	if _, err := ctx.Write([]byte{byte(c.Algorithm)}); err != nil {
		return err
	}
	_, err := ctx.Write(c.Certificate)
	return err
}

func (c *RDataCERT) decode(ctx *context, d []byte) error {
	if len(d) < 5 {
		return ErrInvalidLen
	}
	c.CertType = CertType(binary.BigEndian.Uint16(d[0:2]))
	c.KeyTag = binary.BigEndian.Uint16(d[2:4])
	c.Algorithm = Algorithm(d[4])
	c.Certificate = make([]byte, len(d)-5)
	copy(c.Certificate, d[5:])
	return nil
}

// TSIG modes
type TSIGError uint16

const (
	TSIGNoError  TSIGError = 0
	TSIGBadSig   TSIGError = 16
	TSIGBadKey   TSIGError = 17
	TSIGBadTime  TSIGError = 18
	TSIGBadMode  TSIGError = 19
	TSIGBadName  TSIGError = 20
	TSIGBadAlg   TSIGError = 21
	TSIGBadTrunc TSIGError = 22
)

// RDataTSIG represents a TSIG resource record (RFC 8945).
// TSIG records provide transaction-level authentication for DNS messages.
type RDataTSIG struct {
	Algorithm  string    // Algorithm name (e.g., "hmac-sha256.")
	TimeSigned uint64    // Seconds since epoch (48-bit, stored in 64-bit)
	Fudge      uint16    // Seconds of error permitted
	MAC        []byte    // Message Authentication Code
	OriginalID uint16    // Original message ID
	Error      TSIGError // TSIG Error code
	OtherData  []byte    // Other data (for BADTIME errors)
}

func (t *RDataTSIG) GetType() Type { return TSIG }

func (t *RDataTSIG) String() string {
	return fmt.Sprintf("%s %d %d %s %d %d",
		t.Algorithm, t.TimeSigned, t.Fudge,
		strings.ToUpper(hex.EncodeToString(t.MAC)),
		t.OriginalID, t.Error)
}

func (t *RDataTSIG) encode(ctx *context) error {
	if err := ctx.appendLabel(t.Algorithm); err != nil {
		return err
	}
	// Time is 48 bits (6 bytes)
	timeBuf := make([]byte, 6)
	timeBuf[0] = byte(t.TimeSigned >> 40)
	timeBuf[1] = byte(t.TimeSigned >> 32)
	timeBuf[2] = byte(t.TimeSigned >> 24)
	timeBuf[3] = byte(t.TimeSigned >> 16)
	timeBuf[4] = byte(t.TimeSigned >> 8)
	timeBuf[5] = byte(t.TimeSigned)
	if _, err := ctx.Write(timeBuf); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, t.Fudge); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, uint16(len(t.MAC))); err != nil {
		return err
	}
	if _, err := ctx.Write(t.MAC); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, t.OriginalID); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, t.Error); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, uint16(len(t.OtherData))); err != nil {
		return err
	}
	_, err := ctx.Write(t.OtherData)
	return err
}

func (t *RDataTSIG) decode(ctx *context, d []byte) error {
	if len(d) < 1 {
		return ErrInvalidLen
	}
	alg, n, err := ctx.readLabel(d)
	if err != nil {
		return err
	}
	t.Algorithm = alg
	d = d[n:]

	if len(d) < 16 {
		return ErrInvalidLen
	}
	// Time is 48 bits
	t.TimeSigned = uint64(d[0])<<40 | uint64(d[1])<<32 | uint64(d[2])<<24 |
		uint64(d[3])<<16 | uint64(d[4])<<8 | uint64(d[5])
	t.Fudge = binary.BigEndian.Uint16(d[6:8])
	macLen := binary.BigEndian.Uint16(d[8:10])
	d = d[10:]

	if len(d) < int(macLen)+6 {
		return ErrInvalidLen
	}
	t.MAC = make([]byte, macLen)
	copy(t.MAC, d[:macLen])
	d = d[macLen:]

	t.OriginalID = binary.BigEndian.Uint16(d[0:2])
	t.Error = TSIGError(binary.BigEndian.Uint16(d[2:4]))
	otherLen := binary.BigEndian.Uint16(d[4:6])
	d = d[6:]

	if len(d) < int(otherLen) {
		return ErrInvalidLen
	}
	t.OtherData = make([]byte, otherLen)
	copy(t.OtherData, d[:otherLen])
	return nil
}

// TKEY modes as defined in RFC 2930
type TKEYMode uint16

const (
	TKEYModeServerAssignment TKEYMode = 1
	TKEYModeDiffieHellman    TKEYMode = 2
	TKEYModeGSSAPI           TKEYMode = 3
	TKEYModeResolverAssigned TKEYMode = 4
	TKEYModeKeyDeletion      TKEYMode = 5
)

// RDataTKEY represents a TKEY resource record (RFC 2930).
// TKEY records are used to establish shared secret keys between DNS entities.
type RDataTKEY struct {
	Algorithm  string    // Algorithm name
	Inception  uint32    // Validity start time
	Expiration uint32    // Validity end time
	Mode       TKEYMode  // Key agreement mode
	Error      TSIGError // Error code
	Key        []byte    // Key data
	OtherData  []byte    // Other data
}

func (t *RDataTKEY) GetType() Type { return TKEY }

func (t *RDataTKEY) String() string {
	return fmt.Sprintf("%s %d %d %d %d", t.Algorithm, t.Inception, t.Expiration, t.Mode, t.Error)
}

func (t *RDataTKEY) encode(ctx *context) error {
	if err := ctx.appendLabel(t.Algorithm); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, t.Inception); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, t.Expiration); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, t.Mode); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, t.Error); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, uint16(len(t.Key))); err != nil {
		return err
	}
	if _, err := ctx.Write(t.Key); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, uint16(len(t.OtherData))); err != nil {
		return err
	}
	_, err := ctx.Write(t.OtherData)
	return err
}

func (t *RDataTKEY) decode(ctx *context, d []byte) error {
	if len(d) < 1 {
		return ErrInvalidLen
	}
	alg, n, err := ctx.readLabel(d)
	if err != nil {
		return err
	}
	t.Algorithm = alg
	d = d[n:]

	if len(d) < 16 {
		return ErrInvalidLen
	}
	t.Inception = binary.BigEndian.Uint32(d[0:4])
	t.Expiration = binary.BigEndian.Uint32(d[4:8])
	t.Mode = TKEYMode(binary.BigEndian.Uint16(d[8:10]))
	t.Error = TSIGError(binary.BigEndian.Uint16(d[10:12]))
	keyLen := binary.BigEndian.Uint16(d[12:14])
	d = d[14:]

	if len(d) < int(keyLen)+2 {
		return ErrInvalidLen
	}
	t.Key = make([]byte, keyLen)
	copy(t.Key, d[:keyLen])
	d = d[keyLen:]

	otherLen := binary.BigEndian.Uint16(d[0:2])
	d = d[2:]
	if len(d) < int(otherLen) {
		return ErrInvalidLen
	}
	t.OtherData = make([]byte, otherLen)
	copy(t.OtherData, d[:otherLen])
	return nil
}

// RDataSRV represents an SRV resource record (RFC 2782).
// SRV records specify the location of servers for specified services.
type RDataSRV struct {
	Priority uint16 // Priority (lower is preferred)
	Weight   uint16 // Weight for load balancing
	Port     uint16 // TCP/UDP port number
	Target   string // Target host name
}

func (s *RDataSRV) GetType() Type { return SRV }

func (s *RDataSRV) String() string {
	return fmt.Sprintf("%d %d %d %s", s.Priority, s.Weight, s.Port, s.Target)
}

func (s *RDataSRV) encode(ctx *context) error {
	if err := binary.Write(ctx, binary.BigEndian, s.Priority); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, s.Weight); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, s.Port); err != nil {
		return err
	}
	return ctx.appendLabel(s.Target)
}

func (s *RDataSRV) decode(ctx *context, d []byte) error {
	if len(d) < 7 {
		return ErrInvalidLen
	}
	s.Priority = binary.BigEndian.Uint16(d[0:2])
	s.Weight = binary.BigEndian.Uint16(d[2:4])
	s.Port = binary.BigEndian.Uint16(d[4:6])
	target, _, err := ctx.readLabel(d[6:])
	if err != nil {
		return err
	}
	s.Target = target
	return nil
}

// TLSA certificate usage values (RFC 6698)
type TLSACertUsage uint8

const (
	TLSAUsageCAConstraint     TLSACertUsage = 0 // PKIX-TA
	TLSAUsageServiceCert      TLSACertUsage = 1 // PKIX-EE
	TLSAUsageTrustAnchor      TLSACertUsage = 2 // DANE-TA
	TLSAUsageDomainIssuedCert TLSACertUsage = 3 // DANE-EE
)

// TLSA selector values (RFC 6698)
type TLSASelector uint8

const (
	TLSASelectorFullCert TLSASelector = 0 // Full certificate
	TLSASelectorSPKI     TLSASelector = 1 // SubjectPublicKeyInfo
)

// TLSA matching type values (RFC 6698)
type TLSAMatchingType uint8

const (
	TLSAMatchFull   TLSAMatchingType = 0 // Exact match
	TLSAMatchSHA256 TLSAMatchingType = 1 // SHA-256 hash
	TLSAMatchSHA512 TLSAMatchingType = 2 // SHA-512 hash
)

// RDataTLSA represents a TLSA resource record (RFC 6698).
// TLSA records are used for DANE (DNS-based Authentication of Named Entities).
type RDataTLSA struct {
	Usage        TLSACertUsage    // Certificate usage
	Selector     TLSASelector     // Selector
	MatchingType TLSAMatchingType // Matching type
	CertData     []byte           // Certificate association data
}

func (t *RDataTLSA) GetType() Type { return TLSA }

func (t *RDataTLSA) String() string {
	return fmt.Sprintf("%d %d %d %s", t.Usage, t.Selector, t.MatchingType,
		strings.ToUpper(hex.EncodeToString(t.CertData)))
}

func (t *RDataTLSA) encode(ctx *context) error {
	if _, err := ctx.Write([]byte{byte(t.Usage), byte(t.Selector), byte(t.MatchingType)}); err != nil {
		return err
	}
	_, err := ctx.Write(t.CertData)
	return err
}

func (t *RDataTLSA) decode(ctx *context, d []byte) error {
	if len(d) < 3 {
		return ErrInvalidLen
	}
	t.Usage = TLSACertUsage(d[0])
	t.Selector = TLSASelector(d[1])
	t.MatchingType = TLSAMatchingType(d[2])
	t.CertData = make([]byte, len(d)-3)
	copy(t.CertData, d[3:])
	return nil
}

// SSHFP algorithm values (RFC 4255, RFC 6594, RFC 7479)
type SSHFPAlgorithm uint8

const (
	SSHFPAlgRSA     SSHFPAlgorithm = 1 // RSA
	SSHFPAlgDSA     SSHFPAlgorithm = 2 // DSA
	SSHFPAlgECDSA   SSHFPAlgorithm = 3 // ECDSA
	SSHFPAlgEd25519 SSHFPAlgorithm = 4 // Ed25519
	SSHFPAlgEd448   SSHFPAlgorithm = 6 // Ed448
)

// SSHFP fingerprint type values
type SSHFPType uint8

const (
	SSHFPTypeSHA1   SSHFPType = 1 // SHA-1
	SSHFPTypeSHA256 SSHFPType = 2 // SHA-256
)

// RDataSSHFP represents an SSHFP resource record (RFC 4255).
// SSHFP records store SSH public key fingerprints for host verification.
type RDataSSHFP struct {
	Algorithm   SSHFPAlgorithm // Public key algorithm
	FPType      SSHFPType      // Fingerprint type
	Fingerprint []byte         // Fingerprint data
}

func (s *RDataSSHFP) GetType() Type { return SSHFP }

func (s *RDataSSHFP) String() string {
	return fmt.Sprintf("%d %d %s", s.Algorithm, s.FPType,
		strings.ToUpper(hex.EncodeToString(s.Fingerprint)))
}

func (s *RDataSSHFP) encode(ctx *context) error {
	if _, err := ctx.Write([]byte{byte(s.Algorithm), byte(s.FPType)}); err != nil {
		return err
	}
	_, err := ctx.Write(s.Fingerprint)
	return err
}

func (s *RDataSSHFP) decode(ctx *context, d []byte) error {
	if len(d) < 2 {
		return ErrInvalidLen
	}
	s.Algorithm = SSHFPAlgorithm(d[0])
	s.FPType = SSHFPType(d[1])
	s.Fingerprint = make([]byte, len(d)-2)
	copy(s.Fingerprint, d[2:])
	return nil
}

// RDataCAA represents a CAA resource record (RFC 8659).
// CAA records specify which CAs are authorized to issue certificates.
type RDataCAA struct {
	Flags uint8  // Flags (bit 0 = critical)
	Tag   string // Property tag (e.g., "issue", "issuewild", "iodef")
	Value string // Property value
}

func (c *RDataCAA) GetType() Type { return CAA }

func (c *RDataCAA) String() string {
	return fmt.Sprintf("%d %s \"%s\"", c.Flags, c.Tag, c.Value)
}

func (c *RDataCAA) encode(ctx *context) error {
	if _, err := ctx.Write([]byte{c.Flags, byte(len(c.Tag))}); err != nil {
		return err
	}
	if _, err := ctx.Write([]byte(c.Tag)); err != nil {
		return err
	}
	_, err := ctx.Write([]byte(c.Value))
	return err
}

func (c *RDataCAA) decode(ctx *context, d []byte) error {
	if len(d) < 2 {
		return ErrInvalidLen
	}
	c.Flags = d[0]
	tagLen := int(d[1])
	if len(d) < 2+tagLen {
		return ErrInvalidLen
	}
	c.Tag = string(d[2 : 2+tagLen])
	c.Value = string(d[2+tagLen:])
	return nil
}

// IsCritical returns true if the critical flag is set.
func (c *RDataCAA) IsCritical() bool {
	return c.Flags&0x80 != 0
}

// RDataURI represents a URI resource record (RFC 7553).
// URI records publish mappings from hostnames to URIs.
type RDataURI struct {
	Priority uint16 // Priority (lower is preferred)
	Weight   uint16 // Weight for load balancing
	Target   string // Target URI
}

func (u *RDataURI) GetType() Type { return URI }

func (u *RDataURI) String() string {
	return fmt.Sprintf("%d %d \"%s\"", u.Priority, u.Weight, u.Target)
}

func (u *RDataURI) encode(ctx *context) error {
	if err := binary.Write(ctx, binary.BigEndian, u.Priority); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, u.Weight); err != nil {
		return err
	}
	_, err := ctx.Write([]byte(u.Target))
	return err
}

func (u *RDataURI) decode(ctx *context, d []byte) error {
	if len(d) < 4 {
		return ErrInvalidLen
	}
	u.Priority = binary.BigEndian.Uint16(d[0:2])
	u.Weight = binary.BigEndian.Uint16(d[2:4])
	u.Target = string(d[4:])
	return nil
}

// RDataNAPTR represents a NAPTR resource record (RFC 3403).
// NAPTR records are used for DDDS (Dynamic Delegation Discovery System) applications.
type RDataNAPTR struct {
	Order       uint16 // Order (processed first)
	Preference  uint16 // Preference (for equal order)
	Flags       string // Flags (e.g., "u", "s", "a", "p")
	Service     string // Service parameters
	Regexp      string // Substitution expression
	Replacement string // Replacement domain name
}

func (n *RDataNAPTR) GetType() Type { return NAPTR }

func (n *RDataNAPTR) String() string {
	return fmt.Sprintf("%d %d \"%s\" \"%s\" \"%s\" %s",
		n.Order, n.Preference, n.Flags, n.Service, n.Regexp, n.Replacement)
}

func (n *RDataNAPTR) encode(ctx *context) error {
	if err := binary.Write(ctx, binary.BigEndian, n.Order); err != nil {
		return err
	}
	if err := binary.Write(ctx, binary.BigEndian, n.Preference); err != nil {
		return err
	}
	// Character strings (length-prefixed)
	if err := writeCharString(ctx, n.Flags); err != nil {
		return err
	}
	if err := writeCharString(ctx, n.Service); err != nil {
		return err
	}
	if err := writeCharString(ctx, n.Regexp); err != nil {
		return err
	}
	return ctx.appendLabel(n.Replacement)
}

func (n *RDataNAPTR) decode(ctx *context, d []byte) error {
	if len(d) < 4 {
		return ErrInvalidLen
	}
	n.Order = binary.BigEndian.Uint16(d[0:2])
	n.Preference = binary.BigEndian.Uint16(d[2:4])
	d = d[4:]

	// Read character strings
	flags, read, err := readCharString(d)
	if err != nil {
		return err
	}
	n.Flags = flags
	d = d[read:]

	service, read, err := readCharString(d)
	if err != nil {
		return err
	}
	n.Service = service
	d = d[read:]

	regexp, read, err := readCharString(d)
	if err != nil {
		return err
	}
	n.Regexp = regexp
	d = d[read:]

	replacement, _, err := ctx.readLabel(d)
	if err != nil {
		return err
	}
	n.Replacement = replacement
	return nil
}

// RDataHINFO represents an HINFO resource record (RFC 1035).
// HINFO records specify the CPU and OS type of a host.
type RDataHINFO struct {
	CPU string // CPU type
	OS  string // Operating system
}

func (h *RDataHINFO) GetType() Type { return HINFO }

func (h *RDataHINFO) String() string {
	return fmt.Sprintf("\"%s\" \"%s\"", h.CPU, h.OS)
}

func (h *RDataHINFO) encode(ctx *context) error {
	if err := writeCharString(ctx, h.CPU); err != nil {
		return err
	}
	return writeCharString(ctx, h.OS)
}

func (h *RDataHINFO) decode(ctx *context, d []byte) error {
	cpu, read, err := readCharString(d)
	if err != nil {
		return err
	}
	h.CPU = cpu
	d = d[read:]

	os, _, err := readCharString(d)
	if err != nil {
		return err
	}
	h.OS = os
	return nil
}

// RDataRP represents an RP (Responsible Person) resource record (RFC 1183).
// RP records specify the responsible person for a domain.
type RDataRP struct {
	Mbox string // Mailbox of responsible person
	Txt  string // Domain name for TXT record with additional info
}

func (r *RDataRP) GetType() Type { return RP }

func (r *RDataRP) String() string {
	return fmt.Sprintf("%s %s", r.Mbox, r.Txt)
}

func (r *RDataRP) encode(ctx *context) error {
	if err := ctx.appendLabel(r.Mbox); err != nil {
		return err
	}
	return ctx.appendLabel(r.Txt)
}

func (r *RDataRP) decode(ctx *context, d []byte) error {
	mbox, n, err := ctx.readLabel(d)
	if err != nil {
		return err
	}
	r.Mbox = mbox
	d = d[n:]

	txt, _, err := ctx.readLabel(d)
	if err != nil {
		return err
	}
	r.Txt = txt
	return nil
}

// RDataAFSDB represents an AFSDB resource record (RFC 1183).
// AFSDB records locate AFS cell database servers or DCE/NCA cell name servers.
type RDataAFSDB struct {
	Subtype  uint16 // Subtype (1=AFS, 2=DCE)
	Hostname string // Server hostname
}

func (a *RDataAFSDB) GetType() Type { return AFSDB }

func (a *RDataAFSDB) String() string {
	return fmt.Sprintf("%d %s", a.Subtype, a.Hostname)
}

func (a *RDataAFSDB) encode(ctx *context) error {
	if err := binary.Write(ctx, binary.BigEndian, a.Subtype); err != nil {
		return err
	}
	return ctx.appendLabel(a.Hostname)
}

func (a *RDataAFSDB) decode(ctx *context, d []byte) error {
	if len(d) < 3 {
		return ErrInvalidLen
	}
	a.Subtype = binary.BigEndian.Uint16(d[0:2])
	hostname, _, err := ctx.readLabel(d[2:])
	if err != nil {
		return err
	}
	a.Hostname = hostname
	return nil
}

// Helper functions for character strings

// writeCharString writes a DNS character string (length-prefixed, max 255 bytes).
func writeCharString(ctx *context, s string) error {
	if len(s) > 255 {
		return ErrInvalidLen
	}
	if _, err := ctx.Write([]byte{byte(len(s))}); err != nil {
		return err
	}
	_, err := ctx.Write([]byte(s))
	return err
}

// readCharString reads a DNS character string from the given data.
// Returns the string, bytes read, and any error.
func readCharString(d []byte) (string, int, error) {
	if len(d) < 1 {
		return "", 0, ErrInvalidLen
	}
	strLen := int(d[0])
	if len(d) < 1+strLen {
		return "", 0, ErrInvalidLen
	}
	return string(d[1 : 1+strLen]), 1 + strLen, nil
}
