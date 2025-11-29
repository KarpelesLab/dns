package dnssec

import (
	"bytes"
	"encoding/binary"
	"sort"
	"strings"

	"github.com/KarpelesLab/dns/dnsmsg"
)

// CanonicalName converts a domain name to canonical (lowercase) wire format
// as specified in RFC 4034 Section 6.1.
func CanonicalName(name string) []byte {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	var buf bytes.Buffer
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0) // Root label
	return buf.Bytes()
}

// CanonicalRRset sorts an RRset in canonical order as specified in RFC 4034 Section 6.3.
// Records are sorted by their RDATA in canonical wire format.
func CanonicalRRset(rrset []*dnsmsg.Resource) []*dnsmsg.Resource {
	if len(rrset) <= 1 {
		return rrset
	}

	// Make a copy to avoid modifying the original
	sorted := make([]*dnsmsg.Resource, len(rrset))
	copy(sorted, rrset)

	sort.Slice(sorted, func(i, j int) bool {
		// Compare RDATA in wire format
		rdataI := encodeRData(sorted[i])
		rdataJ := encodeRData(sorted[j])
		return bytes.Compare(rdataI, rdataJ) < 0
	})

	return sorted
}

// encodeRData encodes the RDATA of a resource record to wire format.
func encodeRData(rr *dnsmsg.Resource) []byte {
	if rr.Data == nil {
		return nil
	}

	// Create a minimal message to encode the resource
	msg := dnsmsg.New()
	msg.Answer = []*dnsmsg.Resource{rr}

	data, err := msg.MarshalBinary()
	if err != nil {
		return nil
	}

	// The RDATA is at the end of the message after the header and question
	// This is a simplified extraction - for proper implementation we'd need
	// direct access to the encode method
	return data
}

// BuildSignedData constructs the data to be signed/verified for an RRSIG
// as specified in RFC 4034 Section 3.1.8.1.
func BuildSignedData(rrsig *dnsmsg.RDataRRSIG, rrset []*dnsmsg.Resource) ([]byte, error) {
	var buf bytes.Buffer

	// RRSIG RDATA (without signature)
	// Type Covered (2) + Algorithm (1) + Labels (1) + Original TTL (4) +
	// Signature Expiration (4) + Signature Inception (4) + Key Tag (2) + Signer's Name
	binary.Write(&buf, binary.BigEndian, uint16(rrsig.TypeCovered))
	buf.WriteByte(byte(rrsig.Algorithm))
	buf.WriteByte(rrsig.Labels)
	binary.Write(&buf, binary.BigEndian, rrsig.OrigTTL)
	binary.Write(&buf, binary.BigEndian, rrsig.Expiration)
	binary.Write(&buf, binary.BigEndian, rrsig.Inception)
	binary.Write(&buf, binary.BigEndian, rrsig.KeyTag)
	buf.Write(CanonicalName(rrsig.SignerName))

	// RRset in canonical order
	sortedRRset := CanonicalRRset(rrset)
	for _, rr := range sortedRRset {
		// owner name | type | class | TTL | RDLENGTH | RDATA
		buf.Write(CanonicalName(rr.Name))
		binary.Write(&buf, binary.BigEndian, uint16(rr.Type))
		binary.Write(&buf, binary.BigEndian, uint16(rr.Class))
		binary.Write(&buf, binary.BigEndian, rrsig.OrigTTL) // Use original TTL from RRSIG

		// Encode RDATA
		rdata := encodeRDataDirect(rr)
		binary.Write(&buf, binary.BigEndian, uint16(len(rdata)))
		buf.Write(rdata)
	}

	return buf.Bytes(), nil
}

// encodeRDataDirect encodes just the RDATA portion of a resource record.
func encodeRDataDirect(rr *dnsmsg.Resource) []byte {
	if rr.Data == nil {
		return nil
	}

	// For records containing domain names, we need canonical encoding
	switch data := rr.Data.(type) {
	case *dnsmsg.RDataIP:
		return []byte(data.IP)
	case dnsmsg.RDataTXT:
		// TXT records are character strings
		txt := string(data)
		var buf bytes.Buffer
		for len(txt) > 0 {
			chunk := txt
			if len(chunk) > 255 {
				chunk = chunk[:255]
			}
			buf.WriteByte(byte(len(chunk)))
			buf.WriteString(chunk)
			txt = txt[len(chunk):]
		}
		return buf.Bytes()
	case *dnsmsg.RDataMX:
		var buf bytes.Buffer
		binary.Write(&buf, binary.BigEndian, data.Pref)
		buf.Write(CanonicalName(data.Server))
		return buf.Bytes()
	case *dnsmsg.RDataSOA:
		var buf bytes.Buffer
		buf.Write(CanonicalName(data.MName))
		buf.Write(CanonicalName(data.RName))
		binary.Write(&buf, binary.BigEndian, data.Serial)
		binary.Write(&buf, binary.BigEndian, data.Refresh)
		binary.Write(&buf, binary.BigEndian, data.Retry)
		binary.Write(&buf, binary.BigEndian, data.Expire)
		binary.Write(&buf, binary.BigEndian, data.Minimum)
		return buf.Bytes()
	case *dnsmsg.RDataLabel:
		return CanonicalName(data.Label)
	case *dnsmsg.RDataDNSKEY:
		var buf bytes.Buffer
		binary.Write(&buf, binary.BigEndian, data.Flags)
		buf.WriteByte(data.Protocol)
		buf.WriteByte(byte(data.Algorithm))
		buf.Write(data.PublicKey)
		return buf.Bytes()
	case *dnsmsg.RDataDS:
		var buf bytes.Buffer
		binary.Write(&buf, binary.BigEndian, data.KeyTag)
		buf.WriteByte(byte(data.Algorithm))
		buf.WriteByte(byte(data.DigestType))
		buf.Write(data.Digest)
		return buf.Bytes()
	default:
		// Fallback: try to marshal through the message system
		msg := dnsmsg.New()
		msg.Answer = []*dnsmsg.Resource{rr}
		if encoded, err := msg.MarshalBinary(); err == nil && len(encoded) > 12 {
			// Skip header (12 bytes) and find the RDATA
			// This is a rough approximation
			return encoded[12:]
		}
		return nil
	}
}

// CountLabels returns the number of labels in a domain name,
// excluding the root label.
func CountLabels(name string) uint8 {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return 0
	}
	return uint8(strings.Count(name, ".") + 1)
}
