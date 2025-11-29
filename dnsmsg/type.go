package dnsmsg

//go:generate stringer -type=Type

// Type represents a DNS resource record type as defined in RFC 1035 and subsequent RFCs.
// Common types include A (IPv4 address), AAAA (IPv6 address), MX (mail exchange),
// NS (nameserver), CNAME (canonical name), TXT (text), and SOA (start of authority).
type Type uint16

const (
	// RFC 1035
	A     Type = 1
	NS    Type = 2
	MD    Type = 3
	MF    Type = 4
	CNAME Type = 5
	SOA   Type = 6
	MB    Type = 7
	MG    Type = 8
	MR    Type = 9
	NULL  Type = 10
	WKS   Type = 11
	PTR   Type = 12
	HINFO Type = 13
	MINFO Type = 14
	MX    Type = 15
	TXT   Type = 16

	// RFC 1183
	RP    Type = 17
	AFSDB Type = 18

	// RFC 2535 - DNSSEC
	SIG Type = 24
	KEY Type = 25

	AAAA    Type = 28 // RFC 3596 - IPv6
	LOC     Type = 29 // RFC 1876
	SRV     Type = 33 // RFC 2782
	NAPTR   Type = 35 // RFC 3403
	KX      Type = 36 // RFC 2230
	CERT    Type = 37 // RFC 4398
	DNAME   Type = 39 // RFC 6672
	OPT     Type = 41 // RFC 6891 (not a type per se)
	APL     Type = 42 // RFC 3123
	DS      Type = 43 // RFC 4034 (DNSSEC related)
	SSHFP   Type = 44 // RFC 4255
	PSECKEY Type = 45 // RFC 4025
	// RFC 4034 (DNSSEC)
	RRSIG  Type = 46
	NSEC   Type = 47
	DNSKEY Type = 48

	DHCID      Type = 49 // RFC 4701
	NSEC3      Type = 50 // RFC 5155
	NSEC3PARAM Type = 51 // RFC 5155
	TLSA       Type = 52 // RFC 6698
	SMIMEA     Type = 53 // RFC 8162
	HIP        Type = 55 // RFC 8005
	CDS        Type = 59 // RFC 7344
	CDNSKEY    Type = 60 // RFC 7344
	OPENPGPKEY Type = 61 // RFC 7929
	CSYNC      Type = 62 // RFC 7477
	ZONEMD     Type = 63 // TBA (draft)

	TKEY Type = 249 // RFC 2930
	TSIG Type = 250 // RFC 7553
	IXFR Type = 251 // RFC 1996

	// QTYPES from RFC 1035
	AXFR  Type = 252
	MAILB Type = 253
	MAILA Type = 254
	ANY   Type = 255 // "*"

	URI Type = 256   // RFC 7553
	CAA Type = 257   // RFC 6844
	TA  Type = 32768 // DNSSEC Trust Authorities
	DLV Type = 32769 // RFC 4431
)

// StringToType maps string type names to Type values
var StringToType = map[string]Type{
	"A":          A,
	"NS":         NS,
	"MD":         MD,
	"MF":         MF,
	"CNAME":      CNAME,
	"SOA":        SOA,
	"MB":         MB,
	"MG":         MG,
	"MR":         MR,
	"NULL":       NULL,
	"WKS":        WKS,
	"PTR":        PTR,
	"HINFO":      HINFO,
	"MINFO":      MINFO,
	"MX":         MX,
	"TXT":        TXT,
	"RP":         RP,
	"AFSDB":      AFSDB,
	"SIG":        SIG,
	"KEY":        KEY,
	"AAAA":       AAAA,
	"LOC":        LOC,
	"SRV":        SRV,
	"NAPTR":      NAPTR,
	"KX":         KX,
	"CERT":       CERT,
	"DNAME":      DNAME,
	"OPT":        OPT,
	"APL":        APL,
	"DS":         DS,
	"SSHFP":      SSHFP,
	"PSECKEY":    PSECKEY,
	"RRSIG":      RRSIG,
	"NSEC":       NSEC,
	"DNSKEY":     DNSKEY,
	"DHCID":      DHCID,
	"NSEC3":      NSEC3,
	"NSEC3PARAM": NSEC3PARAM,
	"TLSA":       TLSA,
	"SMIMEA":     SMIMEA,
	"HIP":        HIP,
	"CDS":        CDS,
	"CDNSKEY":    CDNSKEY,
	"OPENPGPKEY": OPENPGPKEY,
	"CSYNC":      CSYNC,
	"ZONEMD":     ZONEMD,
	"TKEY":       TKEY,
	"TSIG":       TSIG,
	"IXFR":       IXFR,
	"AXFR":       AXFR,
	"MAILB":      MAILB,
	"MAILA":      MAILA,
	"ANY":        ANY,
	"URI":        URI,
	"CAA":        CAA,
	"TA":         TA,
	"DLV":        DLV,
}
