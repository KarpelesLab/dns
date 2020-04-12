package dnsmsg

type Type byte

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

	// QTYPES
	AXFR   Type = 252
	MAILB  Type = 253
	MAILA  Type = 254
	ALLREC Type = 255 // "*"
)
