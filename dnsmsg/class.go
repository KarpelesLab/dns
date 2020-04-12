package dnsmsg

type Class uint16

const (
	// RFC 1035
	IN Class = 1
	CS Class = 2
	CH Class = 3
	HS Class = 4
)
