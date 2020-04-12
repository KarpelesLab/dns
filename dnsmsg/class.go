package dnsmsg

//go:generate stringer -type=Class

type Class uint16

const (
	// RFC 1035
	IN Class = 1 // INternet
	CS Class = 2 // Unassigned
	CH Class = 3 // CHaos
	HS Class = 4 // Hesiod
)
