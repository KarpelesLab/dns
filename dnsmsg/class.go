package dnsmsg

//go:generate stringer -type=Class

// Class represents a DNS class as defined in RFC 1035.
// The most common class is IN (Internet). Other classes like CH (Chaos)
// and HS (Hesiod) are rarely used in practice.
type Class uint16

const (
	// RFC 1035
	IN Class = 1 // INternet
	CS Class = 2 // Unassigned
	CH Class = 3 // CHaos
	HS Class = 4 // Hesiod
)
