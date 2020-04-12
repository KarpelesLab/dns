package dnsmsg

type Message struct {
	// Header
	ID   uint16
	Bits HeaderBits

	// Question (QD)
	// Answer (AN)
	// Authority (NS)
	// Additional (AR)
}
