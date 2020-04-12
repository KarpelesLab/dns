package dnsmsg

type Message struct {
	// Header
	ID   uint16
	Bits HeaderBits

	// Question
	// Answer
	// Authority
	// Additional
}
