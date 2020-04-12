package dnsmsg

type Message struct {
	// Header
	ID   uint16
	Bits HeaderBits

	Question   []*Question // QD
	Answer     []*Resource // AN
	Authority  []*Resource // NS
	Additional []*Resource // AR
}
