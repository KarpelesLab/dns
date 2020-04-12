package dnsmsg

//go:generate stringer -type=OpCode

type OpCode byte

const (
	// RFC 1035
	Query  OpCode = 0
	IQuery OpCode = 1
	Status OpCode = 2
)
