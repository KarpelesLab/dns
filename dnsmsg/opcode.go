package dnsmsg

type OpCode byte

const (
	// RFC 1035
	Query  OpCode = 0
	IQuery OpCode = 1
	Status OpCode = 2
)
