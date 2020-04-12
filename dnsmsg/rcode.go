package dnsmsg

type RCode byte

const (
	// RFC 1035
	OK          RCode = 0
	ErrFormat   RCode = 1
	ErrServFail RCode = 2
	ErrName     RCode = 3
	ErrNotImpl  RCode = 4
	ErrRefused  RCode = 5
)

func (rc RCode) Error() string {
	switch rc {
	// RFC 1035
	case OK:
		return "no error"
	case ErrFormat:
		return "unable to interpret the query"
	case ErrServFail:
		return "problem with the name server"
	case ErrName:
		return "domain name does not exist"
	case ErrNotImpl:
		return "query is not supported"
	case ErrRefused:
		return "operation refused"
	default:
		return "unknown error"
	}
}
