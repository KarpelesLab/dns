package dnsmsg

type RCode byte

const (
	// RFC 1035
	NoError     RCode = 0
	ErrFormat   RCode = 1
	ErrServFail RCode = 2
	ErrName     RCode = 3
	ErrNotImpl  RCode = 4
	ErrRefused  RCode = 5
)

func (rc RCode) Error() string {
	switch rc {
	// RFC 1035
	case NoError:
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

func (rc RCode) String() string {
	// TODO check these
	switch rc {
	case NoError:
		return "NOERROR"
	case ErrFormat:
		return "FORMERR"
	case ErrServFail:
		return "SERVFAIL"
	case ErrName:
		return "NXDOMAIN"
	case ErrNotImpl:
		return "NOTIMP"
	case ErrRefused:
		return "REFUSED"
	default:
		return "unknown error"
	}
}
