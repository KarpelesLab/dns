package dnsmsg

import "errors"

// Errors returned during DNS message parsing and encoding.
var (
	// ErrInvalidLen is returned when record data has an invalid length.
	ErrInvalidLen = errors.New("invalid data length")
	// ErrNotSupport is returned when a record type is not supported for parsing or encoding.
	ErrNotSupport = errors.New("not supported")
	// ErrNameTooLong is returned when a domain name exceeds 255 characters (RFC 1035 limit).
	ErrNameTooLong = errors.New("name is too long")
	// ErrLabelTooLong is returned when a single label exceeds 63 characters (RFC 1035 limit).
	ErrLabelTooLong = errors.New("label is too long")
	// ErrLabelInvalid is returned when a label is malformed (e.g., compression pointer loop).
	ErrLabelInvalid = errors.New("label is invalid")
)
