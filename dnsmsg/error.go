package dnsmsg

import "errors"

var (
	ErrInvalidLen   = errors.New("invalid data length")
	ErrNotSupport   = errors.New("not supported")
	ErrNameTooLong  = errors.New("name is too long")
	ErrLabelTooLong = errors.New("label is too long")
	ErrInvalidLabel = errors.New("invalid label")
)
