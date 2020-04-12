package dnsmsg

type ResourceData interface {
	// TODO
}

type Resource struct {
	Name  string
	Type  Type
	Class Class
	TTL   uint32

	Data ResourceData
}
