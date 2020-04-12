package dnsmsg

type Resource struct {
	Name  string
	Type  Type
	Class Class
	TTL   uint32

	Data RData
}
