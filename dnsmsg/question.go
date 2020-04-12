package dnsmsg

type Question struct {
	Name  string
	Type  Type
	Class Class
}
