package dnsmsg

type RDataTXT string

func (txt RDataTXT) GetType() Type {
	return TXT
}

func (txt RDataTXT) String() string {
	return string(txt)
}

func (txt RDataTXT) encode(c *context) error {
	_, err := c.Write([]byte(txt))
	return err
}
