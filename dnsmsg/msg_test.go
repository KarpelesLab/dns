package dnsmsg

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestParse(t *testing.T) {
	hexB := "236f0120000100000000000106676f6f676c6503636f6d0000010001000029100000000000000c000a0008773d66c995247430"
	b, _ := hex.DecodeString(hexB)

	// parse
	msg, err := Parse(b)
	if err != nil {
		t.Errorf("failed to parse: %s", err)
	}

	if msg.String() != "ID: 9071 Query rd NOERROR QD: google.com. IN A ReqUDPSize=4096" {
		t.Errorf("failed to parse simple, got %s", msg.String())
	}

	log.Printf("parsed: %s", msg.String())
}
