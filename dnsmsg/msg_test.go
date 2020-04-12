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

	hexB = "236f8180000100010000000106676f6f676c6503636f6d0000010001c00c00010001000000cd0004acd9af6e0000290200000000000000"
	b, _ = hex.DecodeString(hexB)

	// parse
	msg, err = Parse(b)
	if err != nil {
		t.Errorf("failed to parse: %s", err)
	}

	if msg.String() != "ID: 9071 Query qr rd ra NOERROR QD: google.com. IN A AN: google.com. IN A 205 172.217.175.110 ReqUDPSize=512" {
		t.Errorf("failed to parse simple response, got %s", msg.String())
	}

	log.Printf("parsed: %s", msg.String())
}
