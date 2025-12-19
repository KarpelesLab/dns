package dnsmsg

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

func TestParseQuery(t *testing.T) {
	hexB := "236f0120000100000000000106676f6f676c6503636f6d0000010001000029100000000000000c000a0008773d66c995247430"
	b, _ := hex.DecodeString(hexB)

	msg, err := Parse(b)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	expected := "ID: 9071 Query rd NOERROR QD: google.com. IN A ReqUDPSize=4096 OPT(code=10)"
	if msg.String() != expected {
		t.Errorf("unexpected result\ngot:  %s\nwant: %s", msg.String(), expected)
	}
}

func TestParseResponse(t *testing.T) {
	hexB := "236f8180000100010000000106676f6f676c6503636f6d0000010001c00c00010001000000cd0004acd9af6e0000290200000000000000"
	b, _ := hex.DecodeString(hexB)

	msg, err := Parse(b)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	expected := "ID: 9071 Query qr rd ra NOERROR QD: google.com. IN A AN: google.com. IN A 205 172.217.175.110 ReqUDPSize=512"
	if msg.String() != expected {
		t.Errorf("unexpected result\ngot:  %s\nwant: %s", msg.String(), expected)
	}
}

func TestRoundTrip(t *testing.T) {
	// Test that marshaling and parsing produces the same result
	original := New()
	original.ID = 12345
	original.Bits = hQResp | hRecD | hRecA
	original.Question = []*Question{
		{Name: "example.com.", Type: A, Class: IN},
	}
	original.Answer = []*Resource{
		{Name: "example.com.", Type: A, Class: IN, TTL: 300, Data: &RDataIP{IP: net.ParseIP("192.168.1.1").To4(), Type: A}},
	}

	// Marshal
	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal: %s", err)
	}

	// Parse back
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	// Compare
	if original.ID != parsed.ID {
		t.Errorf("ID mismatch: got %d, want %d", parsed.ID, original.ID)
	}
	if original.Bits != parsed.Bits {
		t.Errorf("Bits mismatch: got %v, want %v", parsed.Bits, original.Bits)
	}
	if len(parsed.Question) != 1 {
		t.Fatalf("expected 1 question, got %d", len(parsed.Question))
	}
	if parsed.Question[0].Name != "example.com." {
		t.Errorf("question name mismatch: got %s", parsed.Question[0].Name)
	}
	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}
	if parsed.Answer[0].Data.String() != "192.168.1.1" {
		t.Errorf("answer data mismatch: got %s", parsed.Answer[0].Data.String())
	}
}

func TestRecordTypeA(t *testing.T) {
	// A record with IP 93.184.216.34
	hexB := "00008180000100010000000007657861" +
		"6d706c6503636f6d0000010001c00c00" +
		"010001000000960004b9e8d822"
	b, _ := hex.DecodeString(hexB)

	msg, err := Parse(b)
	if err != nil {
		t.Fatalf("failed to parse A record: %s", err)
	}

	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}

	ans := msg.Answer[0]
	if ans.Type != A {
		t.Errorf("expected A type, got %s", ans.Type)
	}

	ip, ok := ans.Data.(*RDataIP)
	if !ok {
		t.Fatalf("expected RDataIP, got %T", ans.Data)
	}

	expectedIP := net.ParseIP("185.232.216.34").To4()
	if !bytes.Equal(ip.IP, expectedIP) {
		t.Errorf("IP mismatch: got %s, want %s", ip.IP, expectedIP)
	}
}

func TestRecordTypeAAAA(t *testing.T) {
	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "example.com.",
			Type:  AAAA,
			Class: IN,
			TTL:   300,
			Data:  &RDataIP{IP: net.ParseIP("2001:db8::1"), Type: AAAA},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal AAAA: %s", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse AAAA: %s", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	ip, ok := parsed.Answer[0].Data.(*RDataIP)
	if !ok {
		t.Fatalf("expected RDataIP, got %T", parsed.Answer[0].Data)
	}

	expectedIP := net.ParseIP("2001:db8::1")
	if !ip.IP.Equal(expectedIP) {
		t.Errorf("IPv6 mismatch: got %s, want %s", ip.IP, expectedIP)
	}
}

func TestRecordTypeMX(t *testing.T) {
	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "example.com.",
			Type:  MX,
			Class: IN,
			TTL:   3600,
			Data:  &RDataMX{Pref: 10, Server: "mail.example.com."},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal MX: %s", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse MX: %s", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	mx, ok := parsed.Answer[0].Data.(*RDataMX)
	if !ok {
		t.Fatalf("expected RDataMX, got %T", parsed.Answer[0].Data)
	}

	if mx.Pref != 10 {
		t.Errorf("MX preference mismatch: got %d, want 10", mx.Pref)
	}
	if mx.Server != "mail.example.com." {
		t.Errorf("MX server mismatch: got %s", mx.Server)
	}
}

func TestRecordTypeSOA(t *testing.T) {
	msg := New()
	msg.Authority = []*Resource{
		{
			Name:  "example.com.",
			Type:  SOA,
			Class: IN,
			TTL:   86400,
			Data: &RDataSOA{
				MName:   "ns1.example.com.",
				RName:   "admin.example.com.",
				Serial:  2024010101,
				Refresh: 3600,
				Retry:   600,
				Expire:  604800,
				Minimum: 60,
			},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal SOA: %s", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse SOA: %s", err)
	}

	if len(parsed.Authority) != 1 {
		t.Fatalf("expected 1 authority, got %d", len(parsed.Authority))
	}

	soa, ok := parsed.Authority[0].Data.(*RDataSOA)
	if !ok {
		t.Fatalf("expected RDataSOA, got %T", parsed.Authority[0].Data)
	}

	if soa.MName != "ns1.example.com." {
		t.Errorf("SOA MName mismatch: got %s", soa.MName)
	}
	if soa.RName != "admin.example.com." {
		t.Errorf("SOA RName mismatch: got %s", soa.RName)
	}
	if soa.Serial != 2024010101 {
		t.Errorf("SOA Serial mismatch: got %d", soa.Serial)
	}
	if soa.Refresh != 3600 {
		t.Errorf("SOA Refresh mismatch: got %d", soa.Refresh)
	}
	if soa.Retry != 600 {
		t.Errorf("SOA Retry mismatch: got %d", soa.Retry)
	}
	if soa.Expire != 604800 {
		t.Errorf("SOA Expire mismatch: got %d", soa.Expire)
	}
	if soa.Minimum != 60 {
		t.Errorf("SOA Minimum mismatch: got %d", soa.Minimum)
	}
}

func TestRecordTypeTXT(t *testing.T) {
	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "example.com.",
			Type:  TXT,
			Class: IN,
			TTL:   300,
			Data:  RDataTXT("v=spf1 include:_spf.example.com ~all"),
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal TXT: %s", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse TXT: %s", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	txt, ok := parsed.Answer[0].Data.(RDataTXT)
	if !ok {
		t.Fatalf("expected RDataTXT, got %T", parsed.Answer[0].Data)
	}

	expected := "v=spf1 include:_spf.example.com ~all"
	if string(txt) != expected {
		t.Errorf("TXT mismatch: got %s, want %s", string(txt), expected)
	}
}

func TestRecordTypeTXTLong(t *testing.T) {
	// Test TXT record longer than 255 bytes (requires multiple character-strings)
	longText := ""
	for i := 0; i < 300; i++ {
		longText += "a"
	}

	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "example.com.",
			Type:  TXT,
			Class: IN,
			TTL:   300,
			Data:  RDataTXT(longText),
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal long TXT: %s", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse long TXT: %s", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	txt, ok := parsed.Answer[0].Data.(RDataTXT)
	if !ok {
		t.Fatalf("expected RDataTXT, got %T", parsed.Answer[0].Data)
	}

	if string(txt) != longText {
		t.Errorf("long TXT mismatch: got length %d, want %d", len(txt), len(longText))
	}
}

func TestRecordTypeTXTMultiString(t *testing.T) {
	// Test parsing TXT from multiple quoted strings (like DKIM records)
	input := `"v=DKIM1; k=rsa; p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArbq1" "uYX1GIK3Gk9HNQ8RTVfbV2k6BH0hW9TtbF/EULE2qXkVuuX/h6DNxo"`
	expected := "v=DKIM1; k=rsa; p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArbq1uYX1GIK3Gk9HNQ8RTVfbV2k6BH0hW9TtbF/EULE2qXkVuuX/h6DNxo"

	rdata, err := RDataFromString(TXT, input)
	if err != nil {
		t.Fatalf("failed to parse multi-string TXT: %s", err)
	}

	txt, ok := rdata.(RDataTXT)
	if !ok {
		t.Fatalf("expected RDataTXT, got %T", rdata)
	}

	if string(txt) != expected {
		t.Errorf("TXT mismatch:\ngot:  %s\nwant: %s", string(txt), expected)
	}

	// Test round-trip: parse to wire format and back
	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "_dkim.example.com.",
			Type:  TXT,
			Class: IN,
			TTL:   3600,
			Data:  txt,
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal: %s", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	parsedTxt, ok := parsed.Answer[0].Data.(RDataTXT)
	if !ok {
		t.Fatalf("expected RDataTXT, got %T", parsed.Answer[0].Data)
	}

	if string(parsedTxt) != expected {
		t.Errorf("round-trip TXT mismatch:\ngot:  %s\nwant: %s", string(parsedTxt), expected)
	}
}

func TestRecordTypeCNAME(t *testing.T) {
	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "www.example.com.",
			Type:  CNAME,
			Class: IN,
			TTL:   3600,
			Data:  &RDataLabel{Label: "example.com.", Type: CNAME},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal CNAME: %s", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse CNAME: %s", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	lbl, ok := parsed.Answer[0].Data.(*RDataLabel)
	if !ok {
		t.Fatalf("expected RDataLabel, got %T", parsed.Answer[0].Data)
	}

	if lbl.Label != "example.com." {
		t.Errorf("CNAME target mismatch: got %s", lbl.Label)
	}
}

func TestRecordTypeNS(t *testing.T) {
	msg := New()
	msg.Authority = []*Resource{
		{
			Name:  "example.com.",
			Type:  NS,
			Class: IN,
			TTL:   86400,
			Data:  &RDataLabel{Label: "ns1.example.com.", Type: NS},
		},
		{
			Name:  "example.com.",
			Type:  NS,
			Class: IN,
			TTL:   86400,
			Data:  &RDataLabel{Label: "ns2.example.com.", Type: NS},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal NS: %s", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse NS: %s", err)
	}

	if len(parsed.Authority) != 2 {
		t.Fatalf("expected 2 authority records, got %d", len(parsed.Authority))
	}

	ns1, ok := parsed.Authority[0].Data.(*RDataLabel)
	if !ok {
		t.Fatalf("expected RDataLabel, got %T", parsed.Authority[0].Data)
	}
	if ns1.Label != "ns1.example.com." {
		t.Errorf("NS1 mismatch: got %s", ns1.Label)
	}

	ns2, ok := parsed.Authority[1].Data.(*RDataLabel)
	if !ok {
		t.Fatalf("expected RDataLabel, got %T", parsed.Authority[1].Data)
	}
	if ns2.Label != "ns2.example.com." {
		t.Errorf("NS2 mismatch: got %s", ns2.Label)
	}
}

func TestRecordTypePTR(t *testing.T) {
	msg := New()
	msg.Answer = []*Resource{
		{
			Name:  "1.1.168.192.in-addr.arpa.",
			Type:  PTR,
			Class: IN,
			TTL:   3600,
			Data:  &RDataLabel{Label: "host.example.com.", Type: PTR},
		},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal PTR: %s", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse PTR: %s", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	ptr, ok := parsed.Answer[0].Data.(*RDataLabel)
	if !ok {
		t.Fatalf("expected RDataLabel, got %T", parsed.Answer[0].Data)
	}

	if ptr.Label != "host.example.com." {
		t.Errorf("PTR target mismatch: got %s", ptr.Label)
	}
}

func TestLabelCompression(t *testing.T) {
	// Test that label compression works correctly
	msg := New()
	msg.Question = []*Question{
		{Name: "www.example.com.", Type: A, Class: IN},
	}
	msg.Answer = []*Resource{
		{Name: "www.example.com.", Type: CNAME, Class: IN, TTL: 300, Data: &RDataLabel{Label: "example.com.", Type: CNAME}},
		{Name: "example.com.", Type: A, Class: IN, TTL: 300, Data: &RDataIP{IP: net.ParseIP("192.168.1.1").To4(), Type: A}},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal: %s", err)
	}

	// Parse and verify
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	if len(parsed.Answer) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(parsed.Answer))
	}

	// Verify the compression pointer was followed correctly
	if parsed.Answer[0].Name != "www.example.com." {
		t.Errorf("answer[0] name mismatch: got %s", parsed.Answer[0].Name)
	}
	if parsed.Answer[1].Name != "example.com." {
		t.Errorf("answer[1] name mismatch: got %s", parsed.Answer[1].Name)
	}
}

func TestNewQuery(t *testing.T) {
	msg := NewQuery("example.com.", IN, A)

	if len(msg.Question) != 1 {
		t.Fatalf("expected 1 question, got %d", len(msg.Question))
	}

	q := msg.Question[0]
	if q.Name != "example.com." {
		t.Errorf("name mismatch: got %s", q.Name)
	}
	if q.Type != A {
		t.Errorf("type mismatch: got %s", q.Type)
	}
	if q.Class != IN {
		t.Errorf("class mismatch: got %s", q.Class)
	}

	// Verify RD flag is set
	if msg.Bits&hRecD == 0 {
		t.Error("RD flag not set")
	}
}

func TestRDataFromString(t *testing.T) {
	tests := []struct {
		name    string
		typ     Type
		input   string
		wantErr bool
	}{
		{"A record", A, "192.168.1.1", false},
		{"A record invalid", A, "invalid", true},
		{"AAAA record", AAAA, "2001:db8::1", false},
		{"AAAA record invalid", AAAA, "invalid", true},
		{"NS record", NS, "ns1.example.com.", false},
		{"CNAME record", CNAME, "target.example.com.", false},
		{"PTR record", PTR, "host.example.com.", false},
		{"MX record", MX, "10 mail.example.com.", false},
		{"TXT record", TXT, `"hello world"`, false},
		{"SOA record", SOA, "ns1.example.com. admin.example.com. 2024010101 3600 600 604800 60", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdata, err := RDataFromString(tt.typ, tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("RDataFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && rdata == nil {
				t.Error("RDataFromString() returned nil without error")
			}
		})
	}
}

func TestParseInvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x00, 0x01}},
		{"truncated header", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.data)
			if err == nil {
				t.Error("expected error for invalid data")
			}
		})
	}
}

func TestCompressionPointerLoop(t *testing.T) {
	// Construct a packet with a compression pointer loop
	// Header: ID=0x1234, flags=0x0100 (query, RD), QD=1, AN=0, NS=0, AR=0
	header := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// Question with compression pointer that points to itself (offset 12 = 0x0C)
	// This creates an infinite loop: pointer at position 12 points to position 12
	question := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01}

	packet := append(header, question...)
	_, err := Parse(packet)
	if err == nil {
		t.Error("expected error for compression pointer loop")
	}
}

func TestForwardCompressionPointer(t *testing.T) {
	// Construct a packet with a forward compression pointer (should be invalid)
	// Header: ID=0x1234, flags=0x0100, QD=1, AN=0, NS=0, AR=0
	header := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// Question with forward pointer (points to offset 0x20 which is beyond current position)
	question := []byte{0xc0, 0x20, 0x00, 0x01, 0x00, 0x01}
	// Pad to make offset 0x20 exist
	padding := make([]byte, 20)
	// Put a valid label at offset 0x20
	label := []byte{0x04, 't', 'e', 's', 't', 0x00}

	packet := append(header, question...)
	packet = append(packet, padding...)
	packet = append(packet, label...)

	_, err := Parse(packet)
	if err == nil {
		t.Error("expected error for forward compression pointer")
	}
}

func TestTypeString(t *testing.T) {
	tests := []struct {
		typ  Type
		want string
	}{
		{A, "A"},
		{AAAA, "AAAA"},
		{MX, "MX"},
		{TXT, "TXT"},
		{SOA, "SOA"},
		{NS, "NS"},
		{CNAME, "CNAME"},
		{PTR, "PTR"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.typ.String(); got != tt.want {
				t.Errorf("Type.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStringToType(t *testing.T) {
	tests := []struct {
		input string
		want  Type
		ok    bool
	}{
		{"A", A, true},
		{"AAAA", AAAA, true},
		{"MX", MX, true},
		{"INVALID", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := StringToType[tt.input]
			if ok != tt.ok {
				t.Errorf("StringToType[%s] ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("StringToType[%s] = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestHeaderBits(t *testing.T) {
	// Test various header bit combinations
	msg := New()
	msg.Bits = hQResp | hAuth | hRecD | hRecA

	if msg.Bits&hQResp == 0 {
		t.Error("QR bit not set")
	}
	if msg.Bits&hAuth == 0 {
		t.Error("AA bit not set")
	}
	if msg.Bits&hRecD == 0 {
		t.Error("RD bit not set")
	}
	if msg.Bits&hRecA == 0 {
		t.Error("RA bit not set")
	}
}

func TestMultipleQuestions(t *testing.T) {
	msg := New()
	msg.Question = []*Question{
		{Name: "example.com.", Type: A, Class: IN},
		{Name: "example.com.", Type: AAAA, Class: IN},
		{Name: "example.com.", Type: MX, Class: IN},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal: %s", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	if len(parsed.Question) != 3 {
		t.Fatalf("expected 3 questions, got %d", len(parsed.Question))
	}

	expectedTypes := []Type{A, AAAA, MX}
	for i, q := range parsed.Question {
		if q.Type != expectedTypes[i] {
			t.Errorf("question[%d] type mismatch: got %s, want %s", i, q.Type, expectedTypes[i])
		}
	}
}

func TestLabelTooLong(t *testing.T) {
	// Labels are limited to 63 characters
	longLabel := "a"
	for i := 0; i < 64; i++ {
		longLabel += "a"
	}

	msg := New()
	msg.Question = []*Question{
		{Name: longLabel + ".com.", Type: A, Class: IN},
	}

	_, err := msg.MarshalBinary()
	if err == nil {
		t.Error("expected error for label > 63 characters")
	}
}

func TestNameTooLong(t *testing.T) {
	// Names are limited to 255 characters total
	longName := ""
	for i := 0; i < 30; i++ {
		longName += "abcdefghi."
	}

	msg := New()
	msg.Question = []*Question{
		{Name: longName, Type: A, Class: IN},
	}

	_, err := msg.MarshalBinary()
	if err == nil {
		t.Error("expected error for name > 255 characters")
	}
}

// Benchmarks

func BenchmarkParse(b *testing.B) {
	// Standard query response with A record
	hexB := "236f8180000100010000000106676f6f676c6503636f6d0000010001c00c00010001000000cd0004acd9af6e0000290200000000000000"
	data, _ := hex.DecodeString(hexB)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshal(b *testing.B) {
	msg := New()
	msg.ID = 12345
	msg.Bits = hQResp | hRecD | hRecA
	msg.Question = []*Question{
		{Name: "example.com.", Type: A, Class: IN},
	}
	msg.Answer = []*Resource{
		{Name: "example.com.", Type: A, Class: IN, TTL: 300, Data: &RDataIP{IP: net.ParseIP("192.168.1.1").To4(), Type: A}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := msg.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseComplex(b *testing.B) {
	// Build a more complex message with multiple records
	msg := New()
	msg.ID = 12345
	msg.Bits = hQResp | hRecD | hRecA
	msg.Question = []*Question{
		{Name: "example.com.", Type: A, Class: IN},
	}
	msg.Answer = []*Resource{
		{Name: "example.com.", Type: A, Class: IN, TTL: 300, Data: &RDataIP{IP: net.ParseIP("192.168.1.1").To4(), Type: A}},
		{Name: "example.com.", Type: A, Class: IN, TTL: 300, Data: &RDataIP{IP: net.ParseIP("192.168.1.2").To4(), Type: A}},
		{Name: "example.com.", Type: AAAA, Class: IN, TTL: 300, Data: &RDataIP{IP: net.ParseIP("2001:db8::1"), Type: AAAA}},
	}
	msg.Authority = []*Resource{
		{Name: "example.com.", Type: NS, Class: IN, TTL: 86400, Data: &RDataLabel{Label: "ns1.example.com.", Type: NS}},
		{Name: "example.com.", Type: NS, Class: IN, TTL: 86400, Data: &RDataLabel{Label: "ns2.example.com.", Type: NS}},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalComplex(b *testing.B) {
	msg := New()
	msg.ID = 12345
	msg.Bits = hQResp | hRecD | hRecA
	msg.Question = []*Question{
		{Name: "example.com.", Type: A, Class: IN},
	}
	msg.Answer = []*Resource{
		{Name: "example.com.", Type: A, Class: IN, TTL: 300, Data: &RDataIP{IP: net.ParseIP("192.168.1.1").To4(), Type: A}},
		{Name: "example.com.", Type: A, Class: IN, TTL: 300, Data: &RDataIP{IP: net.ParseIP("192.168.1.2").To4(), Type: A}},
		{Name: "example.com.", Type: AAAA, Class: IN, TTL: 300, Data: &RDataIP{IP: net.ParseIP("2001:db8::1"), Type: AAAA}},
	}
	msg.Authority = []*Resource{
		{Name: "example.com.", Type: NS, Class: IN, TTL: 86400, Data: &RDataLabel{Label: "ns1.example.com.", Type: NS}},
		{Name: "example.com.", Type: NS, Class: IN, TTL: 86400, Data: &RDataLabel{Label: "ns2.example.com.", Type: NS}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := msg.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	msg := New()
	msg.ID = 12345
	msg.Bits = hQResp | hRecD | hRecA
	msg.Question = []*Question{
		{Name: "example.com.", Type: A, Class: IN},
	}
	msg.Answer = []*Resource{
		{Name: "example.com.", Type: A, Class: IN, TTL: 300, Data: &RDataIP{IP: net.ParseIP("192.168.1.1").To4(), Type: A}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := msg.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
		_, err = Parse(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}
