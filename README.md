# DNS lightweight library

A pure Go library for parsing and encoding DNS protocol messages as defined in RFC 1035 and subsequent RFCs. Zero external dependencies.

[![Go Reference](https://pkg.go.dev/badge/github.com/KarpelesLab/dns.svg)](https://pkg.go.dev/github.com/KarpelesLab/dns)

## Features

- Parse and generate DNS messages in wire format
- Support for common record types: A, AAAA, MX, TXT, SOA, NS, CNAME, PTR, and more
- EDNS support (RFC 6891)
- Label compression for efficient message encoding
- Protection against malformed packets (compression pointer loops, forward pointers)
- Zero external dependencies - uses only Go standard library

## Installation

```bash
go get github.com/KarpelesLab/dns
```

## Usage

### Parsing a DNS message

```go
import "github.com/KarpelesLab/dns/dnsmsg"

// Parse raw DNS packet
msg, err := dnsmsg.Parse(rawBytes)
if err != nil {
    log.Fatal(err)
}

// Access parsed data
for _, answer := range msg.Answer {
    fmt.Printf("%s %s %s\n", answer.Name, answer.Type, answer.Data)
}
```

### Creating a DNS query

```go
import "github.com/KarpelesLab/dns/dnsmsg"

// Create a query for example.com A record
msg := dnsmsg.NewQuery("example.com.", dnsmsg.IN, dnsmsg.A)

// Marshal to wire format
data, err := msg.MarshalBinary()
if err != nil {
    log.Fatal(err)
}
```

### Creating a DNS response

```go
import (
    "net"
    "github.com/KarpelesLab/dns/dnsmsg"
)

msg := dnsmsg.New()
msg.Bits.SetResponse(true)
msg.Question = []*dnsmsg.Question{
    {Name: "example.com.", Type: dnsmsg.A, Class: dnsmsg.IN},
}
msg.Answer = []*dnsmsg.Resource{
    {
        Name:  "example.com.",
        Type:  dnsmsg.A,
        Class: dnsmsg.IN,
        TTL:   300,
        Data:  &dnsmsg.RDataIP{IP: net.ParseIP("192.168.1.1").To4(), Type: dnsmsg.A},
    },
}

data, err := msg.MarshalBinary()
```

## Supported Record Types

| Type | Description | Status |
|------|-------------|--------|
| A | IPv4 address | Full support |
| AAAA | IPv6 address | Full support |
| NS | Nameserver | Full support |
| CNAME | Canonical name | Full support |
| SOA | Start of authority | Full support |
| PTR | Pointer | Full support |
| MX | Mail exchange | Full support |
| TXT | Text | Full support |
| OPT | EDNS options | Full support |
| Others | See type.go | Parsed as raw bytes |

## Packages

- [`dnsmsg`](https://pkg.go.dev/github.com/KarpelesLab/dns/dnsmsg): Parse and generate DNS messages

## Sources

- [IANA DNS Parameters](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
- [RFC 1035 - Domain Names](https://tools.ietf.org/html/rfc1035)
- [RFC 3596 - DNS Extensions for IPv6](https://tools.ietf.org/html/rfc3596)
- [RFC 6891 - EDNS](https://tools.ietf.org/html/rfc6891)

## License

See LICENSE file.
