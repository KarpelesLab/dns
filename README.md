# DNS lightweight library

A pure Go library for parsing and encoding DNS protocol messages as defined in RFC 1035 and subsequent RFCs. Zero external dependencies.

[![Go Reference](https://pkg.go.dev/badge/github.com/KarpelesLab/dns.svg)](https://pkg.go.dev/github.com/KarpelesLab/dns)

## Features

- Parse and generate DNS messages in wire format
- Support for common record types: A, AAAA, MX, TXT, SOA, NS, CNAME, PTR, and more
- **Full DNSSEC support**: DNSKEY, RRSIG, DS, NSEC, NSEC3, NSEC3PARAM
- EDNS support (RFC 6891)
- Label compression for efficient message encoding
- Protection against malformed packets (compression pointer loops, forward pointers)
- Zero external dependencies for parsing - crypto operations in separate package

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

### DNSSEC: Signing an RRset

```go
import (
    "time"
    "github.com/KarpelesLab/dns/dnsmsg"
    "github.com/KarpelesLab/dns/dnssec"
)

// Generate a new ECDSA P-256 Zone Signing Key
key, privateKey, err := dnssec.GenerateKey(dnsmsg.AlgorithmECDSAP256, 0)
if err != nil {
    log.Fatal(err)
}

// Create a signer
signer, err := dnssec.NewSigner(key, privateKey)
if err != nil {
    log.Fatal(err)
}

// Sign an RRset
rrset := []*dnsmsg.Resource{
    {
        Name:  "example.com.",
        Type:  dnsmsg.A,
        Class: dnsmsg.IN,
        TTL:   300,
        Data:  &dnsmsg.RDataIP{IP: net.ParseIP("192.0.2.1").To4(), Type: dnsmsg.A},
    },
}

rrsig, err := signer.SignRRsetWithDuration(rrset, "example.com.", 300, 30*24*time.Hour)
if err != nil {
    log.Fatal(err)
}
```

### DNSSEC: Verifying a signature

```go
import (
    "github.com/KarpelesLab/dns/dnsmsg"
    "github.com/KarpelesLab/dns/dnssec"
)

// Assuming you have parsed RRSIG, DNSKEY, and RRset from DNS responses
err := dnssec.VerifyRRSIG(rrsig, dnskey, rrset)
if err != nil {
    log.Printf("Signature verification failed: %v", err)
}
```

### DNSSEC: Computing a DS record

```go
import (
    "github.com/KarpelesLab/dns/dnsmsg"
    "github.com/KarpelesLab/dns/dnssec"
)

// Generate a KSK (Key Signing Key)
ksk, _, err := dnssec.GenerateKSK(dnsmsg.AlgorithmECDSAP256, 0)
if err != nil {
    log.Fatal(err)
}

// Compute DS record to publish in parent zone
ds, err := dnssec.ComputeDS("example.com.", ksk, dnsmsg.DigestSHA256)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("DS record: %d %d %d %x\n", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
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
| DNSKEY | DNSSEC public key | Full support |
| RRSIG | DNSSEC signature | Full support |
| DS | Delegation signer | Full support |
| NSEC | Next secure record | Full support |
| NSEC3 | NSEC version 3 | Full support |
| NSEC3PARAM | NSEC3 parameters | Full support |
| Others | See type.go | Parsed as raw bytes |

## Packages

- [`dnsmsg`](https://pkg.go.dev/github.com/KarpelesLab/dns/dnsmsg): Parse and generate DNS messages
- [`dnssec`](https://pkg.go.dev/github.com/KarpelesLab/dns/dnssec): DNSSEC cryptographic operations (signing, verification, DS computation)

## DNSSEC Algorithms Supported

| Algorithm | ID | Status |
|-----------|-----|--------|
| RSA/SHA-256 | 8 | Full support |
| RSA/SHA-512 | 10 | Full support |
| ECDSA P-256/SHA-256 | 13 | Full support |
| ECDSA P-384/SHA-384 | 14 | Full support |
| Ed25519 | 15 | Full support |

## Sources

- [IANA DNS Parameters](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
- [RFC 1035 - Domain Names](https://tools.ietf.org/html/rfc1035)
- [RFC 3596 - DNS Extensions for IPv6](https://tools.ietf.org/html/rfc3596)
- [RFC 4034 - DNSSEC Resource Records](https://tools.ietf.org/html/rfc4034)
- [RFC 5155 - NSEC3](https://tools.ietf.org/html/rfc5155)
- [RFC 6891 - EDNS](https://tools.ietf.org/html/rfc6891)
- [RFC 8080 - Ed25519 for DNSSEC](https://tools.ietf.org/html/rfc8080)

## License

See LICENSE file.
