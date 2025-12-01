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

## DNS Packet Structure

A DNS packet follows the format defined in RFC 1035 Section 4. This library implements the complete wire format for both parsing and generation.

### Packet Overview

```
+---------------------+
|        Header       |  12 bytes fixed
+---------------------+
|       Question      |  Variable length
+---------------------+
|        Answer       |  Variable length
+---------------------+
|      Authority      |  Variable length
+---------------------+
|      Additional     |  Variable length
+---------------------+
```

### Header Format (12 bytes)

The header is always 12 bytes and contains:

```
                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |  2 bytes (flags)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

| Field | Bits | Description |
|-------|------|-------------|
| ID | 16 | Transaction identifier for matching queries/responses |
| QR | 1 | 0 = Query, 1 = Response |
| OPCODE | 4 | Operation type: 0=Query, 1=IQuery, 2=Status |
| AA | 1 | Authoritative Answer |
| TC | 1 | Truncation (message was truncated) |
| RD | 1 | Recursion Desired |
| RA | 1 | Recursion Available |
| Z | 3 | Reserved (must be zero) |
| RCODE | 4 | Response code: 0=NoError, 1=FormErr, 2=ServFail, 3=NXDomain, etc. |
| QDCOUNT | 16 | Number of questions |
| ANCOUNT | 16 | Number of answer records |
| NSCOUNT | 16 | Number of authority records |
| ARCOUNT | 16 | Number of additional records |

### Question Section

Each question has the following format:

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QNAME                     |  Variable (domain name)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### Resource Record Format

Each resource record (Answer, Authority, Additional) has:

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      NAME                     |  Variable (domain name)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |  4 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     RDATA                     |  Variable (RDLENGTH bytes)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### Domain Name Encoding

Domain names are encoded as a sequence of labels, where each label is:
- 1 byte length (0-63)
- N bytes of label data

The sequence ends with a zero-length label (single 0x00 byte).

**Example:** `www.example.com.` is encoded as:
```
0x03 'w' 'w' 'w' 0x07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 0x03 'c' 'o' 'm' 0x00
 |                |                               |               |
 3 chars          7 chars                         3 chars         end
```

### Label Compression

To reduce packet size, DNS supports label compression. When the two high bits of a length byte are set (`11xxxxxx`), the remaining 14 bits form a pointer to a previous occurrence of the label:

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| 1  1|                OFFSET                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

The offset is relative to the start of the DNS message. This library:
- Automatically compresses labels when encoding (see `context.appendLabel`)
- Safely decompresses labels when parsing with protection against:
  - Pointer loops (infinite recursion)
  - Forward pointers (pointers pointing ahead, not backwards)

### Common Record Types (RDATA formats)

| Type | Value | RDATA Format |
|------|-------|--------------|
| A | 1 | 4 bytes IPv4 address |
| NS | 2 | Domain name |
| CNAME | 5 | Domain name |
| SOA | 6 | MNAME, RNAME (names), Serial, Refresh, Retry, Expire, Minimum (uint32s) |
| PTR | 12 | Domain name |
| MX | 15 | 2-byte preference + domain name |
| TXT | 16 | One or more length-prefixed character strings (max 255 bytes each) |
| AAAA | 28 | 16 bytes IPv6 address |

### Classes

| Class | Value | Description |
|-------|-------|-------------|
| IN | 1 | Internet (most common) |
| CS | 2 | CSNET (obsolete) |
| CH | 3 | Chaos |
| HS | 4 | Hesiod |

## EDNS0 (Extension Mechanisms for DNS)

EDNS0 (RFC 6891) extends DNS to support larger UDP packets, additional flags, and option codes. It works by adding a pseudo-resource record of type OPT (41) to the Additional section.

### Why EDNS0?

The original DNS specification (RFC 1035) limited UDP messages to 512 bytes. EDNS0 solves this and other limitations:

- **Larger UDP payloads**: Clients can advertise support for UDP packets up to 65535 bytes
- **Extended RCODE**: The 4-bit RCODE is extended to 12 bits for more error codes
- **Version negotiation**: Allows future DNS protocol extensions
- **Option codes**: Extensible mechanism for new features (DNSSEC, cookies, client subnet, etc.)

### OPT Record Structure

The OPT pseudo-record repurposes standard resource record fields:

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     NAME                      |  Must be 0 (root domain)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     TYPE                      |  OPT (41)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              UDP Payload Size                 |  Replaces CLASS field
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|   Extended RCODE  |  Version  |DO|    Z      |  Replaces TTL field
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  RDATA (options)              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

| Field | Standard RR Field | EDNS0 Meaning |
|-------|-------------------|---------------|
| NAME | Domain name | Must be root (0x00) |
| TYPE | Record type | OPT (41) |
| CLASS | Class | Requestor's UDP payload size |
| TTL (byte 0) | TTL | Extended RCODE (upper 8 bits) |
| TTL (byte 1) | TTL | EDNS version (must be 0) |
| TTL (bytes 2-3) | TTL | Flags (bit 15 = DO, DNSSEC OK) |
| RDATA | Record data | Variable-length options |

### EDNS Options Format

Each option in RDATA follows this format:

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  OPTION-CODE                  |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                 OPTION-LENGTH                 |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  OPTION-DATA                  |  Variable
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

Common option codes include:

| Code | Name | Description |
|------|------|-------------|
| 3 | NSID | Name Server Identifier |
| 8 | Client Subnet | Client's network for geolocation |
| 10 | Cookie | DNS cookies for security |
| 11 | TCP Keepalive | TCP connection reuse |
| 12 | Padding | Message padding for privacy |
| 15 | Extended Error | Additional error information |

### EDNS0 in This Library

When parsing, the library automatically extracts EDNS0 data from OPT records:

```go
msg, _ := dnsmsg.Parse(rawBytes)

if msg.HasEDNS {
    fmt.Printf("Client UDP size: %d\n", msg.ReqUDPSize)
    fmt.Printf("Extended RCODE/Flags: %08x\n", msg.OptRCode)
    for _, opt := range msg.Opts {
        fmt.Printf("Option code=%d, len=%d\n", opt.Code, len(opt.Data))
    }
}
```

The `Message` struct provides these EDNS-related fields:

| Field | Type | Description |
|-------|------|-------------|
| `HasEDNS` | `bool` | True if OPT record was present |
| `ReqUDPSize` | `uint16` | Requestor's advertised UDP payload size |
| `OptRCode` | `OptRCode` | Extended RCODE and flags (from TTL field) |
| `Opts` | `[]DnsOpt` | Slice of EDNS options |

### Byte-Level EDNS0 Example

An OPT record advertising 4096-byte UDP support with DNSSEC OK:

```
00              # NAME = root (empty)
00 29           # TYPE = OPT (41)
10 00           # CLASS = 4096 (UDP payload size)
00 00 80 00     # TTL: RCODE-ext=0, Version=0, DO=1, Z=0
00 00           # RDLENGTH = 0 (no options)
```

With a Client Subnet option (code 8):

```
00              # NAME = root
00 29           # TYPE = OPT (41)
10 00           # CLASS = 4096
00 00 80 00     # TTL: DO=1
00 0b           # RDLENGTH = 11
00 08           # OPTION-CODE = 8 (Client Subnet)
00 07           # OPTION-LENGTH = 7
00 01           # Family = 1 (IPv4)
18              # Source prefix = 24
00              # Scope prefix = 0
c0 a8 01        # Address = 192.168.1.0/24
```

## Library Architecture

The library is organized into two packages:

### `dnsmsg` - Core DNS Message Handling

Key types and their roles:

| Type | File | Purpose |
|------|------|---------|
| `Message` | msg.go | Main DNS message container with Header, Question, Answer, Authority, Additional sections |
| `HeaderBits` | header.go | 16-bit flags field (QR, OPCODE, AA, TC, RD, RA, RCODE) |
| `Question` | question.go | DNS question (QNAME, QTYPE, QCLASS) |
| `Resource` | resource.go | Resource record (NAME, TYPE, CLASS, TTL, RDATA) |
| `RData` | rdata.go | Interface for type-specific record data |
| `context` | context.go | Internal encoding/decoding context with label compression |

The `context` type handles:
- **Label compression during encoding**: Caches label positions in `labelMap` and reuses them via compression pointers
- **Safe decompression during parsing**: Tracks visited positions to prevent infinite loops and rejects forward pointers
- **Binary I/O**: Implements `io.Reader` and `io.Writer` for the raw message buffer

### `dnssec` - DNSSEC Cryptographic Operations

| Function | Purpose |
|----------|---------|
| `GenerateKey` / `GenerateKSK` | Generate DNSKEY pairs |
| `NewSigner` | Create a signer for RRset signing |
| `SignRRsetWithDuration` | Sign an RRset with specified validity |
| `VerifyRRSIG` | Verify an RRSIG against DNSKEY and RRset |
| `ComputeDS` | Compute DS record from DNSKEY |

## Byte-Level Example

Here's what a DNS query for `example.com. A IN` looks like in wire format:

```
Header (12 bytes):
  00 01          # ID = 1
  01 00          # Flags: RD=1 (recursion desired), Query
  00 01          # QDCOUNT = 1
  00 00          # ANCOUNT = 0
  00 00          # NSCOUNT = 0
  00 00          # ARCOUNT = 0

Question:
  07 65 78 61 6d 70 6c 65   # "example" (7 chars)
  03 63 6f 6d               # "com" (3 chars)
  00                        # End of name
  00 01                     # QTYPE = A (1)
  00 01                     # QCLASS = IN (1)
```

And a corresponding response with compression:

```
Header (12 bytes):
  00 01          # ID = 1
  81 80          # Flags: QR=1 (response), RD=1, RA=1
  00 01          # QDCOUNT = 1
  00 01          # ANCOUNT = 1
  00 00          # NSCOUNT = 0
  00 00          # ARCOUNT = 0

Question (same as query):
  07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
  00 01 00 01

Answer:
  c0 0c          # Name pointer to offset 12 (0x0c) = "example.com."
  00 01          # TYPE = A
  00 01          # CLASS = IN
  00 00 01 2c    # TTL = 300 seconds
  00 04          # RDLENGTH = 4
  5d b8 d8 22    # RDATA = 93.184.216.34
```

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

### Core Record Types (RFC 1035)

| Type | Description | Status |
|------|-------------|--------|
| A | IPv4 address | Full support |
| NS | Nameserver | Full support |
| CNAME | Canonical name | Full support |
| SOA | Start of authority | Full support |
| PTR | Pointer | Full support |
| HINFO | Host information | Full support |
| MX | Mail exchange | Full support |
| TXT | Text | Full support |

### IPv6 and Extended Types

| Type | Description | Status |
|------|-------------|--------|
| AAAA | IPv6 address (RFC 3596) | Full support |
| SRV | Service locator (RFC 2782) | Full support |
| NAPTR | Naming authority pointer (RFC 3403) | Full support |
| DNAME | Delegation name (RFC 6672) | Full support |
| RP | Responsible person (RFC 1183) | Full support |
| AFSDB | AFS database (RFC 1183) | Full support |

### DNSSEC Record Types

| Type | Description | Status |
|------|-------------|--------|
| DNSKEY | DNSSEC public key (RFC 4034) | Full support |
| RRSIG | DNSSEC signature (RFC 4034) | Full support |
| DS | Delegation signer (RFC 4034) | Full support |
| NSEC | Next secure record (RFC 4034) | Full support |
| NSEC3 | NSEC version 3 (RFC 5155) | Full support |
| NSEC3PARAM | NSEC3 parameters (RFC 5155) | Full support |

### Security and Certificate Types

| Type | Description | Status |
|------|-------------|--------|
| CERT | Certificate (RFC 4398) | Full support |
| TLSA | TLS authentication (RFC 6698) | Full support |
| SSHFP | SSH fingerprint (RFC 4255) | Full support |
| CAA | CA authorization (RFC 8659) | Full support |

### Transaction and Extension Types

| Type | Description | Status |
|------|-------------|--------|
| OPT | EDNS options (RFC 6891) | Full support |
| TSIG | Transaction signature (RFC 8945) | Full support |
| TKEY | Transaction key (RFC 2930) | Full support |
| URI | Uniform resource identifier (RFC 7553) | Full support |

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

### Core DNS RFCs
- [RFC 1035 - Domain Names](https://tools.ietf.org/html/rfc1035) - Base DNS specification
- [RFC 3596 - DNS Extensions for IPv6](https://tools.ietf.org/html/rfc3596) - AAAA records
- [RFC 6891 - EDNS](https://tools.ietf.org/html/rfc6891) - Extension mechanisms

### DNSSEC RFCs
- [RFC 4034 - DNSSEC Resource Records](https://tools.ietf.org/html/rfc4034) - DNSKEY, RRSIG, DS, NSEC
- [RFC 5155 - NSEC3](https://tools.ietf.org/html/rfc5155) - Hashed authenticated denial
- [RFC 8080 - Ed25519 for DNSSEC](https://tools.ietf.org/html/rfc8080) - EdDSA algorithm support

### Additional Record Types
- [RFC 1183 - New DNS RR Definitions](https://tools.ietf.org/html/rfc1183) - RP, AFSDB
- [RFC 2782 - DNS SRV RR](https://tools.ietf.org/html/rfc2782) - Service location
- [RFC 2930 - TKEY RR](https://tools.ietf.org/html/rfc2930) - Secret key establishment
- [RFC 3403 - NAPTR RR](https://tools.ietf.org/html/rfc3403) - Dynamic delegation discovery
- [RFC 4255 - SSHFP RR](https://tools.ietf.org/html/rfc4255) - SSH fingerprints
- [RFC 4398 - CERT RR](https://tools.ietf.org/html/rfc4398) - Storing certificates
- [RFC 6672 - DNAME RR](https://tools.ietf.org/html/rfc6672) - Redirection
- [RFC 6698 - TLSA RR](https://tools.ietf.org/html/rfc6698) - DANE TLS authentication
- [RFC 7553 - URI RR](https://tools.ietf.org/html/rfc7553) - URI publication
- [RFC 8659 - CAA RR](https://tools.ietf.org/html/rfc8659) - Certification authority authorization
- [RFC 8945 - TSIG RR](https://tools.ietf.org/html/rfc8945) - Secret key transaction authentication

### Reference
- [IANA DNS Parameters](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)

## License

See LICENSE file.
