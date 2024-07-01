package main

import (
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/KarpelesLab/dns/dnsmsg"
)

func performHandler(params []string, name []byte, typ dnsmsg.Type) (res []dnsmsg.RData, err error) {
	if len(params) == 0 {
		return nil, errors.New("handler missing")
	}

	switch strings.ToLower(params[0]) {
	case "base32addr":
		return base32addrHandler(name, typ)
	default:
		return nil, fmt.Errorf("unsupported handler %s", params[0])
	}
}

var b32e = base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)

func base32addrHandler(name []byte, typ dnsmsg.Type) (res []dnsmsg.RData, err error) {
	pos := bytes.IndexByte(name, '.')
	if pos > 0 {
		name = name[:pos]
	}
	v, err := b32e.DecodeString(strings.ToUpper(string(name)))
	if err != nil {
		return nil, err
	}

	switch typ {
	case dnsmsg.A:
		if len(v) != 4 {
			return nil, errors.New("invalid ip request")
		}
		ip := net.IP(v)
		t := &dnsmsg.RDataIP{IP: ip, Type: typ}
		res = append(res, t)
	case dnsmsg.AAAA:
		ip := net.IP(v)
		t := &dnsmsg.RDataIP{IP: ip, Type: typ}
		res = append(res, t)
	}
	return
}
