package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"
)

func tlsLoadCertificate() []tls.Certificate {
	// quick n dirty self signed certificate for https
	// TODO: replace me with something better.

	ctpl := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		Version:               1,
		SerialNumber:          big.NewInt(1),

		Issuer:     pkix.Name{CommonName: "DNS Unconfigured"},
		Subject:    pkix.Name{CommonName: "DNS Unconfigured"},
		KeyUsage:   x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen: 1,
	}

	ctpl.NotBefore = time.Now()
	ctpl.NotAfter = ctpl.NotBefore.Add(30 * 24 * time.Hour) // 30 days

	key := getSelfKey()

	// self-sign
	crt, err := x509.CreateCertificate(rand.Reader, ctpl, ctpl, key.Public(), key)

	if err != nil {
		log.Printf("failed to create self-signed certificate: %s", err)
		return nil
	}

	tlsCrt := tls.Certificate{
		Certificate: [][]byte{crt},
		PrivateKey:  key,
	}

	return []tls.Certificate{tlsCrt}
}

func getSelfKey() *ecdsa.PrivateKey {
	v, err := simpleGet([]byte("local"), []byte("key"))
	if err == nil {
		// decode key
		k, err := x509.ParsePKCS8PrivateKey(v)
		if err != nil {
			panic(err)
		}
		// TODO support other key types?
		return k.(*ecdsa.PrivateKey)
	}

	log.Printf("[tls] generating new private key...")
	// generate new key
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		// random generator error?
		panic(err)
	}
	v, err = x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}

	// store key
	err = simpleSet([]byte("local"), []byte("key"), v)
	if err != nil {
		panic(err)
	}

	return k
}
