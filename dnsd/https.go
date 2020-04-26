package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"runtime"
	"strings"

	"github.com/KarpelesLab/dns/dnsmsg"
)

func initHttps(ips []net.IP, errch chan<- error) {
	cfg := &tls.Config{
		NextProtos:               []string{"h2", "http/1.1"},
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Certificates: tlsLoadCertificate(),
	}
	srv := &http.Server{
		TLSConfig: cfg,
		Handler:   http.HandlerFunc(handleHttpsReq),
	}

	if len(ips) == 0 {
		httpsListen(srv, nil, errch)
		return
	}

	for _, ip := range ips {
		httpsListen(srv, ip, errch)
	}
}

func httpsListen(srv *http.Server, ip net.IP, errch chan<- error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: 853})
	if err != nil {
		// retry on port 8053 (probably not root)
		l, err = net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: 8853})
		if err != nil {
			errch <- fmt.Errorf("failed to listen TCP: %w", err)
			return
		}
	}

	// one thread per cpu since we'll spawn extra threads per connected clients
	cnt := runtime.NumCPU()

	for i := 0; i < cnt; i++ {
		go httpsThread(srv, l)
	}
	log.Printf("[https] listening on port %s with %d goroutines", l.Addr().String(), cnt)
}

func httpsThread(srv *http.Server, l *net.TCPListener) {
	tlsL := tls.NewListener(l, srv.TLSConfig)

	err := srv.Serve(tlsL)
	log.Printf("[https] Serve failed: %s", err)
}

func handleHttpsReq(rw http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/dns-query":
		// can be GET or POST
		switch req.Method {
		case "GET":
			// /dns-query?dns=AAAA...
			dns := req.URL.Query().Get("dns")
			buf, err := base64.RawURLEncoding.DecodeString(dns)
			if err != nil {
				http.Error(rw, fmt.Sprintf("failed to read: %s", err), http.StatusBadRequest)
				return
			}
			handleHttpsPacket(buf, rw, req)
			return
		case "POST":
			// post content-type = application/dns-message
			if req.Header.Get("Content-Type") != "application/dns-message" {
				http.Error(rw, "bad content-type, should be application/dns-message", http.StatusBadRequest)
				return
			}
			lr := &io.LimitedReader{req.Body, 512} // limit read to 512 bytes
			buf, err := ioutil.ReadAll(lr)
			if err != nil {
				http.Error(rw, fmt.Sprintf("failed to read: %s", err), http.StatusBadRequest)
				return
			}
			handleHttpsPacket(buf, rw, req)
			return
		default:
			http.Error(rw, "unsupported method", http.StatusBadRequest)
			return
		}
	default:
		if strings.HasPrefix(req.URL.Path, "/api/") {
			handleApi(rw, req)
			return
		}
		http.NotFound(rw, req)
		return
	}
}

func handleHttpsPacket(buf []byte, rw http.ResponseWriter, req *http.Request) {
	// get localADdr (type net.Addr)
	laddr := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
	// TODO parse RemoteAddr
	//raddr := req.RemoteAddr
	raddr := net.Addr(nil)

	// parse pkg
	msg, err := dnsmsg.Parse(buf)
	if err != nil {
		log.Printf("[https] failed to parse msg from %s: %s", raddr, err)
		http.Error(rw, fmt.Sprintf("failed to parse: %s", err), http.StatusBadRequest)
		return
	}

	res, err := handleQuery(msg, laddr, raddr)
	if err != nil {
		log.Printf("[https] failed to respond to %s: %s", raddr, err)
		return
	}
	if res == nil {
		// no response needed
		return
	}

	buf, err = res.MarshalBinary()
	if err != nil {
		log.Printf("[https] failed to make response to %s: %s", raddr, err)
		return
	}

	// write packet len + packet
	if len(buf) > 65535 {
		log.Printf("[https] failed to respond (packet too big) to %s", raddr)
		return
	}

	rw.Header().Set("Content-Type", "application/dns-message")
	_, err = rw.Write(buf)
	if err != nil {
		log.Printf("[https] failed to write to %s: %s", raddr, err)
		return
	}
}
