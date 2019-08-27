package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/amlweems/stun"
)

func panicIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var (
	InsecureTransport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
)

func main() {
	flagAddr := flag.String("proxy", "http://127.0.0.1:8000", "address to proxy to (e.g. http://127.0.0.1:8000)")
	flagListen := flag.String("listen", "127.0.0.1:4443", "address to listen on (e.g. 127.0.0.1:4443)")
	flagFallback := flag.String("fallback", "*.example.org", "fallback in case SNI is not sent")
	flagVerify := flag.Bool("verify", false, "verify TLS certificates to proxy host")
	flag.Parse()

	addr, err := url.Parse(*flagAddr)
	panicIfErr(err)

	ca := stun.NewCertificateAuthority()
	ca.DefaultServerName = *flagFallback

	l, err := tls.Listen("tcp", *flagListen, &tls.Config{
		GetCertificate: ca.GetCertificate,
	})
	panicIfErr(err)

	proxy := httputil.NewSingleHostReverseProxy(addr)
	if *flagVerify == false {
		proxy.Transport = InsecureTransport
	}
	http.Serve(l, proxy)
}
