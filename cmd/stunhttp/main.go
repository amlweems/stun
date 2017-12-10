package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/amlweems/stun"
)

func panicIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flagAddr := flag.String("proxy", "http://127.0.0.1:8000", "address to proxy to (e.g. http://127.0.0.1:8000)")
	flagListen := flag.String("listen", "127.0.0.1:4443", "address to listen on (e.g. 127.0.0.1:4443)")
	flag.Parse()

	addr, err := url.Parse(*flagAddr)
	panicIfErr(err)

	ca := stun.NewCertificateAuthority()

	l, err := tls.Listen("tcp", *flagListen, &tls.Config{
		GetCertificate: ca.GetCertificate,
	})
	panicIfErr(err)

	http.Serve(l, httputil.NewSingleHostReverseProxy(addr))
}
