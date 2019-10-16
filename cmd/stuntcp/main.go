package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"sync"

	"github.com/amlweems/stun"
)

func panicIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var (
	insecureConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
)

func main() {
	flagAddr := flag.String("proxy", "127.0.0.1:8000", "address to proxy to (e.g. 127.0.0.1:8000)")
	flagListen := flag.String("listen", "127.0.0.1:4443", "address to listen on (e.g. 127.0.0.1:4443)")
	flagFallback := flag.String("fallback", "*.example.org", "fallback in case SNI is not sent")
	flagTLS := flag.Bool("tls", false, "proxy to a TLS service")
	flag.Parse()

	ca := stun.NewCertificateAuthority()
	ca.DefaultServerName = *flagFallback

	l, err := tls.Listen("tcp", *flagListen, &tls.Config{
		GetCertificate: ca.GetCertificate,
	})
	panicIfErr(err)

	defer l.Close()
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		panicIfErr(err)

		inject, err := net.Listen("tcp", "0.0.0.0:0")
		panicIfErr(err)
		log.Printf("inject at %s for %s", inject.Addr(), conn.RemoteAddr())

		// Handle the connection in a new goroutine.
		go func(c net.Conn, inject net.Listener) {
			var proxy net.Conn
			var err error

			// connect to proxy address (optionally using TLS)
			if *flagTLS {
				proxy, err = tls.Dial("tcp", *flagAddr, insecureConfig)
			} else {
				proxy, err = net.Dial("tcp", *flagAddr)
			}

			if err != nil {
				log.Print(err)
			}

			// Close the connection once.
			var once sync.Once
			onceBody := func() {
				c.Close()
				proxy.Close()
				inject.Close()
			}

			// Read from conn, send to proxy.
			go func(c net.Conn) {
				prefix := c.RemoteAddr().String() + " c2s"
				io.Copy(stun.NewHexLogger(prefix, proxy), c)
				once.Do(onceBody)
			}(c)

			// Read from proxy, send to conn.
			go func(c net.Conn) {
				prefix := c.RemoteAddr().String() + " s2c"
				io.Copy(stun.NewHexLogger(prefix, c), proxy)
				once.Do(onceBody)
			}(c)

			for {
				ci, err := inject.Accept()
				if err != nil {
					break
				}

				go func(ci net.Conn) {
					prefix := c.RemoteAddr().String() + " i2s"
					io.Copy(stun.NewHexLogger(prefix, proxy), ci)
					ci.Close()
				}(ci)
			}

		}(conn, inject)
	}
}
