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

func main() {
	flagAddr := flag.String("proxy", "127.0.0.1:8000", "address to proxy to (e.g. 127.0.0.1:8000)")
	flagListen := flag.String("listen", "127.0.0.1:4443", "address to listen on (e.g. 127.0.0.1:4443)")
	flag.Parse()

	ca := stun.NewCertificateAuthority()

	l, err := tls.Listen("tcp", *flagListen, &tls.Config{
		GetCertificate: ca.GetCertificate,
	})
	panicIfErr(err)

	defer l.Close()
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		// Handle the connection in a new goroutine.
		go func(c net.Conn) {
			proxy, err := net.Dial("tcp", *flagAddr)
			if err != nil {
				log.Print(err)
			}

			// Close the connection once.
			var once sync.Once
			onceBody := func() {
				c.Close()
				proxy.Close()
			}

			// Read from conn, send to proxy.
			go func(c net.Conn) {
				io.Copy(proxy, c)
				once.Do(onceBody)
			}(c)

			// Read from proxy, send to conn.
			go func(c net.Conn) {
				io.Copy(c, proxy)
				once.Do(onceBody)
			}(c)
		}(conn)
	}
}
