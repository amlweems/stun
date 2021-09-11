package main

import (
	"crypto/tls"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net"
	"os"
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

var (
	flagMirror     bool
	flagAddr       string
	flagListenAddr string
	flagListenPort string
	flagFallback   string
	flagTLS        bool
	flagServerCert string
	flagServerKey  string
	flagClientCert string
	flagClientKey  string
)

func main() {
	flag.BoolVar(&flagMirror, "mirror", true, "mirror traffic based on ServerName")
	flag.StringVar(&flagAddr, "proxy", "", "address to proxy to (e.g. example.org:443)")
	flag.StringVar(&flagListenAddr, "listen", "0.0.0.0", "address to listen on")
	flag.StringVar(&flagListenPort, "port", "443", "port to listen on")
	flag.StringVar(&flagFallback, "fallback", "*.example.org", "fallback in case SNI is not sent")
	flag.BoolVar(&flagTLS, "tls", true, "proxy to a TLS service")
	flag.StringVar(&flagServerCert, "server-cert", "", "path to server certificate")
	flag.StringVar(&flagServerKey, "server-key", "", "path to server key")
	flag.StringVar(&flagClientCert, "client-cert", "", "path to client certificate")
	flag.StringVar(&flagClientKey, "client-key", "", "path to client key")
	flag.Parse()

	if flagMirror && flagAddr != "" {
		log.Printf("proxy address specified, disabling mirroring")
		flagMirror = false
	}

	if flagClientCert != "" && flagClientKey != "" {
		cert, err := tls.LoadX509KeyPair(flagClientCert, flagClientKey)
		panicIfErr(err)
		insecureConfig.Certificates = []tls.Certificate{cert}
	}

	config := &tls.Config{
		ClientAuth: tls.RequestClientCert,
	}
	if flagServerCert != "" && flagServerKey != "" {
		cert, err := tls.LoadX509KeyPair(flagServerCert, flagServerKey)
		panicIfErr(err)
		config.Certificates = []tls.Certificate{cert}
	} else {
		ca := stun.NewCertificateAuthority()
		ca.DefaultServerName = flagFallback
		config.GetCertificate = ca.GetCertificate
	}
	l, err := tls.Listen("tcp", flagListenAddr+":"+flagListenPort, config)
	panicIfErr(err)

	defer l.Close()
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		panicIfErr(err)

		// Convert conn to tls.Conn
		tlsconn := conn.(*tls.Conn)

		// Ensure the TLS handshake has completed before moving on
		err = tlsconn.Handshake()
		if err != nil {
			conn.Close()
			log.Printf("error in tls handshake: %s", err)
			continue
		}

		target := flagAddr
		state := tlsconn.ConnectionState()
		for _, peer := range state.PeerCertificates {
			log.Printf("peer: %s", peer.Subject.String())
			pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: peer.Raw})
		}
		if flagMirror {
			target = state.ServerName + ":" + flagListenPort
		}
		log.Printf("proxying traffic to %s", target)

		inject, err := net.Listen("tcp", "0.0.0.0:0")
		panicIfErr(err)
		log.Printf("inject at %s for %s", inject.Addr(), conn.RemoteAddr())

		// Handle the connection in a new goroutine.
		go func(c net.Conn, inject net.Listener) {
			var proxy net.Conn
			var err error

			// connect to proxy address (optionally using TLS)
			if flagTLS {
				proxy, err = tls.Dial("tcp", target, insecureConfig)
			} else {
				proxy, err = net.Dial("tcp", target)
			}

			if err != nil {
				log.Print(err)
				inject.Close()
				c.Close()
				return
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
