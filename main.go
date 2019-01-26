// A simple static server for testing small websites
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/handlers"
)

// Server is a wrapper around net.httpd
type Server struct {
	low, high *http.Server
}

func buildRedirect(httpsAddr string, req *http.Request) string {
	var host string
	if strings.Contains(req.Host, ":") {
		host, _, _ = net.SplitHostPort(req.Host)
	} else {
		host = req.Host
	}

	if strings.Contains(httpsAddr, ":") {
		_, port, _ := net.SplitHostPort(httpsAddr)
		return "https://" + host + ":" + port + req.URL.String()
	}
	return "https://" + host + req.URL.String()
}

// Builds self signed certs for debug
func buildDebugCerts() []tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Can't create private key", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatal("Can't create serial number", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"localhost"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal("Can't create certificate: ", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal("Can't convert X509 cert/key to tls Cert: ", err)
	}

	return []tls.Certificate{tlsCert}
}

// Create creates a new server
func create(low, high, wwwroot string) *Server {

	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		Certificates: buildDebugCerts(),
	}

	return &Server{
		low: &http.Server{
			Addr:         low,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Connection", "close")
				url := buildRedirect(high, req)
				log.Printf("Redirecting to %s", url)
				http.Redirect(w, req, url, http.StatusMovedPermanently)
			}),
		},
		high: &http.Server{
			Addr:         high,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSConfig:    tlsConfig,
			Handler:      handlers.CombinedLoggingHandler(os.Stdout, http.FileServer(http.Dir(wwwroot))),
		},
	}
}

// Start starts a server
func (s *Server) start() {
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)

		// Wait for signals
		<-sigint

		log.Printf("Shutting down")
		s.low.Shutdown(context.Background())
		s.high.Shutdown(context.Background())
		close(idleConnsClosed)
	}()

	go func() {
		log.Printf("HTTP server listening on %s", s.low.Addr)
		if err := s.low.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("HTTP server %s error ListenAndServe: %v", s.low.Addr, err)
		}

	}()

	go func() {
		log.Printf("HTTPS server listening on %s", s.high.Addr)
		if err := s.high.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Printf("HTTPS server %s error ListenAndServeTLS: %v", s.high.Addr, err)
		}

	}()

	// Wait for shutdown
	<-idleConnsClosed
}

func main() {

	args := os.Args[1:]

	if len(args) != 3 {
		log.Fatal("Should have exactly three arguments: http port, https port, and root folder")
	}

	s := create(args[0], args[1], args[2])
	s.start()
}
