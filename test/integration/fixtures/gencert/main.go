// Command gencert writes a self-signed certificate for the integration
// stack's TLS proxy.
//
// It exists so that no private key is committed to this repository. A test key
// is harmless in principle, but a security product that ships a .pem in its
// own tree invites exactly one question in a review, and "it's only for tests"
// is a worse answer than not having it. Generating it at test time also keeps
// the stack free of a cert-generating container image.
//
// Go rather than openssl: nginx:alpine has no openssl binary, and the host
// having one is not something a test suite should assume.
//
// Usage: go run ./test/integration/fixtures/gencert <out-dir> <ip>
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gencert <out-dir> <ip>")
		os.Exit(2)
	}
	outDir, ip := os.Args[1], os.Args[2]
	if err := run(outDir, ip); err != nil {
		fmt.Fprintln(os.Stderr, "gencert:", err)
		os.Exit(1)
	}
}

func run(outDir, ip string) error {
	addr := net.ParseIP(ip)
	if addr == nil {
		return fmt.Errorf("invalid IP %q", ip)
	}
	// #nosec G703 -- outDir is an argument to a build-time fixture generator
	// invoked by the Makefile. Writing where it is told is the whole job.
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	// Deliberately self-signed and deliberately short-lived: the point of the
	// fixture is a certificate that fails verification the way a real
	// hand-rolled proxy certificate does.
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ray-guard-integration-tls-proxy"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{addr},
		DNSNames:              []string{"tls-proxy"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certPath := filepath.Join(outDir, "cert.pem")
	if err := writePEM(certPath, 0o644, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	keyPath := filepath.Join(outDir, "key.pem")
	if err := writePEM(keyPath, 0o600, &pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s (self-signed, 90 days, IP SAN %s)\n", certPath, keyPath, ip)
	return nil
}

func writePEM(path string, perm os.FileMode, block *pem.Block) error {
	// #nosec G304,G703 -- see above: a fixture generator writing to the
	// directory it was given.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, block); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
