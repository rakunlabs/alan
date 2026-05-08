package alan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// alpnProtocol is the ALPN protocol identifier negotiated during the
	// QUIC/TLS handshake. Bumping this is the supported way to make a
	// breaking wire-format change: peers running a different ALPN simply
	// fail the handshake and never become members.
	alpnProtocol = "alan/3"
	// pskPrefix is mixed into the PSK hash so the same Key cannot be reused
	// to authenticate against any other system that hashes the same secret.
	pskPrefix = "github.com/rakunlabs/alan/psk"
)

// derivePSKHash derives a 32-byte fingerprint of sharedKey, used to bind a
// peer's TLS certificate to cluster membership.
func derivePSKHash(sharedKey []byte) [32]byte {
	return sha256.Sum256(append([]byte(pskPrefix), sharedKey...))
}

// pskHashHex returns the lowercase-hex encoding of the PSK fingerprint that
// gets embedded in TLS certificates and compared during VerifyPeerCertificate.
func pskHashHex(sharedKey []byte) string {
	h := derivePSKHash(sharedKey)
	return hex.EncodeToString(h[:])
}

// newServerTLSConfig creates a TLS config for the QUIC listener.
// If sharedKey is non-nil, VerifyPeerCertificate enforces PSK admission.
func newServerTLSConfig(cert tls.Certificate, sharedKey []byte) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpnProtocol},
		ClientAuth:   tls.RequireAnyClientCert,
		// Chain validation is intentionally disabled: peers use ephemeral
		// self-signed certificates. Trust is established by VerifyPeerCertificate
		// below (when a shared key is configured).
		InsecureSkipVerify: true,
	}

	if len(sharedKey) > 0 {
		expected := pskHashHex(sharedKey)
		cfg.VerifyPeerCertificate = makePSKVerifier(expected, "client")
	}

	return cfg
}

// newClientTLSConfig creates a TLS config for dialing QUIC connections.
func newClientTLSConfig(cert tls.Certificate, sharedKey []byte) *tls.Config {
	cfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{alpnProtocol},
		InsecureSkipVerify: true,
	}

	if len(sharedKey) > 0 {
		expected := pskHashHex(sharedKey)
		cfg.VerifyPeerCertificate = makePSKVerifier(expected, "server")
	}

	return cfg
}

// makePSKVerifier returns a TLS VerifyPeerCertificate callback that checks the
// peer cert's Subject.Organization equals the expected PSK fingerprint, using
// a constant-time comparison.
func makePSKVerifier(expected, role string) func([][]byte, [][]*x509.Certificate) error {
	expectedBytes := []byte(expected)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no %s certificate", role)
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse cert: %w", err)
		}
		if len(cert.Subject.Organization) == 0 {
			return fmt.Errorf("PSK mismatch: peer not in cluster")
		}
		got := []byte(cert.Subject.Organization[0])
		if subtle.ConstantTimeCompare(got, expectedBytes) != 1 {
			return fmt.Errorf("PSK mismatch: peer not in cluster")
		}
		return nil
	}
}

// generatePSKCert creates a self-signed certificate that embeds the PSK
// fingerprint in Subject.Organization. The private key never leaves memory.
func generatePSKCert(sharedKey []byte) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	subject := pkix.Name{CommonName: "alan-peer"}
	if len(sharedKey) > 0 {
		subject.Organization = []string{pskHashHex(sharedKey)}
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// newQUICConfig builds the QUIC config for both server and client roles.
// Stream/connection windows scale with maxMessageSize so flow control is
// large enough not to throttle typical messages, but never below 64 MiB so
// streaming workloads have headroom.
func newQUICConfig(keepAlive, maxIdle time.Duration, maxMessageSize int64) *quic.Config {
	const minWindow = uint64(64 * 1024 * 1024) // 64 MiB
	streamWindow := minWindow
	if maxMessageSize > 0 && uint64(maxMessageSize) > streamWindow {
		streamWindow = uint64(maxMessageSize)
	}
	connWindow := streamWindow * 2

	return &quic.Config{
		MaxIdleTimeout:             maxIdle,
		KeepAlivePeriod:            keepAlive,
		MaxIncomingStreams:         1024,
		MaxStreamReceiveWindow:     streamWindow,
		MaxConnectionReceiveWindow: connWindow,
	}
}
