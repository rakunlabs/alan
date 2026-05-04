package alan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// alpnProtocol is the ALPN protocol identifier for alan peers.
	alpnProtocol = "alan/1"
	// pskPrefix is used to derive a PSK verifier from the shared key.
	pskPrefix = "github.com/rakunlabs/alan/psk"
)

// derivePSKHash derives a 32-byte hash from the shared key for PSK verification via ALPN trick.
func derivePSKHash(sharedKey []byte) [32]byte {
	return sha256.Sum256(append([]byte(pskPrefix), sharedKey...))
}

// newServerTLSConfig creates a TLS config for the QUIC listener.
// If sharedKey is non-nil, VerifyPeerCertificate is set to validate the PSK.
func newServerTLSConfig(cert tls.Certificate, sharedKey []byte) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpnProtocol},
		ClientAuth:   tls.RequireAnyClientCert,
		// We don't verify the actual certificate chain — peers use ephemeral self-signed certs.
		// Security comes from the pre-shared key embedded in the cert's Subject (if enabled).
		InsecureSkipVerify: true,
	}

	if len(sharedKey) > 0 {
		pskHash := derivePSKHash(sharedKey)
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no client certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse cert: %w", err)
			}
			// Check that the peer's cert has the expected Organization field (PSK proof)
			if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != fmt.Sprintf("%x", pskHash) {
				return fmt.Errorf("PSK mismatch: peer not in cluster")
			}
			return nil
		}
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
		pskHash := derivePSKHash(sharedKey)
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse cert: %w", err)
			}
			if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != fmt.Sprintf("%x", pskHash) {
				return fmt.Errorf("PSK mismatch: peer not in cluster")
			}
			return nil
		}
	}

	return cfg
}

// generatePSKCert creates a self-signed cert that embeds the PSK hash in Organization field.
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
		pskHash := derivePSKHash(sharedKey)
		subject.Organization = []string{fmt.Sprintf("%x", pskHash)}
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

// newQUICConfig creates the QUIC config for connections.
func newQUICConfig(keepAlive time.Duration, maxIdle time.Duration) *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  maxIdle,
		KeepAlivePeriod: keepAlive,
		// Allow many concurrent streams for parallel sends
		MaxIncomingStreams: 1024,
		// Large receive windows for big data transfers
		MaxStreamReceiveWindow:     64 * 1024 * 1024,  // 64 MB
		MaxConnectionReceiveWindow: 128 * 1024 * 1024, // 128 MB
	}
}

// Stream framing: each message on a QUIC stream is:
//   [MsgType:1][PayloadLen:4 big-endian][Payload:N]

// writeStreamMessage writes a framed message to a QUIC stream.
func writeStreamMessage(w io.Writer, msgType byte, payload []byte) error {
	header := make([]byte, 5)
	header[0] = msgType
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}
	return nil
}

// readStreamMessage reads a framed message from a QUIC stream.
func readStreamMessage(r io.Reader) (msgType byte, payload []byte, err error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}

	msgType = header[0]
	length := binary.BigEndian.Uint32(header[1:5])

	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return msgType, payload, nil
}
