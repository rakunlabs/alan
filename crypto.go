package alan

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// nonceSize is the size of the nonce used for XChaCha20-Poly1305
const nonceSize = chacha20poly1305.NonceSizeX // 24 bytes

// encrypt encrypts plaintext using XChaCha20-Poly1305.
// Returns: [nonce:24][ciphertext+tag]
// The nonce is randomly generated and prepended to the ciphertext.
func (a *Alan) encrypt(plaintext []byte) ([]byte, error) {
	if a.aead == nil {
		return nil, ErrSecurityNotEnabled
	}

	// Generate random nonce
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal appends the encrypted data to the nonce
	// Result: [nonce][ciphertext+tag]
	ciphertext := a.aead.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// decrypt decrypts ciphertext using XChaCha20-Poly1305.
// Expects: [nonce:24][ciphertext+tag]
// Returns the decrypted plaintext.
func (a *Alan) decrypt(data []byte) ([]byte, error) {
	if a.aead == nil {
		return nil, ErrSecurityNotEnabled
	}

	if len(data) < nonceSize+a.aead.Overhead() {
		return nil, ErrMessageTooShort
	}

	// Extract nonce and ciphertext
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// Decrypt and verify
	plaintext, err := a.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// processOutgoing encrypts data if security is enabled, otherwise returns as-is
func (a *Alan) processOutgoing(data []byte) ([]byte, error) {
	if a.aead == nil {
		return data, nil
	}
	return a.encrypt(data)
}

// processIncoming decrypts data if security is enabled, otherwise returns as-is
func (a *Alan) processIncoming(data []byte) ([]byte, error) {
	if a.aead == nil {
		return data, nil
	}
	return a.decrypt(data)
}
