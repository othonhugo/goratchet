package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	// ErrCiphertextTooShort is returned when the ciphertext is too short to contain a valid nonce.
	ErrCiphertextTooShort = errors.New("crypto: ciphertext too short")
)

// Encrypt uses the Message Key to encrypt plaintext with associated data.
func Encrypt(mk MessageKey, plaintext, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(mk[:])

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, ad)

	return append(nonce, ciphertext...), nil
}

// Decrypt uses the Message Key to decrypt ciphertext with associated data.
func Decrypt(mk MessageKey, ciphertextWithNonce, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(mk[:])

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	if len(ciphertextWithNonce) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := ciphertextWithNonce[:nonceSize], ciphertextWithNonce[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, ad)
}
