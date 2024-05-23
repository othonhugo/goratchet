package aes

import "crypto/cipher"

func Encrypt(cipher cipher.AEAD, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonceSize
	}

	return cipher.Seal(nil, nonce, plaintext, additionalData), nil
}

func Decrypt(cipher cipher.AEAD, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonceSize
	}

	return cipher.Open(nil, nonce, ciphertext, additionalData)
}
