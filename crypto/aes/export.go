package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const NonceSize = 12

var (
	NewCipher = aes.NewCipher
	NewGCM    = cipher.NewGCM

	ErrInvalidNonceSize = fmt.Errorf("aes: nonce size must be %d bytes", NonceSize)
)
