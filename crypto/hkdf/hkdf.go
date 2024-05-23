package hkdf

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

func Extract(secret, salt []byte) []byte {
	return hkdf.Extract(sha256.New, secret, salt)
}
