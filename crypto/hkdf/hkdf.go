package hkdf

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

const ExtractOutputLength = 32

func Extract(secret, salt []byte) [ExtractOutputLength]byte {
	var key [ExtractOutputLength]byte

	copy(key[:], hkdf.Extract(sha256.New, secret[:], salt))

	return key
}
