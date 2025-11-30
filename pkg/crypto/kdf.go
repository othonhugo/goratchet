package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// DeriveRK performs the KDF for the Root Key.
func DeriveRK(rk ChainKey, dhOut []byte) (ChainKey, ChainKey) {
	keys := DeriveHKDF(dhOut, rk[:], []byte("DoubleRatchet-Root"), 64)

	var nextRk, nextCk ChainKey

	copy(nextRk[:], keys[0:32])
	copy(nextCk[:], keys[32:64])

	return nextRk, nextCk
}

// DeriveCK performs the KDF for the Chain Key.
func DeriveCK(ck ChainKey) (ChainKey, MessageKey) {
	// Message Key derivation
	mac := hmac.New(sha256.New, ck[:])

	mac.Write([]byte{0x01})
	mkBytes := mac.Sum(nil)

	var mk MessageKey

	copy(mk[:], mkBytes)

	// Next Chain Key derivation
	mac.Reset()
	mac.Write([]byte{0x02})

	ckBytes := mac.Sum(nil)

	var nextCk ChainKey

	copy(nextCk[:], ckBytes)

	return nextCk, mk
}

// DeriveHKDF implements a simple HKDF-SHA256 expansion.
func DeriveHKDF(secret, salt, info []byte, length int) []byte {
	// Extract
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}

	mac := hmac.New(sha256.New, salt)

	mac.Write(secret)
	prk := mac.Sum(nil)

	// Expand
	var okm []byte
	var t []byte

	counter := byte(1)

	mac = hmac.New(sha256.New, prk)

	for len(okm) < length {
		mac.Reset()
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})

		t = mac.Sum(nil)
		okm = append(okm, t...)

		counter++
	}

	return okm[:length]
}
