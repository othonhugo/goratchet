package ratchet

import (
	"github.com/othonhugo/doubleratchet/crypto"
	"github.com/othonhugo/doubleratchet/crypto/aes"
	"github.com/othonhugo/doubleratchet/crypto/hkdf"
)

type state struct {
	root, chain [hkdf.ExtractOutputLength]byte
}

type symmetricKeyRatchet struct {
	keys state
}

func (sym *symmetricKeyRatchet) updateRootKey(sharedSecret, salt []byte) {
	sym.keys.root = hkdf.Extract(sharedSecret, salt)
}

func (sym *symmetricKeyRatchet) updateChainKey(sharedSecret, salt []byte) {
	var key []byte

	if len(sym.keys.chain) > 0 {
		key = sym.keys.chain[:]
	} else {
		key = sym.keys.root[:]
	}

	sym.keys.chain = hkdf.Extract(append(key, sharedSecret...), salt)
}

func (sym *symmetricKeyRatchet) encrypt(plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(sym.keys.chain[:])

	if err != nil {
		return nil, nil, err
	}

	cipher, err := aes.NewGCM(block)

	if err != nil {
		return nil, nil, err
	}

	nonce, err := crypto.Random(aes.NonceSize)

	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := aes.Encrypt(cipher, nonce, plaintext, nil)

	if err != nil {
		return nil, nil, err
	}

	return nonce, ciphertext, nil
}

func (sym *symmetricKeyRatchet) decrypt(nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sym.keys.chain[:])

	if err != nil {
		return nil, err
	}

	cipher, err := aes.NewGCM(block)

	if err != nil {
		return nil, err
	}

	return aes.Decrypt(cipher, nonce, ciphertext, nil)
}
