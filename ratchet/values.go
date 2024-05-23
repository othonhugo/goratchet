package ratchet

type CipheredMessage struct {
	Nonce, Ciphertext, Salt, PublicKey []byte
}

type UncipheredMessage struct {
	Plaintext []byte
}
