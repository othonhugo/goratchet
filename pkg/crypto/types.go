// Package crypto defines cryptographic key types used in the Double Ratchet algorithm.
package crypto

const (
	// MessageKeySize is the size of the message key in bytes (32 bytes for AES-256).
	MessageKeySize = 32

	// ChainKeySize is the size of the chain key in bytes (32 bytes).
	ChainKeySize = 32
)

// MessageKey is the key used to encrypt/decrypt a specific message.
type MessageKey [MessageKeySize]byte

// ChainKey is the key used to derive future ChainKeys and MessageKeys.
type ChainKey [ChainKeySize]byte
