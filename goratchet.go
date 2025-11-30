// Package goratchet provides a high-level interface for the Double Ratchet algorithm.
package goratchet

import "github.com/othonhugo/goratchet/pkg/doubleratchet"

// DoubleRatchet represents a Double Ratchet session.
type DoubleRatchet = doubleratchet.DoubleRatchet

// CipheredMessage represents an encrypted message.
type CipheredMessage = doubleratchet.CipheredMessage

// UncipheredMessage represents a decrypted message.
type UncipheredMessage = doubleratchet.UncipheredMessage

// New creates a new DoubleRatchet session.
func New(localPri, remotePub []byte) (DoubleRatchet, error) {
	return doubleratchet.New(localPri, remotePub, nil)
}

// Deserialize restores a session from a byte slice.
func Deserialize(data []byte) (DoubleRatchet, error) {
	return doubleratchet.Deserialize(data)
}
