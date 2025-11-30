package goratchet

import "github.com/othonhugo/goratchet/pkg/doubleratchet"

type DoubleRatchet = doubleratchet.DoubleRatchet
type CipheredMessage = doubleratchet.CipheredMessage
type UncipheredMessage = doubleratchet.UncipheredMessage

// New creates a new DoubleRatchet session.
func New(localPri []byte, remotePub []byte) (doubleratchet.DoubleRatchet, error) {
	return doubleratchet.New(localPri, remotePub, nil)
}

// Deserialize restores a session from a byte slice.
func Deserialize(data []byte) (doubleratchet.DoubleRatchet, error) {
	return doubleratchet.Deserialize(data)
}
