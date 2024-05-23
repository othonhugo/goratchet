package doubleratchet

import (
	"github.com/othonhugo/doubleratchet/crypto/ecdh"
	"github.com/othonhugo/doubleratchet/ratchet"
)

type DoubleRatchet interface {
	Send(plaintext, salt []byte) (ratchet.CipheredMessage, error)
	Receive(ciphered ratchet.CipheredMessage) (ratchet.UncipheredMessage, error)
}

func New(localPri, remotePub []byte) (DoubleRatchet, error) {
	pri, err := ecdh.UnmarshalPrivateKey(localPri)

	if err != nil {
		return nil, err
	}

	pub, err := ecdh.UnmarshalPublicKey(remotePub)

	if err != nil {
		return nil, err
	}

	d := &ratchet.DoubleRatchet{}

	if err := d.Init(pri, pub); err != nil {
		return nil, err
	}

	return d, nil
}
