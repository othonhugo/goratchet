package ratchet

import (
	"github.com/othonhugo/doubleratchet/crypto/ecdh"
)

type diffieHellmanRatchet struct {
	localPrivateKey *ecdh.PrivateKey
	remotePublicKey *ecdh.PublicKey
}

func (dh *diffieHellmanRatchet) refreshPrivateKey() error {
	pri, err := ecdh.GeneratePrivateKey()

	if err != nil {
		return err
	}

	dh.localPrivateKey = pri

	return nil
}

func (dh *diffieHellmanRatchet) exchange(remotePub *ecdh.PublicKey) ([]byte, error) {
	if remotePub == nil {
		return nil, ErrRemotePublicKeyIsNil
	}

	if dh.localPrivateKey == nil {
		return nil, ErrLocalPrivateKeyIsNil
	}

	sharedSecret, err := dh.localPrivateKey.ECDH(remotePub)

	if err != nil {
		return nil, err
	}

	dh.remotePublicKey = remotePub

	return sharedSecret, nil
}
