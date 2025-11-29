package doubleratchet

import (
	"crypto/ecdh"
	"crypto/rand"
)

type diffieHellmanRatchet struct {
	localPrivateKey *ecdh.PrivateKey
	remotePublicKey *ecdh.PublicKey
}

func (dh *diffieHellmanRatchet) refresh() error {
	pri, err := ecdh.P256().GenerateKey(rand.Reader)

	if err != nil {
		return err
	}

	dh.localPrivateKey = pri

	return nil
}

func (dh *diffieHellmanRatchet) exchange(remotePub *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := dh.localPrivateKey.ECDH(remotePub)

	if err != nil {
		return nil, err
	}

	dh.remotePublicKey = remotePub

	return sharedSecret, nil
}
