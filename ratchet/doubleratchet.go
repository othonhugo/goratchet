package ratchet

import (
	"github.com/othonhugo/doubleratchet/crypto/ecdh"
)

type DoubleRatchet struct {
	dh diffieHellmanRatchet

	recv symmetricKeyRatchet
	send symmetricKeyRatchet
}

func (d *DoubleRatchet) Init(localPri *ecdh.PrivateKey, remotePub *ecdh.PublicKey) error {
	d.dh.localPrivateKey = localPri

	sharedSecret, err := d.dh.exchange(remotePub)

	if err != nil {
		return err
	}

	d.send.updateRootKey(sharedSecret, nil)
	d.recv.updateRootKey(sharedSecret, nil)

	d.send.updateChainKey(sharedSecret, nil)
	d.recv.updateChainKey(sharedSecret, nil)

	return nil
}

func (d *DoubleRatchet) Send(plaintext, salt []byte) (CipheredMessage, error) {
	d.dh.refreshPrivateKey()

	sharedSecret, err := d.dh.exchange(d.dh.remotePublicKey)

	if err != nil {
		return CipheredMessage{}, err
	}

	d.send.updateChainKey(sharedSecret, salt)

	nonce, ciphertext, err := d.send.encrypt(plaintext)

	if err != nil {
		return CipheredMessage{}, err
	}

	return CipheredMessage{
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Salt:       salt,
		PublicKey:  d.dh.localPrivateKey.PublicKey().Bytes(),
	}, nil
}

func (d *DoubleRatchet) Receive(ciphered CipheredMessage) (UncipheredMessage, error) {
	remotePub, err := ecdh.UnmarshalPublicKey(ciphered.PublicKey)

	if err != nil {
		return UncipheredMessage{}, err
	}

	sharedSecret, err := d.dh.exchange(remotePub)

	if err != nil {
		return UncipheredMessage{}, err
	}

	d.recv.updateChainKey(sharedSecret, ciphered.Salt)

	plaintext, err := d.recv.decrypt(ciphered.Nonce, ciphered.Ciphertext)

	if err != nil {
		return UncipheredMessage{}, err
	}

	return UncipheredMessage{Plaintext: plaintext}, nil
}
