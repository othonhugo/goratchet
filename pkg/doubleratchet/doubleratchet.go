package doubleratchet

import (
	"bytes"
	"crypto/ecdh"
	"fmt"

	"github.com/othonhugo/doubleratchet/pkg/crypto"
)

type DoubleRatchet struct {
	dh      diffieHellmanRatchet
	rootKey crypto.ChainKey

	sendChainKey crypto.ChainKey
	recvChainKey crypto.ChainKey

	sendN uint32
	recvN uint32
	prevN uint32

	skippedMessageKeys map[headerID]crypto.MessageKey
}

// New creates a new DoubleRatchet session.
func New(localPri, remotePub, salt []byte) (*DoubleRatchet, error) {
	pri, err := ecdh.P256().NewPrivateKey(localPri)

	if err != nil {
		return nil, err
	}

	pub, err := ecdh.P256().NewPublicKey(remotePub)

	if err != nil {
		return nil, err
	}

	sharedSecret, err := pri.ECDH(pub)

	if err != nil {
		return nil, err
	}

	d := &DoubleRatchet{}

	// We use a default salt or nil.
	if err := d.Init(pri, pub, sharedSecret, salt); err != nil {
		return nil, err
	}

	return d, nil
}

// Init initializes the DoubleRatchet with the given keys and shared secret.
func (d *DoubleRatchet) Init(localPri *ecdh.PrivateKey, remotePub *ecdh.PublicKey, sharedSecret, salt []byte) error {
	d.dh.localPrivateKey = localPri
	d.dh.remotePublicKey = remotePub

	d.skippedMessageKeys = make(map[headerID]crypto.MessageKey)

	// Derive distinct keys for send and receive chains to prevent reflection attacks.
	localPubBytes := localPri.PublicKey().Bytes()
	remotePubBytes := remotePub.Bytes()

	var infoSend, infoRecv []byte

	if bytes.Compare(localPubBytes, remotePubBytes) < 0 {
		// We are "Alice" (lesser key)
		infoSend = []byte("DoubleRatchet-Chain-1")
		infoRecv = []byte("DoubleRatchet-Chain-2")
	} else {
		// We are "Bob" (greater key)
		infoSend = []byte("DoubleRatchet-Chain-2")
		infoRecv = []byte("DoubleRatchet-Chain-1")
	}

	// Derive Root Key
	rk, err := crypto.DeriveHKDF(sharedSecret, salt, []byte("DoubleRatchet-Root"), 32)

	if err != nil {
		return err
	}

	copy(d.rootKey[:], rk)

	ckSend, err := crypto.DeriveHKDF(sharedSecret, salt, infoSend, 32)

	if err != nil {
		return err
	}

	copy(d.sendChainKey[:], ckSend)

	ckRecv, err := crypto.DeriveHKDF(sharedSecret, salt, infoRecv, 32)

	if err != nil {
		return err
	}

	copy(d.recvChainKey[:], ckRecv)

	return nil
}

// Send encrypts the given plaintext with associated data ad and returns a CipheredMessage.
func (d *DoubleRatchet) Send(plaintext, ad []byte) (CipheredMessage, error) {
	// Derive Message Key
	nextCk, mk := crypto.DeriveCK(d.sendChainKey)

	d.sendChainKey = nextCk

	header := Header{
		DH: d.dh.localPrivateKey.PublicKey().Bytes(),
		N:  d.sendN,
		PN: d.prevN,
	}

	d.sendN++

	ciphertext, err := crypto.Encrypt(mk, plaintext, ad)

	if err != nil {
		return CipheredMessage{}, err
	}

	return CipheredMessage{
		Header:     header,
		Ciphertext: ciphertext,
	}, nil
}

// Receive decrypts the given CipheredMessage with associated data ad and returns an UncipheredMessage.
func (d *DoubleRatchet) Receive(msg CipheredMessage, ad []byte) (UncipheredMessage, error) {
	if plaintext, err := d.trySkippedMessageKeys(msg.Header, msg.Ciphertext, ad); err == nil {
		return UncipheredMessage{Plaintext: plaintext}, nil
	}

	if !bytes.Equal(msg.Header.DH, d.dh.remotePublicKey.Bytes()) {
		if err := d.skipMessageKeys(d.recvN, msg.Header.PN); err != nil {
			return UncipheredMessage{}, err
		}

		if err := d.dhRatchet(msg.Header.DH); err != nil {
			return UncipheredMessage{}, err
		}
	}

	if err := d.skipMessageKeys(d.recvN, msg.Header.N); err != nil {
		return UncipheredMessage{}, err
	}

	nextCk, mk := crypto.DeriveCK(d.recvChainKey)

	d.recvChainKey = nextCk
	d.recvN++

	plaintext, err := crypto.Decrypt(mk, msg.Ciphertext, ad)

	if err != nil {
		return UncipheredMessage{}, err
	}

	return UncipheredMessage{Plaintext: plaintext}, nil
}

// trySkippedMessageKeys checks if there is a skipped message key for the given header and attempts to decrypt the ciphertext.
func (d *DoubleRatchet) trySkippedMessageKeys(header Header, ciphertext, ad []byte) ([]byte, error) {
	if mk, ok := d.skippedMessageKeys[header.key()]; ok {
		plaintext, err := crypto.Decrypt(mk, ciphertext, ad)

		if err != nil {
			return nil, err
		}

		delete(d.skippedMessageKeys, header.key())

		return plaintext, nil
	}

	return nil, fmt.Errorf("message key not found")
}

// skipMessageKeys derives and stores skipped message keys up to the target message number.
func (d *DoubleRatchet) skipMessageKeys(until, target uint32) error {
	if target < until {
		return fmt.Errorf("received message out of order (old)")
	}

	if target-until > MaxSkip {
		return fmt.Errorf("too many skipped messages")
	}

	for until < target {
		nextCk, mk := crypto.DeriveCK(d.recvChainKey)
		d.recvChainKey = nextCk

		header := Header{
			DH: d.dh.remotePublicKey.Bytes(),
			N:  until,
			PN: d.prevN,
		}

		d.skippedMessageKeys[header.key()] = mk

		until++
		d.recvN++
	}
	return nil
}

// dhRatchet performs a Diffie-Hellman ratchet step with the given remote public key bytes.
func (d *DoubleRatchet) dhRatchet(remotePubBytes []byte) error {
	d.prevN = d.recvN
	d.recvN = 0
	d.sendN = 0

	remotePub, err := ecdh.P256().NewPublicKey(remotePubBytes)

	if err != nil {
		return err
	}

	d.dh.remotePublicKey = remotePub

	// DH1 = DH(d.s, tr)
	dhOut1, err := d.dh.exchange(d.dh.remotePublicKey)

	if err != nil {
		return err
	}

	// RK, CKr = KDF_RK(RK, DH1)
	d.rootKey, d.recvChainKey = crypto.DeriveRK(d.rootKey, dhOut1)

	// Generate new key pair
	if err := d.dh.refresh(); err != nil {
		return err
	}

	// DH2 = DH(d.s, tr)
	dhOut2, err := d.dh.exchange(d.dh.remotePublicKey)

	if err != nil {
		return err
	}

	// RK, CKs = KDF_RK(RK, DH2)
	d.rootKey, d.sendChainKey = crypto.DeriveRK(d.rootKey, dhOut2)

	return nil
}
