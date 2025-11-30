package doubleratchet

import (
	"crypto/ecdh"
	"encoding/json"

	"github.com/othonhugo/goratchet/pkg/crypto"
)

// Deserialize restores a session from a byte slice.
func Deserialize(data []byte) (*doubleRatchet, error) {
	var state State

	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	localPri, err := ecdh.P256().NewPrivateKey(state.LocalPri)

	if err != nil {
		return nil, err
	}

	remotePub, err := ecdh.P256().NewPublicKey(state.RemotePub)

	if err != nil {
		return nil, err
	}

	d := &doubleRatchet{
		rootKey:      state.RootKey,
		sendChainKey: state.SendChainKey,
		recvChainKey: state.RecvChainKey,
		sendN:        state.SendN,
		recvN:        state.RecvN,
		prevN:        state.PrevN,
		dh: diffieHellmanRatchet{
			localPrivateKey: localPri,
			remotePublicKey: remotePub,
		},
		skippedMessageKeys: make(map[headerID]crypto.MessageKey),
	}

	for _, sk := range state.SkippedKeys {
		d.skippedMessageKeys[sk.Header.key()] = sk.Key
	}

	return d, nil
}
