package ratchet

import "errors"

var (
	ErrLocalPrivateKeyIsNil = errors.New("ratchet: local private key is Nil")
	ErrRemotePublicKeyIsNil = errors.New("ratchet: remote public key is Nil")
)
