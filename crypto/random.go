package crypto

import (
	"crypto/rand"
	"errors"
)

var ErrInvalidRandomSize = errors.New("crypto: Random size must be greater than zero")

func Random(size int) ([]byte, error) {
	if size < 0 {
		return nil, ErrInvalidRandomSize
	}

	b := make([]byte, size)

	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}
