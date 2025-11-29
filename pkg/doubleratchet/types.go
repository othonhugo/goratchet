package doubleratchet

const (
	// MaxSkip is the maximum number of message keys that can be skipped in a single chain.
	MaxSkip = 1000
)

// Header contains the message header information for Double Ratchet.
type Header struct {
	DH []byte // The sender's current public key
	N  uint32 // The message number in the current chain
	PN uint32 // The length of the previous sending chain
}

// CipheredMessage represents an encrypted message with its header.
type CipheredMessage struct {
	Header     Header
	Ciphertext []byte
}

// UncipheredMessage represents a decrypted message.
type UncipheredMessage struct {
	Plaintext []byte
}

// headerID is a unique identifier for a message key based on the header information.
type headerID struct {
	dh    string
	n, pn uint32
}

func (h Header) key() headerID {
	return headerID{
		dh: string(h.DH),
		n:  h.N,
		pn: h.PN,
	}
}
