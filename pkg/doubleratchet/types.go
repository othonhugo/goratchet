package doubleratchet

// DoubleRatchet defines the interface for managing a Double Ratchet session, enabling secure message exchange.
type DoubleRatchet interface {
	// Send encrypts the given plaintext with associated data ad and returns a CipheredMessage.
	Send(plaintext, ad []byte) (CipheredMessage, error)

	// Receive decrypts the given CipheredMessage with associated data ad and returns an UncipheredMessage.
	Receive(msg CipheredMessage, ad []byte) (UncipheredMessage, error)

	// Serialize marshals the session state to a byte slice.
	Serialize() ([]byte, error)
}

// State represents the serializable state of a Double Ratchet session.
type State struct {
	RootKey      [32]byte
	SendChainKey [32]byte
	RecvChainKey [32]byte
	SendN        uint32
	RecvN        uint32
	PrevN        uint32
	SkippedKeys  []SkippedMessageKey
	LocalPri     []byte
	RemotePub    []byte
}

// SkippedMessageKey represents a single skipped message key for serialization.
type SkippedMessageKey struct {
	Header Header
	Key    [32]byte
}

// Header contains the message header information for Double Ratchet.
type Header struct {
	DH []byte // The sender's current public key
	N  uint32 // The message number in the current chain
	PN uint32 // The length of the previous sending chain
}

func (h Header) key() headerID {
	return headerID{
		dh: string(h.DH),
		n:  h.N,
		pn: h.PN,
	}
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
