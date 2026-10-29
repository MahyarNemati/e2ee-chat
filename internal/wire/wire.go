// Package wire is the byte-level encoding of everything the relay forwards.
//
// The encoding is deliberately explicit rather than reflective: the ratchet
// header's exact bytes are fed to the AEAD as associated data, so "what the
// header is" has to be one unambiguous thing, not whatever a struct tag
// happened to produce today.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
)

// Magic and Version prefix every envelope.
const (
	Magic   = "E2EE"
	Version = 1
)

// ErrMalformed is returned for any input that does not parse. Callers must not
// distinguish it from a decryption failure when reporting to a peer.
var ErrMalformed = errors.New("wire: malformed message")

// MessageType distinguishes the first message of a session from the rest.
type MessageType uint8

// The two message types.
const (
	TypePreKey MessageType = 1 // carries the X3DH initial message
	TypeNormal MessageType = 2
)

// HeaderLen is the fixed size of a ratchet header: the sender's current ratchet
// public key, the length of the previous sending chain, and the message number.
const HeaderLen = primitives.KeyLen + 4 + 4

// Header is the double ratchet header. Every byte of it is authenticated by the
// message's AEAD tag, so a relay cannot renumber or reroute a message.
type Header struct {
	RatchetKey primitives.PublicKey
	// PreviousChainLength is N for the last message of the previous sending
	// chain; it tells the recipient how many keys to skip when the DH ratchet
	// steps.
	PreviousChainLength uint32
	// Number is this message's index within the current sending chain.
	Number uint32
}

// Marshal encodes a header.
func (h Header) Marshal() []byte {
	out := make([]byte, 0, HeaderLen)
	out = append(out, h.RatchetKey[:]...)
	out = binary.BigEndian.AppendUint32(out, h.PreviousChainLength)
	return binary.BigEndian.AppendUint32(out, h.Number)
}

// ParseHeader decodes a header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) != HeaderLen {
		return Header{}, fmt.Errorf("%w: header is %d bytes, want %d", ErrMalformed, len(b), HeaderLen)
	}
	var h Header
	copy(h.RatchetKey[:], b[:primitives.KeyLen])
	h.PreviousChainLength = binary.BigEndian.Uint32(b[primitives.KeyLen : primitives.KeyLen+4])
	h.Number = binary.BigEndian.Uint32(b[primitives.KeyLen+4:])
	return h, nil
}

// Message is a ratchet header with its ciphertext.
type Message struct {
	Header     Header
	Ciphertext []byte
}

// Envelope is one unit of traffic. The relay sees exactly this and nothing
// more: the type byte, public keys, two key ids and an opaque ciphertext.
type Envelope struct {
	Type MessageType
	// The following four fields are present only on TypePreKey envelopes.
	IdentityKey     primitives.PublicKey
	EphemeralKey    primitives.PublicKey
	SignedPreKeyID  uint32
	OneTimePreKeyID uint32

	Message Message
}

// Marshal encodes an envelope.
func (e Envelope) Marshal() []byte {
	out := make([]byte, 0, 6+2*primitives.KeyLen+8+HeaderLen+len(e.Message.Ciphertext))
	out = append(out, Magic...)
	out = append(out, Version, byte(e.Type))
	if e.Type == TypePreKey {
		out = append(out, e.IdentityKey[:]...)
		out = append(out, e.EphemeralKey[:]...)
		out = binary.BigEndian.AppendUint32(out, e.SignedPreKeyID)
		out = binary.BigEndian.AppendUint32(out, e.OneTimePreKeyID)
	}
	out = append(out, e.Message.Header.Marshal()...)
	return append(out, e.Message.Ciphertext...)
}

// ParseEnvelope decodes an envelope, rejecting anything short, mislabelled or
// of the wrong version.
func ParseEnvelope(b []byte) (Envelope, error) {
	const prefix = len(Magic) + 2
	if len(b) < prefix {
		return Envelope{}, fmt.Errorf("%w: %d bytes", ErrMalformed, len(b))
	}
	if !primitives.ConstantTimeEqual(b[:len(Magic)], []byte(Magic)) {
		return Envelope{}, fmt.Errorf("%w: bad magic", ErrMalformed)
	}
	if b[len(Magic)] != Version {
		return Envelope{}, fmt.Errorf("%w: unsupported version %d", ErrMalformed, b[len(Magic)])
	}

	e := Envelope{Type: MessageType(b[len(Magic)+1])}
	rest := b[prefix:]
	switch e.Type {
	case TypePreKey:
		const n = 2*primitives.KeyLen + 8
		if len(rest) < n {
			return Envelope{}, fmt.Errorf("%w: truncated prekey fields", ErrMalformed)
		}
		copy(e.IdentityKey[:], rest[:primitives.KeyLen])
		copy(e.EphemeralKey[:], rest[primitives.KeyLen:2*primitives.KeyLen])
		e.SignedPreKeyID = binary.BigEndian.Uint32(rest[2*primitives.KeyLen : 2*primitives.KeyLen+4])
		e.OneTimePreKeyID = binary.BigEndian.Uint32(rest[2*primitives.KeyLen+4 : n])
		rest = rest[n:]
	case TypeNormal:
	default:
		return Envelope{}, fmt.Errorf("%w: unknown type %d", ErrMalformed, e.Type)
	}

	if len(rest) < HeaderLen+primitives.AEADTagLen {
		return Envelope{}, fmt.Errorf("%w: truncated ratchet message", ErrMalformed)
	}
	h, err := ParseHeader(rest[:HeaderLen])
	if err != nil {
		return Envelope{}, err
	}
	e.Message = Message{Header: h, Ciphertext: rest[HeaderLen:]}
	return e, nil
}
