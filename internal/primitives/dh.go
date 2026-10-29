// Package primitives wraps the small set of cryptographic building blocks this
// project needs: X25519 Diffie-Hellman, XEdDSA signatures over Montgomery keys,
// HKDF/HMAC key derivation and ChaCha20-Poly1305 authenticated encryption.
//
// Nothing here is novel. The point of the package is that every primitive is
// checked against its published test vectors (see vectors_test.go) before the
// protocol layers above are allowed to depend on it.
package primitives

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// KeyLen is the size of an X25519 private or public key.
const KeyLen = 32

// ErrInvalidKey is returned when a public key is not usable for Diffie-Hellman:
// either it is not a canonical field element or it is a low-order point, which
// would force the shared secret to a value the peer can predict.
var ErrInvalidKey = errors.New("primitives: invalid public key")

type (
	// PrivateKey is an X25519 scalar, stored unclamped as RFC 7748 specifies;
	// clamping happens at the point of use.
	PrivateKey [KeyLen]byte
	// PublicKey is an X25519 u-coordinate.
	PublicKey [KeyLen]byte
	// SharedSecret is the raw output of X25519, never used as a key directly.
	SharedSecret [KeyLen]byte
)

// KeyPair is an X25519 key pair. The same pair is used for Diffie-Hellman and,
// via XEdDSA, for signatures -- which is what lets a Signal-style identity key
// serve both roles.
type KeyPair struct {
	Private PrivateKey
	Public  PublicKey
}

// GenerateKeyPair draws a fresh X25519 key pair from r. Pass nil for
// crypto/rand.Reader.
func GenerateKeyPair(r io.Reader) (KeyPair, error) {
	if r == nil {
		r = rand.Reader
	}
	var kp KeyPair
	if _, err := io.ReadFull(r, kp.Private[:]); err != nil {
		return KeyPair{}, fmt.Errorf("primitives: read randomness: %w", err)
	}
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, fmt.Errorf("primitives: derive public key: %w", err)
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// PublicFromPrivate recomputes the public key for a stored private key.
func PublicFromPrivate(priv PrivateKey) (PublicKey, error) {
	var pub PublicKey
	out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, fmt.Errorf("primitives: derive public key: %w", err)
	}
	copy(pub[:], out)
	return pub, nil
}

// DH computes the X25519 shared secret. curve25519.X25519 already rejects the
// low-order points that would make the output all-zero (RFC 7748 section 6.1),
// so an error here means the peer sent a degenerate key.
func DH(priv PrivateKey, pub PublicKey) (SharedSecret, error) {
	var ss SharedSecret
	out, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return ss, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	copy(ss[:], out)
	return ss, nil
}

// IsZero reports whether a public key is the all-zero value, which no honest
// peer will ever send.
func (p PublicKey) IsZero() bool {
	var zero PublicKey
	return ConstantTimeEqual(p[:], zero[:])
}
