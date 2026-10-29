package primitives

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// SignatureLen is the length of an XEdDSA signature, R || s.
const SignatureLen = 64

// ErrBadSignature is returned by a verification that failed.
var ErrBadSignature = errors.New("primitives: signature does not verify")

// XEdDSA (Signal's "XEdDSA and VXEdDSA Signature Schemes", revision 1) lets a
// single Montgomery key pair be used both for X25519 Diffie-Hellman and for
// Ed25519-shaped signatures. That is what makes a Signal identity key able to
// sign its own signed prekey while still being a DH key -- without it you would
// need a second identity key and a second thing for users to verify.
//
// The scheme is Ed25519 with two changes:
//
//   - the signing scalar is the X25519 private key, negated when the Edwards
//     public key it produces has its sign bit set, so that the public key can
//     always be recovered from the Montgomery u-coordinate alone;
//   - the per-signature nonce is hashed with a domain-separation prefix
//     (0xFE followed by 31 0xFF bytes) so that it can never collide with an
//     Ed25519 hash of the same key, and with 64 random bytes mixed in.

// hash1Prefix is 2^b - 1 - i for i = 1, b = 256: the XEdDSA spec's way of
// domain-separating hash_1 from plain SHA-512.
var hash1Prefix = func() []byte {
	p := make([]byte, 32)
	p[0] = 0xFE
	for i := 1; i < 32; i++ {
		p[i] = 0xFF
	}
	return p
}()

// signingKeyPair implements calculate_key_pair from the XEdDSA spec: it maps a
// Montgomery private key to the Edwards public key with sign bit 0 and the
// scalar that signs for it.
func signingKeyPair(priv PrivateKey) (*edwards25519.Point, *edwards25519.Scalar, error) {
	k, err := edwards25519.NewScalar().SetBytesWithClamping(priv[:])
	if err != nil {
		return nil, nil, fmt.Errorf("primitives: clamp private key: %w", err)
	}
	e := new(edwards25519.Point).ScalarBaseMult(k)
	enc := e.Bytes()

	a := k
	if enc[31]>>7 == 1 {
		// The Edwards public key is negative; negate the scalar so that the
		// positive point signs, and the verifier can assume sign bit 0.
		a = edwards25519.NewScalar().Negate(k)
	}
	enc[31] &= 0x7F
	pub, err := new(edwards25519.Point).SetBytes(enc)
	if err != nil {
		return nil, nil, fmt.Errorf("primitives: recover edwards public key: %w", err)
	}
	return pub, a, nil
}

// Sign produces an XEdDSA signature over message with an X25519 private key.
// Pass nil for r to use crypto/rand.
func Sign(priv PrivateKey, message []byte, r io.Reader) ([]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	pub, a, err := signingKeyPair(priv)
	if err != nil {
		return nil, err
	}

	var z [64]byte
	if _, err := io.ReadFull(r, z[:]); err != nil {
		return nil, fmt.Errorf("primitives: read randomness: %w", err)
	}

	h := sha512.New()
	h.Write(hash1Prefix)
	h.Write(a.Bytes())
	h.Write(message)
	h.Write(z[:])
	nonce, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("primitives: reduce nonce: %w", err)
	}

	rPoint := new(edwards25519.Point).ScalarBaseMult(nonce)
	rBytes, aBytes := rPoint.Bytes(), pub.Bytes()

	hs := sha512.New()
	hs.Write(rBytes)
	hs.Write(aBytes)
	hs.Write(message)
	challenge, err := edwards25519.NewScalar().SetUniformBytes(hs.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("primitives: reduce challenge: %w", err)
	}

	s := edwards25519.NewScalar().MultiplyAdd(challenge, a, nonce)

	sig := make([]byte, SignatureLen)
	copy(sig[:32], rBytes)
	copy(sig[32:], s.Bytes())
	return sig, nil
}

// Verify checks an XEdDSA signature against an X25519 public key. It returns a
// bool rather than an error so that no caller can accidentally treat a
// verification failure as success by ignoring a second return value.
func Verify(pub PublicKey, message, sig []byte) bool {
	if len(sig) != SignatureLen {
		return false
	}
	a, err := montgomeryToEdwards(pub)
	if err != nil {
		return false
	}
	// A non-canonical s would let an attacker mint a second valid encoding of
	// the same signature; SetCanonicalBytes rejects anything >= l.
	s, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}
	rBytes := sig[:32]

	hs := sha512.New()
	hs.Write(rBytes)
	hs.Write(a.Bytes())
	hs.Write(message)
	challenge, err := edwards25519.NewScalar().SetUniformBytes(hs.Sum(nil))
	if err != nil {
		return false
	}

	// R' = sB - hA, computed as h(-A) + sB.
	minusA := new(edwards25519.Point).Negate(a)
	want := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(challenge, minusA, s)
	return ConstantTimeEqual(rBytes, want.Bytes())
}

// montgomeryToEdwards maps an X25519 u-coordinate to the Edwards point with
// sign bit 0, using the birational map y = (u-1)/(u+1).
func montgomeryToEdwards(pub PublicKey) (*edwards25519.Point, error) {
	// RFC 7748 has X25519 ignore the most significant bit of a u-coordinate, so
	// mask it before insisting on a canonical field element.
	var buf [KeyLen]byte
	copy(buf[:], pub[:])
	buf[31] &= 0x7F

	u, err := new(field.Element).SetBytes(buf[:])
	if err != nil {
		return nil, fmt.Errorf("%w: u is not a canonical field element", ErrInvalidKey)
	}
	one := new(field.Element).One()
	den := new(field.Element).Add(u, one)
	if den.Equal(new(field.Element).Zero()) == 1 {
		// u = -1 is the one point the birational map does not cover.
		return nil, fmt.Errorf("%w: u = -1 has no Edwards image", ErrInvalidKey)
	}
	num := new(field.Element).Subtract(u, one)
	y := new(field.Element).Multiply(num, new(field.Element).Invert(den))

	// y.Bytes() is already 32 little-endian bytes with the top bit clear, which
	// is exactly an Edwards encoding with sign bit 0.
	p, err := new(edwards25519.Point).SetBytes(y.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: not a point on edwards25519", ErrInvalidKey)
	}
	return p, nil
}
