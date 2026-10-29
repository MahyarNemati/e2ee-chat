// Package x3dh implements the asynchronous key agreement of Signal's X3DH
// specification over Curve25519: an identity key, a signed prekey and a pool of
// one-time prekeys, published as a bundle so that a sender can establish a
// session -- and send a first message -- while the recipient is offline.
package x3dh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
)

// NoPreKey marks a bundle or initial message that used no one-time prekey,
// which happens once a recipient's pool is exhausted.
const NoPreKey uint32 = 0

var (
	// ErrBadSignature means the signed prekey was not signed by the identity
	// key in the same bundle. See Bundle.Verify for why this matters.
	ErrBadSignature = errors.New("x3dh: signed prekey signature does not verify")
	// ErrBadBundle means the bundle is structurally unusable.
	ErrBadBundle = errors.New("x3dh: malformed prekey bundle")
	// ErrUnknownPreKey means the initial message referenced a prekey the
	// recipient does not have (already consumed, or never published).
	ErrUnknownPreKey = errors.New("x3dh: unknown prekey id")
)

// signedPreKeyContext domain-separates the signed prekey signature so it can
// never be confused with a signature over anything else this key signs.
const signedPreKeyContext = "e2ee-chat/XEdDSA/signed-prekey/v1"

// SigningInput is the exact byte string covered by a signed prekey signature:
// the context string, the prekey id and the prekey itself. Binding the id as
// well as the key stops a relay from re-labelling a genuine prekey.
func SigningInput(id uint32, pub primitives.PublicKey) []byte {
	out := make([]byte, 0, len(signedPreKeyContext)+4+primitives.KeyLen)
	out = append(out, signedPreKeyContext...)
	out = binary.BigEndian.AppendUint32(out, id)
	return append(out, pub[:]...)
}

// PreKey is the public half of a one-time prekey.
type PreKey struct {
	ID        uint32               `json:"id"`
	PublicKey primitives.PublicKey `json:"public_key"`
}

// SignedPreKey is a medium-term key pair signed by the identity key.
type SignedPreKey struct {
	ID        uint32             `json:"id"`
	KeyPair   primitives.KeyPair `json:"key_pair"`
	Signature []byte             `json:"signature"`
	CreatedAt time.Time          `json:"created_at"`
}

// OneTimePreKey is a single-use key pair.
type OneTimePreKey struct {
	ID      uint32             `json:"id"`
	KeyPair primitives.KeyPair `json:"key_pair"`
}

// Account holds every private key a user owns. It never leaves the client
// except through the passphrase-encrypted keystore.
type Account struct {
	Name           string             `json:"name"`
	Identity       primitives.KeyPair `json:"identity"`
	SignedPreKey   SignedPreKey       `json:"signed_pre_key"`
	OneTimePreKeys []OneTimePreKey    `json:"one_time_pre_keys"`
	NextPreKeyID   uint32             `json:"next_pre_key_id"`
}

// NewAccount generates an identity key, a signed prekey and numOneTime one-time
// prekeys. Pass nil for r to use crypto/rand.
func NewAccount(r io.Reader, name string, numOneTime int) (*Account, error) {
	if name == "" {
		return nil, errors.New("x3dh: account name must not be empty")
	}
	identity, err := primitives.GenerateKeyPair(r)
	if err != nil {
		return nil, err
	}
	acct := &Account{Name: name, Identity: identity, NextPreKeyID: 1}
	if err := acct.RotateSignedPreKey(r); err != nil {
		return nil, err
	}
	if err := acct.AddOneTimePreKeys(r, numOneTime); err != nil {
		return nil, err
	}
	return acct, nil
}

// RotateSignedPreKey generates a fresh signed prekey and signs it with the
// identity key. Rotating limits how far back a compromise of the signed prekey
// reaches; the old private key should be kept only long enough to accept
// sessions already in flight.
func (a *Account) RotateSignedPreKey(r io.Reader) error {
	kp, err := primitives.GenerateKeyPair(r)
	if err != nil {
		return err
	}
	id := a.NextPreKeyID
	a.NextPreKeyID++
	sig, err := primitives.Sign(a.Identity.Private, SigningInput(id, kp.Public), r)
	if err != nil {
		return fmt.Errorf("x3dh: sign prekey: %w", err)
	}
	a.SignedPreKey = SignedPreKey{ID: id, KeyPair: kp, Signature: sig, CreatedAt: time.Now().UTC()}
	return nil
}

// AddOneTimePreKeys tops the pool back up.
func (a *Account) AddOneTimePreKeys(r io.Reader, n int) error {
	for i := 0; i < n; i++ {
		kp, err := primitives.GenerateKeyPair(r)
		if err != nil {
			return err
		}
		id := a.NextPreKeyID
		a.NextPreKeyID++
		a.OneTimePreKeys = append(a.OneTimePreKeys, OneTimePreKey{ID: id, KeyPair: kp})
	}
	return nil
}

// TakeOneTimePreKey removes and returns the prekey with the given id. A
// one-time prekey is used exactly once: that is what stops an attacker who
// replays a captured first message from establishing the same session twice.
func (a *Account) TakeOneTimePreKey(id uint32) (OneTimePreKey, error) {
	for i, k := range a.OneTimePreKeys {
		if k.ID == id {
			a.OneTimePreKeys = append(a.OneTimePreKeys[:i], a.OneTimePreKeys[i+1:]...)
			return k, nil
		}
	}
	return OneTimePreKey{}, fmt.Errorf("%w: %d", ErrUnknownPreKey, id)
}

// Published is everything a client uploads to the relay. All of it is public.
type Published struct {
	Name                  string               `json:"name"`
	IdentityKey           primitives.PublicKey `json:"identity_key"`
	SignedPreKeyID        uint32               `json:"signed_pre_key_id"`
	SignedPreKey          primitives.PublicKey `json:"signed_pre_key"`
	SignedPreKeySignature []byte               `json:"signed_pre_key_signature"`
	OneTimePreKeys        []PreKey             `json:"one_time_pre_keys"`
}

// Publish returns the public bundle to upload. No private key is included --
// that is asserted by a test, because it is the kind of mistake that is
// invisible until someone reads the wire.
func (a *Account) Publish() Published {
	pub := Published{
		Name:                  a.Name,
		IdentityKey:           a.Identity.Public,
		SignedPreKeyID:        a.SignedPreKey.ID,
		SignedPreKey:          a.SignedPreKey.KeyPair.Public,
		SignedPreKeySignature: a.SignedPreKey.Signature,
	}
	for _, k := range a.OneTimePreKeys {
		pub.OneTimePreKeys = append(pub.OneTimePreKeys, PreKey{ID: k.ID, PublicKey: k.KeyPair.Public})
	}
	return pub
}

// Bundle is what a sender fetches: the identity key, the signed prekey with its
// signature, and at most one one-time prekey, which the relay has now consumed.
type Bundle struct {
	Name                  string               `json:"name"`
	IdentityKey           primitives.PublicKey `json:"identity_key"`
	SignedPreKeyID        uint32               `json:"signed_pre_key_id"`
	SignedPreKey          primitives.PublicKey `json:"signed_pre_key"`
	SignedPreKeySignature []byte               `json:"signed_pre_key_signature"`
	OneTimePreKeyID       uint32               `json:"one_time_pre_key_id"`
	OneTimePreKey         primitives.PublicKey `json:"one_time_pre_key"`
}

// HasOneTimePreKey reports whether the relay had a one-time prekey left.
func (b Bundle) HasOneTimePreKey() bool { return b.OneTimePreKeyID != NoPreKey }

// Verify checks the structure of a bundle and the signed prekey's signature.
//
// The signature is the only thing tying the signed prekey to the identity key.
// Without it the relay could hand out a signed prekey of its own alongside the
// genuine identity key; the sender would complete X3DH against the relay, the
// relay would decrypt, re-encrypt to the real recipient, and neither end would
// see anything wrong. With it, a relay that wants to read messages has to
// substitute the identity key too -- which changes the safety number, and is
// the one thing a user can detect out of band.
func (b Bundle) Verify() error {
	if b.Name == "" {
		return fmt.Errorf("%w: empty name", ErrBadBundle)
	}
	if b.IdentityKey.IsZero() || b.SignedPreKey.IsZero() {
		return fmt.Errorf("%w: zero key", ErrBadBundle)
	}
	if b.SignedPreKeyID == NoPreKey {
		return fmt.Errorf("%w: signed prekey id must not be zero", ErrBadBundle)
	}
	if b.HasOneTimePreKey() && b.OneTimePreKey.IsZero() {
		return fmt.Errorf("%w: one-time prekey id with a zero key", ErrBadBundle)
	}
	if !primitives.Verify(b.IdentityKey, SigningInput(b.SignedPreKeyID, b.SignedPreKey), b.SignedPreKeySignature) {
		return ErrBadSignature
	}
	return nil
}
