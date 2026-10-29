package x3dh

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
)

func newAccount(t *testing.T, name string, n int) *Account {
	t.Helper()
	a, err := NewAccount(rand.Reader, name, n)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// bundleFor models what the relay hands out: the published material with at
// most one one-time prekey, which the relay then deletes.
func bundleFor(t *testing.T, a *Account, withOneTime bool) Bundle {
	t.Helper()
	p := a.Publish()
	b := Bundle{
		Name:                  p.Name,
		IdentityKey:           p.IdentityKey,
		SignedPreKeyID:        p.SignedPreKeyID,
		SignedPreKey:          p.SignedPreKey,
		SignedPreKeySignature: p.SignedPreKeySignature,
	}
	if withOneTime {
		if len(p.OneTimePreKeys) == 0 {
			t.Fatal("account has no one-time prekeys to hand out")
		}
		b.OneTimePreKeyID = p.OneTimePreKeys[0].ID
		b.OneTimePreKey = p.OneTimePreKeys[0].PublicKey
	}
	return b
}

func TestAgreementWithOneTimePreKey(t *testing.T) {
	alice, bob := newAccount(t, "alice", 5), newAccount(t, "bob", 5)
	bundle := bundleFor(t, bob, true)

	sent, err := Initiate(rand.Reader, alice.Identity, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if sent.OneTimePreKeyID == NoPreKey {
		t.Fatal("a bundle with a one-time prekey produced a session without one")
	}

	recv, err := Accept(bob, alice.Identity.Public, sent.EphemeralKey, sent.SignedPreKeyID, sent.OneTimePreKeyID)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sent.SharedSecret[:], recv.SharedSecret[:]) {
		t.Fatalf("shared secrets differ:\n%x\n%x", sent.SharedSecret, recv.SharedSecret)
	}
	var zero [32]byte
	if bytes.Equal(sent.SharedSecret[:], zero[:]) {
		t.Fatal("shared secret is all zero")
	}
	if !bytes.Equal(sent.AssociatedData, recv.AssociatedData) {
		t.Fatal("associated data differs between the two sides")
	}
	if sent.RemoteRatchetKey != recv.RatchetKeyPair.Public {
		t.Fatal("the two sides disagree about the recipient's initial ratchet key")
	}
}

// With the pool exhausted the agreement still works -- it just drops DH4.
func TestAgreementWithoutOneTimePreKey(t *testing.T) {
	alice, bob := newAccount(t, "alice", 0), newAccount(t, "bob", 0)
	bundle := bundleFor(t, bob, false)
	if bundle.HasOneTimePreKey() {
		t.Fatal("expected a bundle with no one-time prekey")
	}

	sent, err := Initiate(rand.Reader, alice.Identity, bundle)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := Accept(bob, alice.Identity.Public, sent.EphemeralKey, sent.SignedPreKeyID, NoPreKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sent.SharedSecret[:], recv.SharedSecret[:]) {
		t.Fatal("shared secrets differ without a one-time prekey")
	}
}

// Dropping DH4 must change the secret, or the one-time prekey is not actually
// contributing anything.
func TestOneTimePreKeyChangesTheSecret(t *testing.T) {
	alice, bob := newAccount(t, "alice", 5), newAccount(t, "bob", 5)

	withOTPK, err := Initiate(rand.Reader, alice.Identity, bundleFor(t, bob, true))
	if err != nil {
		t.Fatal(err)
	}
	withoutOTPK, err := Initiate(rand.Reader, alice.Identity, bundleFor(t, bob, false))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(withOTPK.SharedSecret[:], withoutOTPK.SharedSecret[:]) {
		t.Fatal("the one-time prekey made no difference to the shared secret")
	}
}

// A one-time prekey is used once. Replaying a captured first message must not
// re-establish the same session.
func TestOneTimePreKeyIsConsumedOnce(t *testing.T) {
	alice, bob := newAccount(t, "alice", 5), newAccount(t, "bob", 5)
	bundle := bundleFor(t, bob, true)
	sent, err := Initiate(rand.Reader, alice.Identity, bundle)
	if err != nil {
		t.Fatal(err)
	}
	before := len(bob.OneTimePreKeys)

	if _, err := Accept(bob, alice.Identity.Public, sent.EphemeralKey, sent.SignedPreKeyID, sent.OneTimePreKeyID); err != nil {
		t.Fatal(err)
	}
	if after := len(bob.OneTimePreKeys); after != before-1 {
		t.Fatalf("pool went from %d to %d; the prekey was not consumed", before, after)
	}
	if _, err := Accept(bob, alice.Identity.Public, sent.EphemeralKey, sent.SignedPreKeyID, sent.OneTimePreKeyID); !errors.Is(err, ErrUnknownPreKey) {
		t.Fatalf("replayed first message: got %v, want ErrUnknownPreKey", err)
	}
}

func TestBundleVerifyRejectsTampering(t *testing.T) {
	bob := newAccount(t, "bob", 5)
	good := bundleFor(t, bob, true)
	if err := good.Verify(); err != nil {
		t.Fatalf("a genuine bundle was rejected: %v", err)
	}

	mutations := map[string]func(*Bundle){
		"signed prekey swapped":    func(b *Bundle) { b.SignedPreKey[0] ^= 0x01 },
		"signed prekey id changed": func(b *Bundle) { b.SignedPreKeyID++ },
		"identity key swapped":     func(b *Bundle) { b.IdentityKey[0] ^= 0x01 },
		"signature mangled":        func(b *Bundle) { b.SignedPreKeySignature[0] ^= 0x01 },
		"signature stripped":       func(b *Bundle) { b.SignedPreKeySignature = nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			b := good
			b.SignedPreKeySignature = bytes.Clone(good.SignedPreKeySignature)
			mutate(&b)
			if err := b.Verify(); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("got %v, want ErrBadSignature", err)
			}
		})
	}

	t.Run("structural", func(t *testing.T) {
		for name, mutate := range map[string]func(*Bundle){
			"empty name":           func(b *Bundle) { b.Name = "" },
			"zero identity key":    func(b *Bundle) { b.IdentityKey = primitives.PublicKey{} },
			"zero signed prekey":   func(b *Bundle) { b.SignedPreKey = primitives.PublicKey{} },
			"zero signed prekeyid": func(b *Bundle) { b.SignedPreKeyID = NoPreKey },
			"one-time id, no key":  func(b *Bundle) { b.OneTimePreKey = primitives.PublicKey{} },
		} {
			b := good
			mutate(&b)
			if err := b.Verify(); !errors.Is(err, ErrBadBundle) {
				t.Errorf("%s: got %v, want ErrBadBundle", name, err)
			}
		}
	})
}

// Initiate must refuse a bundle that does not verify, rather than deriving a
// secret with whatever the relay sent.
func TestInitiateRefusesUnsignedBundle(t *testing.T) {
	alice, bob := newAccount(t, "alice", 5), newAccount(t, "bob", 5)
	bundle := bundleFor(t, bob, true)
	bundle.SignedPreKeySignature = make([]byte, primitives.SignatureLen)

	if _, err := Initiate(rand.Reader, alice.Identity, bundle); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

// This is the trust assumption of the whole system, written as a test.
//
// A malicious relay cannot forge a signed prekey under Bob's identity key -- the
// signature stops that. But it can publish a bundle that is entirely its own
// and internally consistent, and Verify will accept it, because there is
// nothing in the protocol that knows which identity key is really Bob's. The
// only thing that changes is the identity key, which is exactly what the safety
// number is derived from and what users compare out of band.
func TestASelfConsistentSubstitutedBundleVerifies(t *testing.T) {
	alice, bob := newAccount(t, "alice", 5), newAccount(t, "bob", 5)
	relay := newAccount(t, "bob", 5) // the relay, impersonating Bob

	substituted := bundleFor(t, relay, true)
	if err := substituted.Verify(); err != nil {
		t.Fatalf("the substituted bundle should verify -- that is the point: %v", err)
	}
	if substituted.IdentityKey == bob.Identity.Public {
		t.Fatal("test setup is wrong: the relay reused Bob's identity key")
	}

	// Alice completes the agreement with the relay and never notices.
	sent, err := Initiate(rand.Reader, alice.Identity, substituted)
	if err != nil {
		t.Fatalf("Alice refused a self-consistent bundle: %v", err)
	}
	accepted, err := Accept(relay, alice.Identity.Public, sent.EphemeralKey, sent.SignedPreKeyID, sent.OneTimePreKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sent.SharedSecret[:], accepted.SharedSecret[:]) {
		t.Fatal("the relay failed to complete the agreement it just mounted")
	}

	// The associated data Alice is using names the relay's identity key, not
	// Bob's. Comparing that out of band is the detection.
	if bytes.Equal(sent.AssociatedData, AssociatedData(alice.Identity.Public, bob.Identity.Public)) {
		t.Fatal("the substitution left the associated data unchanged; nothing would be detectable")
	}
}

func TestAcceptRejectsUnknownSignedPreKey(t *testing.T) {
	alice, bob := newAccount(t, "alice", 5), newAccount(t, "bob", 5)
	sent, err := Initiate(rand.Reader, alice.Identity, bundleFor(t, bob, true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(bob, alice.Identity.Public, sent.EphemeralKey, sent.SignedPreKeyID+1, sent.OneTimePreKeyID); !errors.Is(err, ErrUnknownPreKey) {
		t.Fatalf("got %v, want ErrUnknownPreKey", err)
	}
}

func TestAcceptRejectsZeroKeys(t *testing.T) {
	alice, bob := newAccount(t, "alice", 5), newAccount(t, "bob", 5)
	sent, err := Initiate(rand.Reader, alice.Identity, bundleFor(t, bob, true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(bob, primitives.PublicKey{}, sent.EphemeralKey, sent.SignedPreKeyID, NoPreKey); err == nil {
		t.Fatal("accepted a zero identity key")
	}
	if _, err := Accept(bob, alice.Identity.Public, primitives.PublicKey{}, sent.SignedPreKeyID, NoPreKey); err == nil {
		t.Fatal("accepted a zero ephemeral key")
	}
}

// Whatever Publish returns is uploaded verbatim, so it had better contain no
// private key material.
func TestPublishedBundleCarriesNoPrivateKeys(t *testing.T) {
	bob := newAccount(t, "bob", 4)
	raw, err := json.Marshal(bob.Publish())
	if err != nil {
		t.Fatal(err)
	}

	secrets := [][]byte{bob.Identity.Private[:], bob.SignedPreKey.KeyPair.Private[:]}
	for _, k := range bob.OneTimePreKeys {
		secrets = append(secrets, k.KeyPair.Private[:])
	}
	for i, secret := range secrets {
		if bytes.Contains(raw, secret) {
			t.Errorf("private key %d appears in the published bundle", i)
		}
	}

	// Positive control: the public keys that should be there, are.
	if !bytes.Contains(raw, mustText(t, bob.Identity.Public)) {
		t.Fatal("the published bundle does not contain the identity public key; the search above proves nothing")
	}
	if len(bob.Publish().OneTimePreKeys) != 4 {
		t.Fatal("expected four one-time prekeys to be published")
	}
}

func mustText(t *testing.T, k primitives.PublicKey) []byte {
	t.Helper()
	b, err := k.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRotateSignedPreKeyChangesIDAndSignature(t *testing.T) {
	bob := newAccount(t, "bob", 1)
	oldID, oldKey := bob.SignedPreKey.ID, bob.SignedPreKey.KeyPair.Public
	if err := bob.RotateSignedPreKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if bob.SignedPreKey.ID == oldID || bob.SignedPreKey.KeyPair.Public == oldKey {
		t.Fatal("rotation did not change the signed prekey")
	}
	if err := bundleFor(t, bob, false).Verify(); err != nil {
		t.Fatalf("the rotated prekey does not verify: %v", err)
	}
}

func TestNewAccountRejectsEmptyName(t *testing.T) {
	if _, err := NewAccount(rand.Reader, "", 1); err == nil {
		t.Fatal("accepted an empty account name")
	}
}
