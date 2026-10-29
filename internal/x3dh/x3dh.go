package x3dh

import (
	"fmt"
	"io"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
)

// kdfInfo and the all-ones prefix follow the X3DH specification: the 32 0xFF
// bytes keep the concatenated DH outputs from ever colliding with the encoding
// of a X448 run, and the info string domain-separates this protocol.
const kdfInfo = "e2ee-chat/X3DH/25519/AES-free/v1"

// adContext prefixes the associated data so that it cannot be mistaken for the
// associated data of any other protocol sharing these keys.
const adContext = "e2ee-chat/X3DH/ad/v1"

// Initiated is the sender's half of a completed X3DH run.
type Initiated struct {
	// SharedSecret seeds the double ratchet's root key.
	SharedSecret [32]byte
	// AssociatedData is mixed into every message's AEAD tag for the lifetime of
	// the session, binding both identity keys to every ciphertext.
	AssociatedData []byte
	// EphemeralKey, SignedPreKeyID and OneTimePreKeyID travel in the first
	// message so the recipient can reproduce the same four DH results.
	EphemeralKey    primitives.PublicKey
	SignedPreKeyID  uint32
	OneTimePreKeyID uint32
	// RemoteRatchetKey is the recipient's signed prekey, which doubles as their
	// initial double-ratchet public key.
	RemoteRatchetKey primitives.PublicKey
}

// Accepted is the recipient's half.
type Accepted struct {
	SharedSecret   [32]byte
	AssociatedData []byte
	// RatchetKeyPair is the signed prekey pair, the recipient's initial
	// double-ratchet key pair.
	RatchetKeyPair primitives.KeyPair
	// RemoteIdentityKey is the sender's identity key, for the safety number.
	RemoteIdentityKey primitives.PublicKey
}

// Initiate runs X3DH as the sender against a fetched bundle. It refuses to
// proceed unless the signed prekey's signature verifies.
//
// The four Diffie-Hellman results are, in the specification's order:
//
//	DH1 = DH(IK_A, SPK_B)   authenticates the sender to the recipient
//	DH2 = DH(EK_A, IK_B)    authenticates the recipient to the sender
//	DH3 = DH(EK_A, SPK_B)   forward secrecy against a later identity compromise
//	DH4 = DH(EK_A, OPK_B)   forward secrecy against a signed-prekey compromise
//
// DH4 is omitted when the recipient's one-time prekey pool is exhausted; the
// session is still secure, but a later compromise of the signed prekey would
// expose this first message, which is why pools are refilled.
func Initiate(r io.Reader, self primitives.KeyPair, bundle Bundle) (Initiated, error) {
	if err := bundle.Verify(); err != nil {
		return Initiated{}, err
	}
	ephemeral, err := primitives.GenerateKeyPair(r)
	if err != nil {
		return Initiated{}, err
	}

	dh1, err := primitives.DH(self.Private, bundle.SignedPreKey)
	if err != nil {
		return Initiated{}, fmt.Errorf("x3dh: DH1: %w", err)
	}
	dh2, err := primitives.DH(ephemeral.Private, bundle.IdentityKey)
	if err != nil {
		return Initiated{}, fmt.Errorf("x3dh: DH2: %w", err)
	}
	dh3, err := primitives.DH(ephemeral.Private, bundle.SignedPreKey)
	if err != nil {
		return Initiated{}, fmt.Errorf("x3dh: DH3: %w", err)
	}
	ikm := concatDH(dh1, dh2, dh3)

	otpkID := NoPreKey
	if bundle.HasOneTimePreKey() {
		dh4, err := primitives.DH(ephemeral.Private, bundle.OneTimePreKey)
		if err != nil {
			return Initiated{}, fmt.Errorf("x3dh: DH4: %w", err)
		}
		ikm = append(ikm, dh4[:]...)
		otpkID = bundle.OneTimePreKeyID
	}
	defer primitives.Zero(ikm)

	out := Initiated{
		AssociatedData:   AssociatedData(self.Public, bundle.IdentityKey),
		EphemeralKey:     ephemeral.Public,
		SignedPreKeyID:   bundle.SignedPreKeyID,
		OneTimePreKeyID:  otpkID,
		RemoteRatchetKey: bundle.SignedPreKey,
	}
	copy(out.SharedSecret[:], deriveSecret(ikm))
	return out, nil
}

// Accept runs X3DH as the recipient, reproducing the same shared secret from
// the key ids the sender quoted. The one-time prekey is consumed here: calling
// Accept twice with the same initial message fails the second time, which is
// what makes a replayed session setup fail rather than succeed silently.
func Accept(acct *Account, senderIdentity, senderEphemeral primitives.PublicKey, signedPreKeyID, oneTimePreKeyID uint32) (Accepted, error) {
	if senderIdentity.IsZero() || senderEphemeral.IsZero() {
		return Accepted{}, fmt.Errorf("%w: zero key in initial message", ErrBadBundle)
	}
	if signedPreKeyID != acct.SignedPreKey.ID {
		return Accepted{}, fmt.Errorf("%w: signed prekey %d (have %d)", ErrUnknownPreKey, signedPreKeyID, acct.SignedPreKey.ID)
	}
	spk := acct.SignedPreKey.KeyPair

	dh1, err := primitives.DH(spk.Private, senderIdentity)
	if err != nil {
		return Accepted{}, fmt.Errorf("x3dh: DH1: %w", err)
	}
	dh2, err := primitives.DH(acct.Identity.Private, senderEphemeral)
	if err != nil {
		return Accepted{}, fmt.Errorf("x3dh: DH2: %w", err)
	}
	dh3, err := primitives.DH(spk.Private, senderEphemeral)
	if err != nil {
		return Accepted{}, fmt.Errorf("x3dh: DH3: %w", err)
	}
	ikm := concatDH(dh1, dh2, dh3)

	if oneTimePreKeyID != NoPreKey {
		otpk, err := acct.TakeOneTimePreKey(oneTimePreKeyID)
		if err != nil {
			return Accepted{}, err
		}
		dh4, err := primitives.DH(otpk.KeyPair.Private, senderEphemeral)
		if err != nil {
			return Accepted{}, fmt.Errorf("x3dh: DH4: %w", err)
		}
		ikm = append(ikm, dh4[:]...)
	}
	defer primitives.Zero(ikm)

	out := Accepted{
		AssociatedData:    AssociatedData(senderIdentity, acct.Identity.Public),
		RatchetKeyPair:    spk,
		RemoteIdentityKey: senderIdentity,
	}
	copy(out.SharedSecret[:], deriveSecret(ikm))
	return out, nil
}

// AssociatedData is the sender's identity key followed by the recipient's,
// always in that order so both sides compute the same bytes.
func AssociatedData(sender, recipient primitives.PublicKey) []byte {
	ad := make([]byte, 0, len(adContext)+2*primitives.KeyLen)
	ad = append(ad, adContext...)
	ad = append(ad, sender[:]...)
	return append(ad, recipient[:]...)
}

func concatDH(dhs ...primitives.SharedSecret) []byte {
	// The specification prepends 32 bytes of 0xFF for Curve25519.
	ikm := make([]byte, 32, 32+len(dhs)*primitives.KeyLen+primitives.KeyLen)
	for i := range ikm {
		ikm[i] = 0xFF
	}
	for _, dh := range dhs {
		ikm = append(ikm, dh[:]...)
	}
	return ikm
}

func deriveSecret(ikm []byte) []byte {
	salt := make([]byte, 32) // HKDF salt of HashLen zero bytes, per the spec.
	return primitives.HKDF(salt, ikm, kdfInfo, 32)
}
