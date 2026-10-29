package primitives

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/edwards25519"
)

func mustKeyPair(t *testing.T) KeyPair {
	t.Helper()
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestDHAgrees(t *testing.T) {
	a, b := mustKeyPair(t), mustKeyPair(t)
	ab, err := DH(a.Private, b.Public)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := DH(b.Private, a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab[:], ba[:]) {
		t.Fatalf("DH disagrees: %x vs %x", ab, ba)
	}
	var zero SharedSecret
	if bytes.Equal(ab[:], zero[:]) {
		t.Fatal("shared secret is all zero")
	}
}

// A peer that sends a low-order point forces the shared secret to a value it
// knows in advance. X25519 must refuse rather than return it.
func TestDHRejectsLowOrderPoints(t *testing.T) {
	lowOrder := []PublicKey{
		{}, // identity
		{1},
		{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
			0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
		{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
			0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	}
	me := mustKeyPair(t)
	for i, pub := range lowOrder {
		if _, err := DH(me.Private, pub); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("low-order point %d: got err %v, want ErrInvalidKey", i, err)
		}
	}
}

// The Montgomery <-> Edwards conversion is the fiddliest part of XEdDSA, so
// check it against edwards25519's own independent Edwards -> Montgomery map in
// both directions.
func TestMontgomeryEdwardsConversionRoundTrips(t *testing.T) {
	var sawPositive, sawNegative bool
	for i := 0; i < 64; i++ {
		kp := mustKeyPair(t)

		edPub, _, err := signingKeyPair(kp.Private)
		if err != nil {
			t.Fatalf("signingKeyPair: %v", err)
		}
		if edPub.Bytes()[31]>>7 != 0 {
			t.Fatal("calculate_key_pair must return a public key with sign bit 0")
		}
		if got := edPub.BytesMontgomery(); !bytes.Equal(got, kp.Public[:]) {
			t.Fatalf("edwards public key maps back to %x, want %x", got, kp.Public)
		}

		conv, err := montgomeryToEdwards(kp.Public)
		if err != nil {
			t.Fatalf("montgomeryToEdwards: %v", err)
		}
		if conv.Equal(edPub) != 1 {
			t.Fatal("montgomeryToEdwards disagrees with calculate_key_pair")
		}

		// Record which branch of the sign-bit fix-up we exercised.
		raw, err := edwards25519.NewScalar().SetBytesWithClamping(kp.Private[:])
		if err != nil {
			t.Fatal(err)
		}
		if new(edwards25519.Point).ScalarBaseMult(raw).Bytes()[31]>>7 == 1 {
			sawNegative = true
		} else {
			sawPositive = true
		}
	}
	if !sawPositive || !sawNegative {
		t.Fatalf("only one sign branch exercised (positive=%v negative=%v); the test is not covering calculate_key_pair", sawPositive, sawNegative)
	}
}

func TestXEdDSASignVerify(t *testing.T) {
	msg := []byte("signed prekey bytes")
	for i := 0; i < 32; i++ {
		kp := mustKeyPair(t)
		sig, err := Sign(kp.Private, msg, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != SignatureLen {
			t.Fatalf("signature is %d bytes, want %d", len(sig), SignatureLen)
		}
		if !Verify(kp.Public, msg, sig) {
			t.Fatal("valid signature rejected")
		}
	}
}

func TestXEdDSARejectsTampering(t *testing.T) {
	kp := mustKeyPair(t)
	msg := []byte("signed prekey bytes")
	sig, err := Sign(kp.Private, msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong message", func(t *testing.T) {
		if Verify(kp.Public, []byte("signed prekey byte*"), sig) {
			t.Fatal("accepted a signature over a different message")
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		if Verify(mustKeyPair(t).Public, msg, sig) {
			t.Fatal("accepted a signature under someone else's key")
		}
	})
	t.Run("flipped bit in R", func(t *testing.T) {
		bad := bytes.Clone(sig)
		bad[3] ^= 0x01
		if Verify(kp.Public, msg, bad) {
			t.Fatal("accepted a mutated R")
		}
	})
	t.Run("flipped bit in s", func(t *testing.T) {
		bad := bytes.Clone(sig)
		bad[40] ^= 0x01
		if Verify(kp.Public, msg, bad) {
			t.Fatal("accepted a mutated s")
		}
	})
	t.Run("non-canonical s", func(t *testing.T) {
		bad := bytes.Clone(sig)
		for i := 32; i < 64; i++ {
			bad[i] = 0xFF
		}
		if Verify(kp.Public, msg, bad) {
			t.Fatal("accepted an s >= l")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		if Verify(kp.Public, msg, sig[:63]) {
			t.Fatal("accepted a 63-byte signature")
		}
	})
	t.Run("empty", func(t *testing.T) {
		if Verify(kp.Public, msg, nil) {
			t.Fatal("accepted an empty signature")
		}
	})
}

// Signatures are randomised: two signatures over the same message must differ,
// and both must verify.
func TestXEdDSAIsRandomised(t *testing.T) {
	kp := mustKeyPair(t)
	msg := []byte("same message")
	a, err := Sign(kp.Private, msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(kp.Private, msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two signatures over the same message are identical")
	}
	if !Verify(kp.Public, msg, a) || !Verify(kp.Public, msg, b) {
		t.Fatal("a randomised signature failed to verify")
	}
}

func TestAEADRejectsTampering(t *testing.T) {
	key := make([]byte, AEADKeyLen)
	nonce := make([]byte, AEADNonceLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	pt, ad := []byte("attack at dawn"), []byte("header")

	ct, err := Seal(key, nonce, pt, ad)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(key, nonce, ct, ad); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip: %q, %v", got, err)
	}

	t.Run("mutated ciphertext", func(t *testing.T) {
		bad := bytes.Clone(ct)
		bad[0] ^= 0x01
		if _, err := Open(key, nonce, bad, ad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
	})
	t.Run("mutated associated data", func(t *testing.T) {
		if _, err := Open(key, nonce, ct, []byte("headeR")); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
	})
	t.Run("mutated tag", func(t *testing.T) {
		bad := bytes.Clone(ct)
		bad[len(bad)-1] ^= 0x01
		if _, err := Open(key, nonce, bad, ad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		other := make([]byte, AEADKeyLen)
		other[0] = 1
		if _, err := Open(other, nonce, ct, ad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
	})
}

func TestXAEADRoundTrip(t *testing.T) {
	key := make([]byte, AEADKeyLen)
	nonce := make([]byte, AEADNonceLenX)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ct, err := SealX(key, nonce, []byte("keystore blob"), []byte("v1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenX(key, nonce, ct, []byte("v1"))
	if err != nil || string(got) != "keystore blob" {
		t.Fatalf("round trip: %q, %v", got, err)
	}
	if _, err := OpenX(key, nonce, ct, []byte("v2")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("associated data not bound: %v", err)
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual([]byte("abc"), []byte("abc")) {
		t.Error("equal slices reported unequal")
	}
	if ConstantTimeEqual([]byte("abc"), []byte("abd")) {
		t.Error("different slices reported equal")
	}
	if ConstantTimeEqual([]byte("abc"), []byte("ab")) {
		t.Error("different lengths reported equal")
	}
}
