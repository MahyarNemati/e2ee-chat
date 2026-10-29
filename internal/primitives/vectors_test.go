package primitives

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// Known-answer tests against the published vectors. If an implementation
// disagrees with these, it is the implementation that is wrong -- a round-trip
// test would happily agree with itself forever.

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex in test vector: %v", err)
	}
	return b
}

// TestX25519Vectors is RFC 7748 section 5.2.
func TestX25519Vectors(t *testing.T) {
	cases := []struct{ scalar, u, want string }{
		{
			scalar: "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
			u:      "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
			want:   "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
		},
		{
			scalar: "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
			u:      "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
			want:   "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
		},
	}
	for i, tc := range cases {
		got, err := curve25519.X25519(unhex(t, tc.scalar), unhex(t, tc.u))
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if want := unhex(t, tc.want); !bytes.Equal(got, want) {
			t.Errorf("case %d:\n got %x\nwant %x", i, got, want)
		}
	}
}

// TestX25519DHVector is RFC 7748 section 6.1: the full Alice/Bob exchange,
// which is exactly how this project uses X25519.
func TestX25519DHVector(t *testing.T) {
	var alicePriv, bobPriv PrivateKey
	copy(alicePriv[:], unhex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	copy(bobPriv[:], unhex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))

	alicePub, err := PublicFromPrivate(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	bobPub, err := PublicFromPrivate(bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"); !bytes.Equal(alicePub[:], want) {
		t.Errorf("alice public:\n got %x\nwant %x", alicePub, want)
	}
	if want := unhex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"); !bytes.Equal(bobPub[:], want) {
		t.Errorf("bob public:\n got %x\nwant %x", bobPub, want)
	}

	wantShared := unhex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
	ab, err := DH(alicePriv, bobPub)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := DH(bobPriv, alicePub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab[:], wantShared) {
		t.Errorf("DH(a, B):\n got %x\nwant %x", ab, wantShared)
	}
	if !bytes.Equal(ba[:], wantShared) {
		t.Errorf("DH(b, A):\n got %x\nwant %x", ba, wantShared)
	}
}

// TestChaCha20Poly1305Vector is RFC 8439 section 2.8.2.
func TestChaCha20Poly1305Vector(t *testing.T) {
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	ad := unhex(t, "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7")
	key := unhex(t, `80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
	                 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f`)
	nonce := unhex(t, "07 00 00 00 40 41 42 43 44 45 46 47")
	wantCT := unhex(t, `d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
	                    a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
	                    3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
	                    1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
	                    92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
	                    fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
	                    3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
	                    61 16`)
	wantTag := unhex(t, "1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91")

	sealed, err := Seal(key, nonce, plaintext, ad)
	if err != nil {
		t.Fatal(err)
	}
	gotCT, gotTag := sealed[:len(sealed)-AEADTagLen], sealed[len(sealed)-AEADTagLen:]
	if !bytes.Equal(gotCT, wantCT) {
		t.Errorf("ciphertext:\n got %x\nwant %x", gotCT, wantCT)
	}
	if !bytes.Equal(gotTag, wantTag) {
		t.Errorf("tag:\n got %x\nwant %x", gotTag, wantTag)
	}

	back, err := Open(key, nonce, sealed, ad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Errorf("round trip: got %q", back)
	}
}

// TestHKDFVectors is RFC 5869 appendix A, cases 1-3 (the SHA-256 ones).
func TestHKDFVectors(t *testing.T) {
	cases := []struct{ name, ikm, salt, info, prk, okm string }{
		{
			name: "A.1 basic",
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "000102030405060708090a0b0c",
			info: "f0f1f2f3f4f5f6f7f8f9",
			prk:  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			okm: `3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
			      34007208d5b887185865`,
		},
		{
			name: "A.2 long inputs",
			ikm: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
			      202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
			      404142434445464748494a4b4c4d4e4f`,
			salt: `606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
			       808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
			       a0a1a2a3a4a5a6a7a8a9aaabacadaeaf`,
			info: `b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf
			       d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef
			       f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`,
			prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			okm: `b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c
			      59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71
			      cc30c58179ec3e87c14c01d5c1f3434f1d87`,
		},
		{
			name: "A.3 zero-length salt and info",
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "",
			info: "",
			prk:  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			okm: `8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d
			      9d201395faa4b61a96c8`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ikm, salt := unhex(t, tc.ikm), unhex(t, tc.salt)
			info := string(unhex(t, tc.info))
			wantPRK, wantOKM := unhex(t, tc.prk), unhex(t, tc.okm)

			if got := HKDFExtract(salt, ikm); !bytes.Equal(got, wantPRK) {
				t.Errorf("PRK:\n got %x\nwant %x", got, wantPRK)
			}
			if got := HKDFExpand(wantPRK, info, len(wantOKM)); !bytes.Equal(got, wantOKM) {
				t.Errorf("OKM (expand):\n got %x\nwant %x", got, wantOKM)
			}
			// The one-shot wrapper the protocol layers actually call must agree.
			if got := HKDF(salt, ikm, info, len(wantOKM)); !bytes.Equal(got, wantOKM) {
				t.Errorf("OKM (one-shot):\n got %x\nwant %x", got, wantOKM)
			}
		})
	}
}

// TestHMACSHA256Vector is RFC 4231 test case 2, which pins the chain KDF's
// underlying PRF.
func TestHMACSHA256Vector(t *testing.T) {
	got := HMACSHA256([]byte("Jefe"), []byte("what do ya want for nothing?"))
	want := unhex(t, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
	if !bytes.Equal(got, want) {
		t.Errorf("HMAC-SHA256:\n got %x\nwant %x", got, want)
	}
}
