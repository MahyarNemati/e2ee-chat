package keystore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
)

var secret = []byte(`{"identity":"a private key that must never appear in the file"}`)

func TestSealOpenRoundTrip(t *testing.T) {
	sealed, err := Seal([]byte("correct horse battery staple"), secret, TestParams())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open([]byte("correct horse battery staple"), sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip returned %q", got)
	}
}

// The whole point of the file: its contents must not be readable.
func TestSealedFileContainsNoPlaintext(t *testing.T) {
	sealed, err := Seal([]byte("passphrase"), secret, TestParams())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("the plaintext is in the sealed file verbatim")
	}
	for _, fragment := range []string{"identity", "private key", "never appear"} {
		if bytes.Contains(sealed, []byte(fragment)) {
			t.Fatalf("fragment %q leaked into the sealed file", fragment)
		}
	}
	// Positive control: the magic really is there, so the search above is
	// looking at the bytes it thinks it is.
	if !bytes.HasPrefix(sealed, magic) {
		t.Fatal("sealed file does not start with the magic; the test is not reading the keystore")
	}
}

func TestWrongPassphraseRejected(t *testing.T) {
	sealed, err := Seal([]byte("passphrase"), secret, TestParams())
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []string{"", "passphras", "passphrase ", "Passphrase", "other"} {
		if _, err := Open([]byte(wrong), sealed); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("passphrase %q: got %v, want ErrWrongPassphrase", wrong, err)
		}
	}
}

// Rewriting the Argon2id parameters down to something cheap would let an
// attacker brute-force the passphrase far faster. The header is associated
// data, so any edit to it breaks the tag.
func TestHeaderIsAuthenticated(t *testing.T) {
	pass := []byte("passphrase")
	sealed, err := Seal(pass, secret, Params{Time: 2, MemoryKiB: 16, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < headerLen; i++ {
		mutated := bytes.Clone(sealed)
		mutated[i] ^= 0x01
		if _, err := Open(pass, mutated); err == nil {
			t.Fatalf("flipping byte %d of the header still decrypted", i)
		}
	}
	for _, i := range []int{headerLen, len(sealed) - 1} {
		mutated := bytes.Clone(sealed)
		mutated[i] ^= 0x01
		if _, err := Open(pass, mutated); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("flipping byte %d: got %v, want ErrWrongPassphrase", i, err)
		}
	}
}

func TestOpenRejectsMalformedFiles(t *testing.T) {
	pass := []byte("passphrase")
	sealed, err := Seal(pass, secret, TestParams())
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":       {},
		"short":       sealed[:headerLen],
		"bad magic":   append([]byte("XXXXXXXX"), sealed[8:]...),
		"unknown kdf": func() []byte { b := bytes.Clone(sealed); b[8] = 9; return b }(),
		"zero memory": func() []byte { b := bytes.Clone(sealed); copy(b[13:17], []byte{0, 0, 0, 0}); return b }(),
		"absurd memory": func() []byte {
			b := bytes.Clone(sealed)
			copy(b[13:17], []byte{0xFF, 0xFF, 0xFF, 0xFF})
			return b
		}(),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(pass, raw); err == nil {
				t.Fatal("accepted a malformed keystore")
			}
		})
	}
}

// Two seals of the same plaintext under the same passphrase must differ: the
// salt and nonce are fresh each time.
func TestSealIsRandomised(t *testing.T) {
	a, err := Seal([]byte("passphrase"), secret, TestParams())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal([]byte("passphrase"), secret, TestParams())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are byte-identical")
	}
	for _, sealed := range [][]byte{a, b} {
		got, err := Open([]byte("passphrase"), sealed)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("round trip: %v", err)
		}
	}
}

func TestSealRejectsEmptyPassphrase(t *testing.T) {
	if _, err := Seal(nil, secret, TestParams()); err == nil {
		t.Fatal("sealed with an empty passphrase")
	}
}

func TestSaveAndLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "alice.keys")
	pass := []byte("passphrase")

	if err := Save(path, pass, secret, TestParams()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("keystore is mode %o, want 600", perm)
	}

	got, err := LoadFile(path, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("file round trip changed the contents")
	}
	if _, err := LoadFile(path, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("got %v, want ErrWrongPassphrase", err)
	}

	// Saving again replaces the file atomically and leaves no temporary behind.
	if err := Save(path, pass, []byte("v2"), TestParams()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one file in the keystore directory, found %d", len(entries))
	}
}

// The default parameters have to be the expensive ones; a copy-paste of the
// test parameters into production would be invisible otherwise.
func TestDefaultParamsAreExpensive(t *testing.T) {
	p := DefaultParams()
	if p.MemoryKiB < 19*1024 {
		t.Errorf("default memory cost is %d KiB; RFC 9106 recommends at least 19 MiB", p.MemoryKiB)
	}
	if p.Time < 1 || p.Parallelism < 1 {
		t.Error("default parameters are degenerate")
	}
}

// Argon2id must be doing the work: a different salt means a different key, and
// the same inputs must be reproducible.
func TestKeyDerivationIsSaltedAndDeterministic(t *testing.T) {
	p := TestParams()
	a := deriveKey([]byte("passphrase"), []byte("salt-one--------"), p)
	b := deriveKey([]byte("passphrase"), []byte("salt-two--------"), p)
	c := deriveKey([]byte("passphrase"), []byte("salt-one--------"), p)

	if bytes.Equal(a, b) {
		t.Error("different salts produced the same key")
	}
	if !bytes.Equal(a, c) {
		t.Error("the same inputs produced different keys")
	}
	if len(a) != primitives.AEADKeyLen {
		t.Errorf("derived key is %d bytes, want %d", len(a), primitives.AEADKeyLen)
	}
	if d := deriveKey([]byte("passphrase"), []byte("salt-one--------"), Params{Time: p.Time + 1, MemoryKiB: p.MemoryKiB, Parallelism: p.Parallelism}); bytes.Equal(a, d) {
		t.Error("changing the pass count produced the same key")
	}
}
