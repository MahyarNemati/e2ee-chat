// Package keystore encrypts a client's key material at rest with a key derived
// from a passphrase by Argon2id.
//
// The threat is an attacker who copies the file. Argon2id is memory-hard, so
// guessing the passphrase costs them RAM as well as time; a plain hash would
// cost them almost nothing on a GPU. The parameters live in the file header and
// are authenticated along with the ciphertext, so an attacker cannot rewrite
// them down to something cheap and hand the file back.
package keystore

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
	"golang.org/x/crypto/argon2"
)

// magic identifies the format and pins its version.
var magic = []byte("E2EEKEY1")

const (
	kdfArgon2id byte = 1
	saltLen          = 16
	// headerLen is magic | kdf id | time | memory | parallelism | salt | nonce.
	headerLen = len("E2EEKEY1") + 1 + 4 + 4 + 1 + saltLen + primitives.AEADNonceLenX

	// Upper bounds on what a keystore header may ask for. Generous compared
	// with any sane configuration, small enough that a hostile file cannot make
	// Open run for hours or allocate the machine out of memory.
	maxMemoryKiB   = 1024 * 1024 // 1 GiB
	maxTime        = 64
	maxParallelism = 64
)

// ErrWrongPassphrase is returned when the file does not decrypt. It cannot
// distinguish a wrong passphrase from a corrupted or tampered file, and
// deliberately does not try.
var ErrWrongPassphrase = errors.New("keystore: wrong passphrase or corrupted keystore")

// ErrMalformed is returned for a file that is not a keystore at all.
var ErrMalformed = errors.New("keystore: malformed keystore file")

// Params are the Argon2id cost parameters.
type Params struct {
	Time        uint32 // passes over memory
	MemoryKiB   uint32 // memory cost
	Parallelism uint8  // lanes
}

// DefaultParams follows the second recommended option of RFC 9106 section 4:
// 64 MiB, three passes, four lanes. It takes a noticeable fraction of a second,
// which is the point.
func DefaultParams() Params {
	return Params{Time: 3, MemoryKiB: 64 * 1024, Parallelism: 4}
}

// TestParams are deliberately weak, for tests that run this hundreds of times.
// Never use them for a real keystore.
func TestParams() Params {
	return Params{Time: 1, MemoryKiB: 8, Parallelism: 1}
}

func (p Params) validate() error {
	if p.Time == 0 || p.MemoryKiB == 0 || p.Parallelism == 0 {
		return fmt.Errorf("%w: zero Argon2id parameter", ErrMalformed)
	}
	// A hostile file can name any cost it likes. Deriving the key is the first
	// thing Open does, so an unchecked header is a denial of service: a flipped
	// bit in the pass count turns 3 passes into 16 million. Refuse implausible
	// parameters before Argon2id is allowed to allocate or iterate.
	if p.MemoryKiB > maxMemoryKiB {
		return fmt.Errorf("%w: memory cost of %d KiB is implausible", ErrMalformed, p.MemoryKiB)
	}
	if p.Time > maxTime {
		return fmt.Errorf("%w: %d passes is implausible", ErrMalformed, p.Time)
	}
	if p.Parallelism > maxParallelism {
		return fmt.Errorf("%w: %d lanes is implausible", ErrMalformed, p.Parallelism)
	}
	return nil
}

// Seal encrypts plaintext under a key derived from passphrase.
func Seal(passphrase, plaintext []byte, params Params) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("keystore: passphrase must not be empty")
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("keystore: salt: %w", err)
	}
	nonce := make([]byte, primitives.AEADNonceLenX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("keystore: nonce: %w", err)
	}

	header := marshalHeader(params, salt, nonce)
	key := deriveKey(passphrase, salt, params)
	defer primitives.Zero(key)

	// The header is the associated data, so the cost parameters and salt are
	// covered by the tag.
	ct, err := primitives.SealX(key, nonce, plaintext, header)
	if err != nil {
		return nil, fmt.Errorf("keystore: encrypt: %w", err)
	}
	return append(header, ct...), nil
}

// Open decrypts a keystore file.
func Open(passphrase, data []byte) ([]byte, error) {
	if len(data) < headerLen+primitives.AEADTagLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(data))
	}
	if !primitives.ConstantTimeEqual(data[:len(magic)], magic) {
		return nil, fmt.Errorf("%w: bad magic", ErrMalformed)
	}
	params, salt, nonce, err := parseHeader(data[:headerLen])
	if err != nil {
		return nil, err
	}

	key := deriveKey(passphrase, salt, params)
	defer primitives.Zero(key)

	pt, err := primitives.OpenX(key, nonce, data[headerLen:], data[:headerLen])
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return pt, nil
}

func marshalHeader(p Params, salt, nonce []byte) []byte {
	out := make([]byte, 0, headerLen)
	out = append(out, magic...)
	out = append(out, kdfArgon2id)
	out = binary.BigEndian.AppendUint32(out, p.Time)
	out = binary.BigEndian.AppendUint32(out, p.MemoryKiB)
	out = append(out, p.Parallelism)
	out = append(out, salt...)
	return append(out, nonce...)
}

func parseHeader(h []byte) (Params, []byte, []byte, error) {
	i := len(magic)
	if h[i] != kdfArgon2id {
		return Params{}, nil, nil, fmt.Errorf("%w: unknown KDF %d", ErrMalformed, h[i])
	}
	i++
	p := Params{
		Time:        binary.BigEndian.Uint32(h[i : i+4]),
		MemoryKiB:   binary.BigEndian.Uint32(h[i+4 : i+8]),
		Parallelism: h[i+8],
	}
	if err := p.validate(); err != nil {
		return Params{}, nil, nil, err
	}
	i += 9
	return p, h[i : i+saltLen], h[i+saltLen:], nil
}

func deriveKey(passphrase, salt []byte, p Params) []byte {
	return argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Parallelism, primitives.AEADKeyLen)
}

// Save writes a sealed keystore to path with owner-only permissions.
func Save(path string, passphrase, plaintext []byte, params Params) error {
	sealed, err := Seal(passphrase, plaintext, params)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("keystore: create directory: %w", err)
		}
	}
	// Write to a temporary file and rename, so an interrupted save cannot leave
	// a half-written keystore where the only copy of an identity key used to be.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keystore-*")
	if err != nil {
		return fmt.Errorf("keystore: create temporary file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("keystore: chmod: %w", err)
	}
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		return fmt.Errorf("keystore: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("keystore: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keystore: close: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}

// LoadFile reads and decrypts a keystore from path.
func LoadFile(path string, passphrase []byte) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: read: %w", err)
	}
	return Open(passphrase, data)
}
