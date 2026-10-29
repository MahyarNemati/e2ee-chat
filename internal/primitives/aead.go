package primitives

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// AEADKeyLen is the ChaCha20-Poly1305 key size.
	AEADKeyLen = chacha20poly1305.KeySize
	// AEADNonceLen is the IETF ChaCha20-Poly1305 nonce size (RFC 8439).
	AEADNonceLen = chacha20poly1305.NonceSize
	// AEADNonceLenX is the XChaCha20-Poly1305 nonce size, large enough to be
	// drawn at random. Used by the keystore, where there is no counter.
	AEADNonceLenX = chacha20poly1305.NonceSizeX
	// AEADTagLen is the Poly1305 authenticator size.
	AEADTagLen = chacha20poly1305.Overhead
)

// ErrDecrypt is returned whenever an authenticator does not verify. It is
// deliberately uninformative: a caller cannot learn from it whether the key,
// the nonce, the associated data or the ciphertext was wrong.
var ErrDecrypt = errors.New("primitives: authentication failed")

// Seal encrypts plaintext with ChaCha20-Poly1305, binding ad into the tag.
func Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("primitives: aead: %w", err)
	}
	if len(nonce) != AEADNonceLen {
		return nil, fmt.Errorf("primitives: nonce is %d bytes, want %d", len(nonce), AEADNonceLen)
	}
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

// Open decrypts and authenticates. The tag comparison inside
// chacha20poly1305 is constant-time.
func Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("primitives: aead: %w", err)
	}
	if len(nonce) != AEADNonceLen {
		return nil, fmt.Errorf("primitives: nonce is %d bytes, want %d", len(nonce), AEADNonceLen)
	}
	pt, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// SealX and OpenX are the extended-nonce variant, used where the nonce has to
// be random rather than derived from a counter.
func SealX(key, nonce, plaintext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("primitives: xaead: %w", err)
	}
	if len(nonce) != AEADNonceLenX {
		return nil, fmt.Errorf("primitives: nonce is %d bytes, want %d", len(nonce), AEADNonceLenX)
	}
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

// OpenX decrypts a SealX ciphertext.
func OpenX(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("primitives: xaead: %w", err)
	}
	if len(nonce) != AEADNonceLenX {
		return nil, fmt.Errorf("primitives: nonce is %d bytes, want %d", len(nonce), AEADNonceLenX)
	}
	pt, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
