package primitives

import "crypto/subtle"

// ConstantTimeEqual compares two byte slices without leaking where they first
// differ. Every authenticator comparison in this project goes through here:
// AEAD tags (inside ChaCha20-Poly1305), XEdDSA signature checks, safety-number
// comparison and the keystore's version/magic checks.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Zero overwrites b. Go gives no guarantee that this survives the optimiser or
// that the bytes were not already copied by the garbage collector, so treat it
// as hygiene rather than as a defence -- see the limitations section of the
// README.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
