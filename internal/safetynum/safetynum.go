// Package safetynum derives the 60-digit safety number two users compare out of
// band, following the construction Signal uses for its fingerprints.
//
// This is the only defence against the relay substituting a prekey bundle. The
// signed-prekey signature proves that a signed prekey belongs to some identity
// key; nothing in the protocol proves that the identity key belongs to the
// person you meant. A relay that publishes its own identity key for "bob" can
// read everything -- and the single observable consequence is that the safety
// number Alice sees does not match the one Bob sees. Comparing them over a
// channel the relay does not control is what closes the gap.
package safetynum

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
)

const (
	// version is hashed in so that a future change to the construction cannot
	// collide with this one.
	version uint16 = 0
	// iterations is the hash-iteration count Signal uses. It is not a password
	// KDF: the cost exists to make brute-forcing a colliding identity key
	// expensive for whoever wants two keys to display the same digits.
	iterations = 5200
	// fingerprintLen is the number of digest bytes turned into digits.
	fingerprintLen = 30
	// chunkLen bytes become one five-digit group.
	chunkLen = 5
)

// Fingerprint is one party's 30-digit half of a safety number.
func Fingerprint(identity primitives.PublicKey, stableID string) string {
	buf := make([]byte, 0, 2+primitives.KeyLen+len(stableID))
	buf = binary.BigEndian.AppendUint16(buf, version)
	buf = append(buf, identity[:]...)
	buf = append(buf, stableID...)

	digest := sha512.Sum512(buf)
	for i := 1; i < iterations; i++ {
		h := sha512.New()
		h.Write(digest[:])
		h.Write(identity[:])
		digest = [sha512.Size]byte(h.Sum(nil))
	}

	var out strings.Builder
	for i := 0; i < fingerprintLen; i += chunkLen {
		// Five bytes, big-endian, reduced to five decimal digits.
		var n uint64
		for _, b := range digest[i : i+chunkLen] {
			n = n<<8 | uint64(b)
		}
		fmt.Fprintf(&out, "%05d", n%100000)
	}
	return out.String()
}

// SafetyNumber combines both fingerprints. The two halves are sorted so that
// both participants compute the same string without having to agree on who is
// "first".
func SafetyNumber(local, remote primitives.PublicKey, localID, remoteID string) string {
	halves := []string{Fingerprint(local, localID), Fingerprint(remote, remoteID)}
	sort.Strings(halves)
	return halves[0] + halves[1]
}

// Format groups a safety number into blocks of five digits, as it is displayed
// for reading aloud.
func Format(number string) string {
	var out []string
	for i := 0; i < len(number); i += chunkLen {
		end := min(i+chunkLen, len(number))
		out = append(out, number[i:end])
	}
	var b strings.Builder
	for i, group := range out {
		if i > 0 {
			if i%4 == 0 {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
		}
		b.WriteString(group)
	}
	return b.String()
}

// Equal compares two safety numbers in constant time. The values are public, so
// this is belt and braces -- but an authenticator comparison that is sometimes
// constant-time and sometimes not is a habit worth refusing to form.
func Equal(a, b string) bool {
	return primitives.ConstantTimeEqual([]byte(a), []byte(b))
}
