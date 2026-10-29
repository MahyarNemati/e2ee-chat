package safetynum

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
)

func key(t *testing.T) primitives.PublicKey {
	t.Helper()
	kp, err := primitives.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return kp.Public
}

func TestFingerprintShape(t *testing.T) {
	fp := Fingerprint(key(t), "alice")
	if len(fp) != 30 {
		t.Fatalf("fingerprint is %d digits, want 30", len(fp))
	}
	if strings.Trim(fp, "0123456789") != "" {
		t.Fatalf("fingerprint %q is not all digits", fp)
	}
}

func TestFingerprintIsDeterministic(t *testing.T) {
	k := key(t)
	if Fingerprint(k, "alice") != Fingerprint(k, "alice") {
		t.Fatal("fingerprint is not deterministic")
	}
}

func TestFingerprintDependsOnKeyAndID(t *testing.T) {
	a, b := key(t), key(t)
	if Fingerprint(a, "alice") == Fingerprint(b, "alice") {
		t.Fatal("two different identity keys produced the same fingerprint")
	}
	if Fingerprint(a, "alice") == Fingerprint(a, "bob") {
		t.Fatal("the stable id is not part of the fingerprint")
	}

	// A single flipped bit must change it, or a substituted key could pass
	// a casual comparison.
	flipped := a
	flipped[0] ^= 0x01
	if Fingerprint(a, "alice") == Fingerprint(flipped, "alice") {
		t.Fatal("a one-bit change to the identity key did not change the fingerprint")
	}
}

// Both users must see the same digits whichever side they are on; otherwise
// comparing them over the phone is useless.
func TestSafetyNumberIsSymmetric(t *testing.T) {
	alice, bob := key(t), key(t)
	fromAlice := SafetyNumber(alice, bob, "alice", "bob")
	fromBob := SafetyNumber(bob, alice, "bob", "alice")
	if fromAlice != fromBob {
		t.Fatalf("the two sides disagree:\n%s\n%s", fromAlice, fromBob)
	}
	if len(fromAlice) != 60 {
		t.Fatalf("safety number is %d digits, want 60", len(fromAlice))
	}
}

// The detection property: a relay that substitutes its own identity key changes
// the safety number that one side sees.
func TestSubstitutedIdentityKeyChangesTheSafetyNumber(t *testing.T) {
	alice, bob, relay := key(t), key(t), key(t)

	genuine := SafetyNumber(alice, bob, "alice", "bob")
	// Alice is talking to the relay but believes she is talking to Bob.
	underAttack := SafetyNumber(alice, relay, "alice", "bob")

	if genuine == underAttack {
		t.Fatal("substituting the identity key left the safety number unchanged")
	}
	if Equal(genuine, underAttack) {
		t.Fatal("Equal reported two different safety numbers as equal")
	}
	if !Equal(genuine, SafetyNumber(bob, alice, "bob", "alice")) {
		t.Fatal("Equal reported two identical safety numbers as different")
	}
}

func TestFormatGroupsDigits(t *testing.T) {
	number := SafetyNumber(key(t), key(t), "alice", "bob")
	formatted := Format(number)
	if got := strings.Join(strings.Fields(formatted), ""); got != number {
		t.Fatalf("formatting lost or added digits:\n%q\n%q", got, number)
	}
	if lines := strings.Split(formatted, "\n"); len(lines) != 3 {
		t.Fatalf("expected three lines of four groups, got %d lines", len(lines))
	}
}
