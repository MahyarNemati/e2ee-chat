package ratchet

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
	"github.com/MahyarNemati/e2ee-chat/internal/wire"
)

// newPair builds the two ends of a ratchet from a shared secret, as X3DH would
// hand them over. Keeping X3DH out of these tests isolates ratchet failures
// from key-agreement failures; the two are exercised together in the client
// package's end-to-end test.
func newPair(t *testing.T, cfg Config) (alice, bob *Session) {
	t.Helper()
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatal(err)
	}
	bobRatchet, err := primitives.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ad := []byte("identity-A|identity-B")

	alice, err = NewSender(rand.Reader, cfg, sk, bobRatchet.Public, ad)
	if err != nil {
		t.Fatal(err)
	}
	return alice, NewReceiver(rand.Reader, cfg, sk, bobRatchet, ad)
}

func encrypt(t *testing.T, s *Session, text string) wire.Message {
	t.Helper()
	m, err := s.Encrypt([]byte(text))
	if err != nil {
		t.Fatalf("encrypt %q: %v", text, err)
	}
	return m
}

func decryptEquals(t *testing.T, s *Session, m wire.Message, want string) {
	t.Helper()
	got, err := s.Decrypt(m)
	if err != nil {
		t.Fatalf("decrypt (want %q): %v", want, err)
	}
	if string(got) != want {
		t.Fatalf("decrypted %q, want %q", got, want)
	}
}

func TestConversationInterleaved(t *testing.T) {
	alice, bob := newPair(t, Config{})

	// Alice opens; Bob has no sending chain until he has received something.
	if _, err := bob.Encrypt([]byte("too early")); !errors.Is(err, ErrNoSendingChain) {
		t.Fatalf("responder encrypted before receiving: %v", err)
	}
	decryptEquals(t, bob, encrypt(t, alice, "hello"), "hello")

	// 40 messages each way, in bursts, so both the symmetric ratchet (within a
	// burst) and the DH ratchet (between bursts) are exercised repeatedly.
	for round := 0; round < 10; round++ {
		for i := 0; i < 4; i++ {
			want := fmt.Sprintf("a%d-%d", round, i)
			decryptEquals(t, bob, encrypt(t, alice, want), want)
		}
		for i := 0; i < 4; i++ {
			want := fmt.Sprintf("b%d-%d", round, i)
			decryptEquals(t, alice, encrypt(t, bob, want), want)
		}
	}

	// A final strictly alternating exchange: every message is its own DH step.
	for i := 0; i < 10; i++ {
		want := fmt.Sprintf("ping%d", i)
		decryptEquals(t, bob, encrypt(t, alice, want), want)
		want = fmt.Sprintf("pong%d", i)
		decryptEquals(t, alice, encrypt(t, bob, want), want)
	}
}

func TestEmptyAndLargeMessages(t *testing.T) {
	alice, bob := newPair(t, Config{})
	decryptEquals(t, bob, encrypt(t, alice, ""), "")

	big := bytes.Repeat([]byte("x"), 1<<20)
	m, err := alice.Encrypt(big)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bob.Decrypt(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, big) {
		t.Fatal("1 MiB message did not round trip")
	}
}

func TestOutOfOrderDelivery(t *testing.T) {
	alice, bob := newPair(t, Config{})

	var msgs []wire.Message
	for i := 0; i < 6; i++ {
		msgs = append(msgs, encrypt(t, alice, fmt.Sprintf("m%d", i)))
	}
	// Deliver 5, 0, 3, 1, 4, 2.
	for _, i := range []int{5, 0, 3, 1, 4, 2} {
		decryptEquals(t, bob, msgs[i], fmt.Sprintf("m%d", i))
	}
	if n := bob.SkippedKeyCount(); n != 0 {
		t.Fatalf("%d skipped keys still cached after every message arrived; they should all have been consumed", n)
	}
}

func TestOutOfOrderAcrossRatchetSteps(t *testing.T) {
	alice, bob := newPair(t, Config{})
	decryptEquals(t, bob, encrypt(t, alice, "open"), "open")

	// Bob replies (DH step 1), Alice replies (DH step 2) -- but hold both of
	// Alice's first-chain messages back until after the ratchet has moved on.
	early := []wire.Message{encrypt(t, alice, "early0"), encrypt(t, alice, "early1")}

	reply := encrypt(t, bob, "reply")
	decryptEquals(t, alice, reply, "reply")
	later := encrypt(t, alice, "later")

	decryptEquals(t, bob, later, "later")
	decryptEquals(t, bob, early[1], "early1")
	decryptEquals(t, bob, early[0], "early0")
}

func TestDuplicateDeliveryRejected(t *testing.T) {
	alice, bob := newPair(t, Config{})
	m := encrypt(t, alice, "once")
	decryptEquals(t, bob, m, "once")

	if _, err := bob.Decrypt(m); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay of a delivered message: got %v, want ErrReplay", err)
	}
	// And the session is still usable afterwards.
	decryptEquals(t, bob, encrypt(t, alice, "twice"), "twice")
}

func TestReplayOfASkippedMessageRejected(t *testing.T) {
	alice, bob := newPair(t, Config{})
	first := encrypt(t, alice, "first")
	second := encrypt(t, alice, "second")

	decryptEquals(t, bob, second, "second") // caches first's key
	decryptEquals(t, bob, first, "first")   // consumes it

	if _, err := bob.Decrypt(first); err == nil {
		t.Fatal("a skipped message decrypted twice; its key was not deleted on use")
	}
}

func TestReplayAcrossARatchetStepRejected(t *testing.T) {
	alice, bob := newPair(t, Config{})
	stale := encrypt(t, alice, "stale")
	decryptEquals(t, bob, stale, "stale")

	decryptEquals(t, alice, encrypt(t, bob, "reply"), "reply")
	decryptEquals(t, bob, encrypt(t, alice, "fresh"), "fresh")

	if _, err := bob.Decrypt(stale); err == nil {
		t.Fatal("a message from a retired chain was accepted again")
	}
	// The failed attempt must not have corrupted the session.
	decryptEquals(t, bob, encrypt(t, alice, "still works"), "still works")
}

func TestTamperedHeaderRejected(t *testing.T) {
	mutations := map[string]func(*wire.Header){
		"ratchet key":           func(h *wire.Header) { h.RatchetKey[0] ^= 0x01 },
		"message number":        func(h *wire.Header) { h.Number++ },
		"previous chain length": func(h *wire.Header) { h.PreviousChainLength++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			alice, bob := newPair(t, Config{})
			// Give the chain some history so the mutated fields are plausible.
			decryptEquals(t, bob, encrypt(t, alice, "warm up"), "warm up")

			m := encrypt(t, alice, "secret")
			mutate(&m.Header)
			if _, err := bob.Decrypt(m); err == nil {
				t.Fatal("tampered header accepted")
			}
			// Untampered traffic still flows: the header check did not wedge
			// the session.
			decryptEquals(t, bob, encrypt(t, alice, "after"), "after")
		})
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	alice, bob := newPair(t, Config{})
	m := encrypt(t, alice, "attack at dawn")

	t.Run("body", func(t *testing.T) {
		bad := wire.Message{Header: m.Header, Ciphertext: bytes.Clone(m.Ciphertext)}
		bad.Ciphertext[2] ^= 0x01
		if err := mustFail(t, bob, bad); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("tag", func(t *testing.T) {
		bad := wire.Message{Header: m.Header, Ciphertext: bytes.Clone(m.Ciphertext)}
		bad.Ciphertext[len(bad.Ciphertext)-1] ^= 0x01
		if err := mustFail(t, bob, bad); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		bad := wire.Message{Header: m.Header, Ciphertext: m.Ciphertext[:len(m.Ciphertext)-1]}
		if err := mustFail(t, bob, bad); err != nil {
			t.Fatal(err)
		}
	})

	// After three forgeries the genuine message must still decrypt.
	decryptEquals(t, bob, m, "attack at dawn")
}

func mustFail(t *testing.T, s *Session, m wire.Message) error {
	t.Helper()
	if _, err := s.Decrypt(m); err == nil {
		return errors.New("forged message accepted")
	}
	return nil
}

// The X3DH associated data binds both identity keys into every tag. A receiver
// built from the same shared secret but a different associated data -- which is
// what a relay substituting an identity key would produce -- must not decrypt.
func TestWrongAssociatedDataRejected(t *testing.T) {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatal(err)
	}
	bobRatchet, err := primitives.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewSender(rand.Reader, Config{}, sk, bobRatchet.Public, []byte("identity-A|identity-B"))
	if err != nil {
		t.Fatal(err)
	}
	m := encrypt(t, alice, "hello")

	matching := NewReceiver(rand.Reader, Config{}, sk, bobRatchet, []byte("identity-A|identity-B"))
	decryptEquals(t, matching, m, "hello")

	mismatched := NewReceiver(rand.Reader, Config{}, sk, bobRatchet, []byte("identity-A|identity-X"))
	if _, err := mismatched.Decrypt(m); err == nil {
		t.Fatal("a message decrypted under different associated data")
	}
}

// Forward secrecy: once a message has been delivered its key is gone, so an
// attacker who seizes the receiver's entire state afterwards still cannot read
// what was already said.
func TestForwardSecrecy(t *testing.T) {
	alice, bob := newPair(t, Config{})

	var sent []wire.Message
	for i := 0; i < 5; i++ {
		m := encrypt(t, alice, fmt.Sprintf("secret %d", i))
		sent = append(sent, m)
		decryptEquals(t, bob, m, fmt.Sprintf("secret %d", i))
	}

	// The attacker takes a complete copy of Bob's state, keys included.
	stolen := snapshot(t, bob, Config{})

	// Positive control: the stolen state is a working session, so a failure
	// below is about the deleted keys and not about a broken snapshot.
	decryptEquals(t, stolen, encrypt(t, alice, "after the theft"), "after the theft")

	for i, m := range sent {
		if _, err := stolen.Decrypt(m); err == nil {
			t.Fatalf("stolen state decrypted already-delivered message %d", i)
		}
	}
}

// Post-compromise security: an attacker who takes a complete copy of one
// party's state is locked out again as the Diffie-Hellman ratchet turns, because
// each step mixes in a private key generated after the theft.
//
// Healing is not instantaneous and this test pins down exactly when it happens.
// With Bob's state stolen, the attacker holds Bob's current ratchet key, so it
// keeps reading until Bob performs his next ratchet step -- which produces a key
// pair the attacker never saw. From then on Bob's outgoing traffic is closed,
// and Alice's closes one step later, once she has ratcheted against Bob's new
// key. A full round trip in each direction, which is the honest statement of
// the property.
func TestPostCompromiseSecurity(t *testing.T) {
	alice, bob := newPair(t, Config{})
	decryptEquals(t, bob, encrypt(t, alice, "hello"), "hello")

	eve := snapshot(t, bob, Config{}) // a complete copy of Bob, keys included

	// Phase 1: the attacker is inside the session. These positive controls
	// matter -- without them a later failure could just mean a broken clone.
	m := encrypt(t, alice, "alice 1")
	decryptEquals(t, bob, m, "alice 1")
	decryptEquals(t, eve, m, "alice 1")

	// Phase 2: Bob replies, Alice ratchets and answers. Alice's new ratchet key
	// is combined with Bob's old one, which the attacker holds, so Alice's
	// traffic is still readable.
	decryptEquals(t, alice, encrypt(t, bob, "bob 1"), "bob 1")
	m = encrypt(t, alice, "alice 2")
	decryptEquals(t, bob, m, "alice 2")
	decryptEquals(t, eve, m, "alice 2")

	// Decrypting that message made Bob ratchet, generating a key pair the
	// attacker could not have. Bob's outgoing traffic is now closed.
	healedB := encrypt(t, bob, "bob 2")
	decryptEquals(t, alice, healedB, "bob 2")
	if _, err := eve.Decrypt(healedB); err == nil {
		t.Fatal("the attacker still reads Bob after his first post-theft ratchet step")
	}

	// Alice has now ratcheted against Bob's new key, so her traffic is closed
	// too, and the session has healed in both directions.
	healedA := encrypt(t, alice, "alice 3")
	decryptEquals(t, bob, healedA, "alice 3")
	if _, err := eve.Decrypt(healedA); err == nil {
		t.Fatal("the attacker still reads Alice after a full round trip")
	}

	// The genuine session is unharmed by everything the attacker tried.
	decryptEquals(t, alice, encrypt(t, bob, "bob 3"), "bob 3")
}

func snapshot(t *testing.T, s *Session, cfg Config) *Session {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	clone, err := Load(rand.Reader, cfg, raw)
	if err != nil {
		t.Fatal(err)
	}
	return clone
}

// A header may claim any message number. Honouring a huge one would mean
// deriving and storing that many keys, so the bound has to refuse.
func TestSkipLimitEnforced(t *testing.T) {
	alice, bob := newPair(t, Config{MaxSkip: 10, MaxSkippedKeys: 100})

	var msgs []wire.Message
	for i := 0; i < 20; i++ {
		msgs = append(msgs, encrypt(t, alice, fmt.Sprintf("m%d", i)))
	}
	if _, err := bob.Decrypt(msgs[15]); !errors.Is(err, ErrSkipLimit) {
		t.Fatalf("skipping 15 with a bound of 10: got %v, want ErrSkipLimit", err)
	}
	if n := bob.SkippedKeyCount(); n != 0 {
		t.Fatalf("the refused message still cached %d keys", n)
	}
	// Within the bound it works, and the session was not damaged by the refusal.
	decryptEquals(t, bob, msgs[8], "m8")
	if n := bob.SkippedKeyCount(); n != 8 {
		t.Fatalf("cached %d keys after skipping 8, want 8", n)
	}
}

// A forged header claiming an enormous number must be refused outright rather
// than allocating.
func TestAbsurdMessageNumberRefused(t *testing.T) {
	alice, bob := newPair(t, Config{})
	m := encrypt(t, alice, "hello")
	m.Header.Number = 1 << 31
	if _, err := bob.Decrypt(m); !errors.Is(err, ErrSkipLimit) {
		t.Fatalf("got %v, want ErrSkipLimit", err)
	}
	if n := bob.SkippedKeyCount(); n != 0 {
		t.Fatalf("allocated %d keys for a forged header", n)
	}
}

// The total cache is bounded too: enough legitimate gaps, and the oldest keys
// are forgotten rather than retained forever.
func TestSkippedKeyCacheIsBounded(t *testing.T) {
	const bound = 50
	alice, bob := newPair(t, Config{MaxSkip: 1000, MaxSkippedKeys: bound})

	var msgs []wire.Message
	for i := 0; i < 200; i++ {
		msgs = append(msgs, encrypt(t, alice, fmt.Sprintf("m%d", i)))
	}
	decryptEquals(t, bob, msgs[199], "m199")

	if n := bob.SkippedKeyCount(); n != bound {
		t.Fatalf("cached %d keys, bound is %d", n, bound)
	}
	// The most recent gaps are still decryptable...
	for _, i := range []int{199 - bound, 198} {
		decryptEquals(t, bob, msgs[i], fmt.Sprintf("m%d", i))
	}
	// ...and the oldest were evicted. To the receiver an evicted key is
	// indistinguishable from a message it has already seen; either way it does
	// not decrypt.
	if _, err := bob.Decrypt(msgs[0]); err == nil {
		t.Fatal("message 0 decrypted although its key should have been evicted")
	}
}

func TestSessionSerialisationRoundTrip(t *testing.T) {
	alice, bob := newPair(t, Config{MaxSkip: 100, MaxSkippedKeys: 100})
	decryptEquals(t, bob, encrypt(t, alice, "one"), "one")
	decryptEquals(t, alice, encrypt(t, bob, "two"), "two")

	// Leave a skipped key outstanding so the cache is part of the round trip.
	gap := encrypt(t, alice, "gap")
	after := encrypt(t, alice, "after")
	decryptEquals(t, bob, after, "after")
	if bob.SkippedKeyCount() != 1 {
		t.Fatalf("expected one cached key, got %d", bob.SkippedKeyCount())
	}

	alice, bob = snapshot(t, alice, Config{}), snapshot(t, bob, Config{})

	decryptEquals(t, bob, gap, "gap")
	decryptEquals(t, bob, encrypt(t, alice, "three"), "three")
	decryptEquals(t, alice, encrypt(t, bob, "four"), "four")
}

func TestLoadRejectsCorruptState(t *testing.T) {
	cases := map[string]string{
		"not json":     `{`,
		"short root":   `{"root":"AAAA"}`,
		"missing root": `{}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(rand.Reader, Config{}, []byte(body)); err == nil {
				t.Fatal("accepted corrupt session state")
			}
		})
	}
}
