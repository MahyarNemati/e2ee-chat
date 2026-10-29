package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MahyarNemati/e2ee-chat/internal/keystore"
	"github.com/MahyarNemati/e2ee-chat/internal/ratchet"
	"github.com/MahyarNemati/e2ee-chat/internal/x3dh"
)

// A whole conversation through a real HTTP relay: Alice opens while Bob is
// offline, then forty messages each way in bursts, then a strictly alternating
// exchange so every message gets its own Diffie-Hellman step.
func TestTwoPartyConversation(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")

	// Bob has not run Receive even once: the first message is sent to a
	// recipient who is, as far as the protocol is concerned, offline.
	send(t, alice, "bob", "hello bob")
	if got := receiveTexts(t, bob); !slices.Equal(got, []string{"hello bob"}) {
		t.Fatalf("got %q", got)
	}

	for round := 0; round < 10; round++ {
		var wantA, wantB []string
		for i := 0; i < 4; i++ {
			text := fmt.Sprintf("alice %d-%d", round, i)
			send(t, alice, "bob", text)
			wantA = append(wantA, text)
		}
		if got := receiveTexts(t, bob); !slices.Equal(got, wantA) {
			t.Fatalf("round %d: bob got %q, want %q", round, got, wantA)
		}
		for i := 0; i < 4; i++ {
			text := fmt.Sprintf("bob %d-%d", round, i)
			send(t, bob, "alice", text)
			wantB = append(wantB, text)
		}
		if got := receiveTexts(t, alice); !slices.Equal(got, wantB) {
			t.Fatalf("round %d: alice got %q, want %q", round, got, wantB)
		}
	}

	for i := 0; i < 10; i++ {
		ping := fmt.Sprintf("ping %d", i)
		send(t, alice, "bob", ping)
		if got := receiveTexts(t, bob); !slices.Equal(got, []string{ping}) {
			t.Fatalf("got %q", got)
		}
		pong := fmt.Sprintf("pong %d", i)
		send(t, bob, "alice", pong)
		if got := receiveTexts(t, alice); !slices.Equal(got, []string{pong}) {
			t.Fatalf("got %q", got)
		}
	}

	// Unicode and an empty message survive the round trip unchanged.
	for _, text := range []string{"", "🔐 ünïcödé \x00 with a NUL", strings.Repeat("long ", 2000)} {
		send(t, alice, "bob", text)
		if got := receiveTexts(t, bob); !slices.Equal(got, []string{text}) {
			t.Fatalf("got %q, want %q", got, text)
		}
	}
}

// The claim the whole design rests on, checked against the bytes rather than
// asserted in a comment.
func TestRelaySeesNoPlaintext(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")

	secrets := []string{
		"the eagle lands at midnight",
		"routing number 0043119955",
		"meet me behind the gasworks",
		"passphrase: hunter2-but-longer",
	}
	send(t, alice, "bob", secrets[0])
	if got := receiveTexts(t, bob); !slices.Equal(got, secrets[:1]) {
		t.Fatalf("got %q", got)
	}
	send(t, bob, "alice", secrets[1])
	send(t, bob, "alice", secrets[2])
	if got := receiveTexts(t, alice); !slices.Equal(got, secrets[1:3]) {
		t.Fatalf("got %q", got)
	}
	send(t, alice, "bob", secrets[3])
	if got := receiveTexts(t, bob); !slices.Equal(got, secrets[3:]) {
		t.Fatalf("got %q", got)
	}

	corpus := h.corpus()

	// Positive controls first. Without these, a search over an empty buffer
	// would pass and prove nothing at all.
	if h.recorder.count() < 8 {
		t.Fatalf("only %d requests recorded; the conversation did not go through the relay", h.recorder.count())
	}
	if len(corpus) < 4096 {
		t.Fatalf("captured only %d bytes; the recorder is not seeing the traffic", len(corpus))
	}
	for _, marker := range []string{"alice", "bob", "/v1/messages", "/v1/bundles", "ciphertext"} {
		if !bytes.Contains(corpus, []byte(marker)) {
			t.Fatalf("captured traffic does not contain %q, so it is not what it claims to be", marker)
		}
	}
	// And the search itself works. Push a plaintext through the relay exactly
	// the way a ciphertext goes -- base64 inside a JSON field -- and confirm the
	// corpus finds it. Without this control the test would also pass for a
	// search that cannot see through base64 at all, which is the only place a
	// leak could realistically hide.
	canary := "CANARY-the-eagle-has-landed"
	if _, err := h.relay.Send("alice", "canary-sink", []byte(canary)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(h.corpus(), []byte(canary)) {
		t.Fatal("a plaintext sent through the relay was not found: the search cannot detect a leak, so proves nothing")
	}

	// Now the actual assertion.
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if bytes.Contains(corpus, []byte(secret)) {
			t.Errorf("plaintext %q appears in what the relay saw", secret)
		}
		// Also look for any distinctive word on its own, in case only part of a
		// message leaked.
		for _, word := range strings.Fields(secret) {
			if len(word) >= 8 && bytes.Contains(corpus, []byte(word)) {
				t.Errorf("fragment %q of a plaintext appears in what the relay saw", word)
			}
		}
	}
}

// Safety numbers are how two people detect a substituted bundle, so both sides
// must compute the same digits.
func TestSafetyNumbersMatch(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")

	if _, err := alice.SafetyNumber("bob"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("got %v, want ErrNoSession before a session exists", err)
	}

	send(t, alice, "bob", "hello")
	receiveTexts(t, bob)

	fromAlice, err := alice.SafetyNumber("bob")
	if err != nil {
		t.Fatal(err)
	}
	fromBob, err := bob.SafetyNumber("alice")
	if err != nil {
		t.Fatal(err)
	}
	if fromAlice != fromBob {
		t.Fatalf("safety numbers differ:\nalice: %s\nbob:   %s", fromAlice, fromBob)
	}
	if len(fromAlice) != 60 {
		t.Fatalf("safety number is %d digits, want 60", len(fromAlice))
	}

	// Each side is using the other's real identity key.
	if k, _ := alice.PeerIdentityKey("bob"); k != bob.IdentityKey() {
		t.Fatal("alice is not using bob's identity key")
	}
	if k, _ := bob.PeerIdentityKey("alice"); k != alice.IdentityKey() {
		t.Fatal("bob is not using alice's identity key")
	}
}

// The attack the safety number exists for. A relay that publishes its own
// bundle under Bob's name reads everything Alice sends, and every check inside
// the protocol passes -- the signature verifies, because the relay signed its
// own prekey with its own identity key. The only thing that changes is the
// safety number.
func TestSubstitutedBundleReadsTheConversationButChangesTheSafetyNumber(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")

	send(t, alice, "bob", "before the attack")
	receiveTexts(t, bob)
	genuine, err := alice.SafetyNumber("bob")
	if err != nil {
		t.Fatal(err)
	}

	// The relay operator registers their own keys under the name "bob",
	// replacing the published bundle.
	impostor := h.newUser("bob")

	// Alice starts a new session (as she would on a new device) and it lands on
	// the impostor's keys. Nothing visible goes wrong.
	freshAlice, err := New("alice", h.config())
	if err != nil {
		t.Fatal(err)
	}
	send(t, freshAlice, "bob", "the eagle lands at midnight")

	got := receiveTexts(t, impostor)
	if !slices.Equal(got, []string{"the eagle lands at midnight"}) {
		t.Fatalf("the impostor read %q; the attack was supposed to succeed", got)
	}
	if left := receiveTexts(t, bob); len(left) != 0 {
		t.Fatalf("the real bob received %q; the substitution did not take effect", left)
	}

	// The detection: Alice's safety number for "bob" is no longer the one Bob
	// computes, and no longer the one she saw before.
	underAttack, err := freshAlice.SafetyNumber("bob")
	if err != nil {
		t.Fatal(err)
	}
	fromBob, err := bob.SafetyNumber("alice")
	if err != nil {
		t.Fatal(err)
	}
	if underAttack == genuine {
		t.Fatal("the substituted bundle produced the same safety number as the genuine one")
	}
	if underAttack == fromBob {
		t.Fatal("alice and bob still agree on the safety number while a third party is reading")
	}
}

// A relay can corrupt what it stores. The client must report that, keep the
// session intact, and carry on.
func TestTamperedCiphertextIsReportedAndTheSessionSurvives(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")

	send(t, alice, "bob", "establish")
	receiveTexts(t, bob)

	send(t, alice, "bob", "tampered")
	queued := h.relay.Receive("bob")
	if len(queued) != 1 {
		t.Fatalf("expected one queued message, got %d", len(queued))
	}

	for name, mutate := range map[string]func([]byte){
		"ciphertext body":    func(b []byte) { b[len(b)-20] ^= 0x01 },
		"authentication tag": func(b []byte) { b[len(b)-1] ^= 0x01 },
		"header number":      func(b []byte) { b[6+32+4+3] ^= 0x01 },
		"header ratchet key": func(b []byte) { b[7] ^= 0x01 },
		"magic":              func(b []byte) { b[0] ^= 0x01 },
	} {
		t.Run(name, func(t *testing.T) {
			corrupted := bytes.Clone(queued[0].Ciphertext)
			mutate(corrupted)
			if _, err := h.relay.Send("alice", "bob", corrupted); err != nil {
				t.Fatal(err)
			}
			msgs, err := bob.Receive(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(msgs) != 1 {
				t.Fatalf("expected one message, got %d", len(msgs))
			}
			if msgs[0].Err == nil {
				t.Fatalf("a corrupted message decrypted to %q", msgs[0].Text)
			}
		})
	}

	// After five forgeries the session still works in both directions.
	send(t, alice, "bob", "still here")
	if got := receiveTexts(t, bob); !slices.Equal(got, []string{"still here"}) {
		t.Fatalf("got %q", got)
	}
	send(t, bob, "alice", "and back")
	if got := receiveTexts(t, alice); !slices.Equal(got, []string{"and back"}) {
		t.Fatalf("got %q", got)
	}
}

// A relay can also replay what it stored. Delivering the same envelope twice
// must produce one message and one error, not two messages.
func TestReplayedEnvelopeIsRejected(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")

	send(t, alice, "bob", "establish")
	receiveTexts(t, bob)

	send(t, alice, "bob", "transfer the money")
	queued := h.relay.Receive("bob")
	raw := queued[0].Ciphertext

	// Deliver it, then deliver it again.
	for i := 0; i < 2; i++ {
		if _, err := h.relay.Send("alice", "bob", raw); err != nil {
			t.Fatal(err)
		}
	}
	msgs, err := bob.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected two envelopes, got %d", len(msgs))
	}
	if msgs[0].Err != nil || msgs[0].Text != "transfer the money" {
		t.Fatalf("the first delivery should have worked: %q %v", msgs[0].Text, msgs[0].Err)
	}
	if msgs[1].Err == nil {
		t.Fatal("the replay was accepted as a second message")
	}
	if !errors.Is(msgs[1].Err, ratchet.ErrReplay) {
		t.Fatalf("got %v, want ErrReplay", msgs[1].Err)
	}
}

// A replayed first message cannot establish a second session: the one-time
// prekey it quoted has been consumed.
func TestReplayedFirstMessageIsRejected(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")

	send(t, alice, "bob", "the opening message")
	queued := h.relay.Receive("bob")
	raw := queued[0].Ciphertext

	for i := 0; i < 2; i++ {
		if _, err := h.relay.Send("alice", "bob", raw); err != nil {
			t.Fatal(err)
		}
	}
	msgs, err := bob.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].Err != nil || !msgs[0].NewSession {
		t.Fatalf("the first delivery should have established the session: %+v", msgs[0])
	}
	if msgs[1].Err == nil {
		t.Fatal("a replayed first message established a second session")
	}
	if !errors.Is(msgs[1].Err, x3dh.ErrUnknownPreKey) && !errors.Is(msgs[1].Err, ratchet.ErrReplay) {
		t.Fatalf("got %v, want ErrUnknownPreKey or ErrReplay", msgs[1].Err)
	}
}

// Relays reorder. Everything must still decrypt, in whatever order it turns up.
func TestOutOfOrderDeliveryThroughTheRelay(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")

	send(t, alice, "bob", "first")
	receiveTexts(t, bob)

	const n = 12
	for i := 0; i < n; i++ {
		send(t, alice, "bob", fmt.Sprintf("m%d", i))
	}
	queued := h.relay.Receive("bob")
	if len(queued) != n {
		t.Fatalf("expected %d queued messages, got %d", n, len(queued))
	}
	// Reverse them, which is the worst case for the skipped-key cache.
	slices.Reverse(queued)
	for _, env := range queued {
		if _, err := h.relay.Send(env.From, env.To, env.Ciphertext); err != nil {
			t.Fatal(err)
		}
	}

	got := receiveTexts(t, bob)
	want := make([]string, n)
	for i := range want {
		want[i] = fmt.Sprintf("m%d", n-1-i)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// A client is a process that exits. Its state has to survive in a form only its
// passphrase opens.
func TestStateSurvivesSaveAndLoad(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")
	passphrase := []byte("a passphrase for the keystore")
	path := filepath.Join(t.TempDir(), "alice.keys")

	send(t, alice, "bob", "before saving")
	receiveTexts(t, bob)
	send(t, bob, "alice", "a reply")
	if got := receiveTexts(t, alice); !slices.Equal(got, []string{"a reply"}) {
		t.Fatalf("got %q", got)
	}
	wantSafety, err := alice.SafetyNumber("bob")
	if err != nil {
		t.Fatal(err)
	}

	if err := alice.Save(path, passphrase, keystore.TestParams()); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, []byte("wrong passphrase"), h.config()); !errors.Is(err, keystore.ErrWrongPassphrase) {
		t.Fatalf("got %v, want ErrWrongPassphrase", err)
	}

	restored, err := Load(path, passphrase, h.config())
	if err != nil {
		t.Fatal(err)
	}
	if restored.Name() != "alice" || restored.IdentityKey() != alice.IdentityKey() {
		t.Fatal("the restored client is not the same account")
	}
	if got, _ := restored.SafetyNumber("bob"); got != wantSafety {
		t.Fatal("the restored client computes a different safety number")
	}

	// The conversation continues from where it left off, in both directions.
	send(t, restored, "bob", "after reloading")
	if got := receiveTexts(t, bob); !slices.Equal(got, []string{"after reloading"}) {
		t.Fatalf("got %q", got)
	}
	send(t, bob, "alice", "still talking")
	if got := receiveTexts(t, restored); !slices.Equal(got, []string{"still talking"}) {
		t.Fatalf("got %q", got)
	}
}

// Whatever is written to disk must not contain the keys in the clear.
func TestKeystoreFileContainsNoKeyMaterial(t *testing.T) {
	h := newHarness(t)
	alice := h.newUser("alice")
	path := filepath.Join(t.TempDir(), "alice.keys")
	if err := alice.Save(path, []byte("passphrase"), keystore.TestParams()); err != nil {
		t.Fatal(err)
	}

	raw, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 128 {
		t.Fatalf("the keystore is only %d bytes; it cannot hold the state", len(raw))
	}
	identity := alice.IdentityKey()
	if bytes.Contains(raw, identity[:]) {
		t.Error("the identity public key is in the keystore file in the clear")
	}
	for _, marker := range []string{"alice", "account", "ratchet", "identity"} {
		if bytes.Contains(raw, []byte(marker)) {
			t.Errorf("structural marker %q is readable in the keystore file", marker)
		}
	}
}

func TestTopUpPreKeys(t *testing.T) {
	h := newHarness(t)
	bob := h.newUser("bob")

	remaining, err := bob.TopUpPreKeys(context.Background(), DefaultPreKeyPool)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != DefaultPreKeyPool {
		t.Fatalf("a fresh pool reported %d, want %d", remaining, DefaultPreKeyPool)
	}

	// Drain most of the pool, as many new conversations would.
	for i := 0; i < DefaultPreKeyPool-2; i++ {
		if _, err := h.relay.Bundle("bob"); err != nil {
			t.Fatal(err)
		}
	}
	after, err := bob.TopUpPreKeys(context.Background(), 8)
	if err != nil {
		t.Fatal(err)
	}
	if after != DefaultPreKeyPool {
		t.Fatalf("after topping up the pool is %d, want %d", after, DefaultPreKeyPool)
	}

	// And the refilled prekeys actually work.
	alice := h.newUser("alice")
	send(t, alice, "bob", "using a refilled prekey")
	if got := receiveTexts(t, bob); !slices.Equal(got, []string{"using a refilled prekey"}) {
		t.Fatalf("got %q", got)
	}
}

// Even with the pool empty a session still forms; it just loses DH4.
func TestSessionWithoutAOneTimePreKey(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")

	for i := 0; i < DefaultPreKeyPool; i++ {
		if _, err := h.relay.Bundle("bob"); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := h.relay.PreKeyCount("bob"); err != nil || n != 0 {
		t.Fatalf("pool is %d (%v), want 0", n, err)
	}

	send(t, alice, "bob", "no one-time prekey left")
	if got := receiveTexts(t, bob); !slices.Equal(got, []string{"no one-time prekey left"}) {
		t.Fatalf("got %q", got)
	}
	send(t, bob, "alice", "replying anyway")
	if got := receiveTexts(t, alice); !slices.Equal(got, []string{"replying anyway"}) {
		t.Fatalf("got %q", got)
	}
}

func TestSendToUnknownUserFails(t *testing.T) {
	h := newHarness(t)
	alice := h.newUser("alice")
	if err := alice.Send(context.Background(), "nobody", []byte("hello?")); err == nil {
		t.Fatal("sent a message to a user with no published bundle")
	}
}

func TestUsersListing(t *testing.T) {
	h := newHarness(t)
	h.newUser("alice")
	bob := h.newUser("bob")
	users, err := bob.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(users, []string{"alice", "bob"}) {
		t.Fatalf("got %v", users)
	}
}

// A message that arrives with no session and is not a prekey message has to be
// reported, not silently dropped.
func TestMessageWithNoSessionIsReported(t *testing.T) {
	h := newHarness(t)
	alice, bob := h.newUser("alice"), h.newUser("bob")

	send(t, alice, "bob", "establish")
	queued := h.relay.Receive("bob")
	raw := bytes.Clone(queued[0].Ciphertext)

	// Relabel the prekey envelope as a normal one; Bob has no session, so there
	// is nothing to decrypt it with.
	raw[5] = 2
	if _, err := h.relay.Send("alice", "bob", raw); err != nil {
		t.Fatal(err)
	}
	msgs, err := bob.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Err == nil {
		t.Fatalf("expected one reported failure, got %+v", msgs)
	}
}
