package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/MahyarNemati/e2ee-chat/internal/client"
	"github.com/MahyarNemati/e2ee-chat/internal/keystore"
	"github.com/MahyarNemati/e2ee-chat/internal/safetynum"
	"github.com/MahyarNemati/e2ee-chat/internal/server"
	"golang.org/x/term"
)

// runDemo plays a whole conversation through a real relay in one process, and
// then shows what the relay was holding the entire time. It asserts as it goes,
// so it doubles as a smoke test: if anything here is wrong it exits non-zero
// rather than printing a reassuring transcript.
func runDemo(ctx context.Context, args []string) error {
	fs := newFlagSet("demo")
	keep := fs.Bool("keep-state", false, "leave the keystores on disk and print where they are")
	if err := fs.Parse(args); err != nil {
		return err
	}

	relay := server.NewRelay()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           server.NewHandler(relay, slog.New(slog.NewTextHandler(io.Discard, nil))),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	dir, err := os.MkdirTemp("", "e2ee-chat-demo-")
	if err != nil {
		return err
	}
	if *keep {
		defer fmt.Printf("\nkeystores left in %s\n", dir)
	} else {
		defer os.RemoveAll(dir)
	}

	url := "http://" + ln.Addr().String()
	cfg := client.Config{ServerURL: url}
	section("1. two accounts publish prekey bundles to the relay")

	alice, err := client.New("alice", cfg)
	if err != nil {
		return err
	}
	bob, err := client.New("bob", cfg)
	if err != nil {
		return err
	}
	for _, c := range []*client.Client{alice, bob} {
		if err := c.Publish(ctx); err != nil {
			return err
		}
		fmt.Printf("   %-5s identity key %s, %d one-time prekeys\n", c.Name(), mustText(c), client.DefaultPreKeyPool)
	}
	fmt.Printf("   relay at %s holds public keys only\n", url)

	section("2. alice sends the first message while bob is offline (X3DH)")
	if err := alice.Send(ctx, "bob", []byte("hello bob, this is the first message")); err != nil {
		return err
	}
	fmt.Println(`   alice -> "hello bob, this is the first message"`)
	fmt.Println("   bob has not been online once; the message is already encrypted and queued")

	if err := expect(ctx, bob, "hello bob, this is the first message"); err != nil {
		return err
	}
	fmt.Println(`   bob  <- "hello bob, this is the first message"   (session established)`)

	section("3. a conversation, with the ratchet turning on every round trip")
	script := []struct {
		from, to *client.Client
		text     string
	}{
		{bob, alice, "hello alice, I can read that"},
		{alice, bob, "each message gets its own key"},
		{alice, bob, "and this one gets another"},
		{bob, alice, "a reply steps the DH ratchet"},
		{alice, bob, "which is what heals a compromise"},
	}
	for _, step := range script {
		if err := step.from.Send(ctx, step.to.Name(), []byte(step.text)); err != nil {
			return err
		}
		if err := expect(ctx, step.to, step.text); err != nil {
			return err
		}
		fmt.Printf("   %-5s -> %-5s %q\n", step.from.Name(), step.to.Name(), step.text)
	}

	section("4. out of order and replayed messages")
	for i := 0; i < 4; i++ {
		if err := alice.Send(ctx, "bob", []byte(fmt.Sprintf("out-of-order %d", i))); err != nil {
			return err
		}
	}
	queued := relay.Receive("bob")
	if len(queued) != 4 {
		return fmt.Errorf("expected 4 queued messages, got %d", len(queued))
	}
	// Deliver them backwards, and deliver the last one twice.
	for i := len(queued) - 1; i >= 0; i-- {
		if _, err := relay.Send("alice", "bob", queued[i].Ciphertext); err != nil {
			return err
		}
	}
	if _, err := relay.Send("alice", "bob", queued[3].Ciphertext); err != nil {
		return err
	}
	msgs, err := bob.Receive(ctx)
	if err != nil {
		return err
	}
	var delivered, rejected int
	for _, m := range msgs {
		if m.Err != nil {
			rejected++
			fmt.Printf("   bob  rejected a message: %v\n", trimErr(m.Err))
			continue
		}
		delivered++
		fmt.Printf("   bob  <- %q\n", m.Text)
	}
	if delivered != 4 || rejected != 1 {
		return fmt.Errorf("expected 4 delivered and 1 rejected, got %d and %d", delivered, rejected)
	}
	fmt.Println("   all four arrived despite the reordering; the duplicate was refused")

	section("5. a tampered message")
	if err := alice.Send(ctx, "bob", []byte("the eagle lands at midnight")); err != nil {
		return err
	}
	queued = relay.Receive("bob")
	tampered := bytes.Clone(queued[0].Ciphertext)
	tampered[len(tampered)-1] ^= 0x01 // one bit of the authentication tag
	if _, err := relay.Send("alice", "bob", tampered); err != nil {
		return err
	}
	msgs, err = bob.Receive(ctx)
	if err != nil {
		return err
	}
	if len(msgs) != 1 || msgs[0].Err == nil {
		return errors.New("a tampered message was accepted")
	}
	fmt.Printf("   one bit flipped in the tag -> %v\n", trimErr(msgs[0].Err))
	if err := alice.Send(ctx, "bob", []byte("still talking")); err != nil {
		return err
	}
	if err := expect(ctx, bob, "still talking"); err != nil {
		return err
	}
	fmt.Println("   and the session is unharmed: the next genuine message decrypts")

	section("6. safety numbers")
	fromAlice, err := alice.SafetyNumber("bob")
	if err != nil {
		return err
	}
	fromBob, err := bob.SafetyNumber("alice")
	if err != nil {
		return err
	}
	if fromAlice != fromBob {
		return errors.New("the two sides disagree about the safety number")
	}
	fmt.Println(indent(safetynum.Format(fromAlice)))
	fmt.Println("\n   Both sides computed the same digits. If the relay had substituted a prekey")
	fmt.Println("   bundle, these would differ -- and nothing else would.")

	section("7. keys at rest")
	path := filepath.Join(dir, "alice.keys")
	if err := alice.Save(path, []byte("a demo passphrase"), keystore.DefaultParams()); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if _, err := client.Load(path, []byte("wrong passphrase"), cfg); !errors.Is(err, keystore.ErrWrongPassphrase) {
		return fmt.Errorf("a wrong passphrase gave %v", err)
	}
	reloaded, err := client.Load(path, []byte("a demo passphrase"), cfg)
	if err != nil {
		return err
	}
	if reloaded.IdentityKey() != alice.IdentityKey() {
		return errors.New("the reloaded keystore is a different account")
	}
	fmt.Printf("   %d bytes, mode %o, Argon2id with %d MiB; a wrong passphrase is refused\n",
		info.Size(), info.Mode().Perm(), keystore.DefaultParams().MemoryKiB/1024)

	section("8. everything the relay is holding")
	// Leave one message uncollected so the mailbox is not empty.
	if err := alice.Send(ctx, "bob", []byte("the eagle lands at midnight")); err != nil {
		return err
	}
	snapshot, err := relay.Snapshot()
	if err != nil {
		return err
	}
	if err := printRelayState(snapshot); err != nil {
		return err
	}
	for _, plaintext := range []string{"eagle", "midnight", "hello bob", "still talking", "out-of-order"} {
		if bytes.Contains(snapshot, []byte(plaintext)) {
			return fmt.Errorf("plaintext %q found in the relay's state", plaintext)
		}
	}
	fmt.Println("\n   Public keys, two names, a timestamp and opaque bytes. No message text, and")
	fmt.Println("   no key the relay could decrypt one with -- asserted, not just claimed:")
	fmt.Println("   the demo fails if any of those plaintexts turns up in the state above.")
	return nil
}

// printRelayState renders the relay's stored state compactly: the full prekey
// pools would be thirty lines of base64 that say the same thing as their count.
func printRelayState(snapshot []byte) error {
	var state struct {
		Accounts map[string]struct {
			Published struct {
				IdentityKey    string `json:"identity_key"`
				SignedPreKey   string `json:"signed_pre_key"`
				SignedPreKeyID uint32 `json:"signed_pre_key_id"`
			} `json:"published"`
			OneTimePreKeys []struct{} `json:"remaining_one_time_prekeys"`
		} `json:"accounts"`
		Mailboxes map[string][]struct {
			ID         uint64    `json:"id"`
			From       string    `json:"from"`
			To         string    `json:"to"`
			ReceivedAt time.Time `json:"received_at"`
			Ciphertext []byte    `json:"ciphertext"`
		} `json:"mailboxes"`
	}
	if err := json.Unmarshal(snapshot, &state); err != nil {
		return err
	}

	fmt.Println("   accounts:")
	for _, name := range slices.Sorted(maps.Keys(state.Accounts)) {
		a := state.Accounts[name]
		fmt.Printf("     %-6s identity %s\n", name, a.Published.IdentityKey)
		fmt.Printf("            signed prekey #%d %s\n", a.Published.SignedPreKeyID, a.Published.SignedPreKey)
		fmt.Printf("            %d one-time prekeys left\n", len(a.OneTimePreKeys))
	}
	fmt.Println("   mailboxes:")
	for _, name := range slices.Sorted(maps.Keys(state.Mailboxes)) {
		for _, env := range state.Mailboxes[name] {
			fmt.Printf("     #%d %s -> %s at %s\n", env.ID, env.From, env.To, env.ReceivedAt.Format(time.TimeOnly))
			fmt.Printf("        %d bytes of ciphertext: %s...\n", len(env.Ciphertext), hex.EncodeToString(env.Ciphertext[:24]))
		}
	}
	return nil
}

func expect(ctx context.Context, c *client.Client, want string) error {
	msgs, err := c.Receive(ctx)
	if err != nil {
		return err
	}
	if len(msgs) != 1 {
		return fmt.Errorf("%s: expected one message, got %d", c.Name(), len(msgs))
	}
	if msgs[0].Err != nil {
		return fmt.Errorf("%s: %w", c.Name(), msgs[0].Err)
	}
	if msgs[0].Text != want {
		return fmt.Errorf("%s: got %q, want %q", c.Name(), msgs[0].Text, want)
	}
	return nil
}

func section(title string) {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Printf("\n\033[1m%s\033[0m\n", title)
		return
	}
	fmt.Printf("\n== %s\n", title)
}

func trimErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && i+2 < len(s) {
		return s[i+2:]
	}
	return s
}
