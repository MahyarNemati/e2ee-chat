package main

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahyarNemati/e2ee-chat/internal/server"
)

// The demo asserts its own invariants, so running it here means a regression in
// the protocol shows up as a test failure rather than as a transcript nobody
// reads.
func TestDemoRuns(t *testing.T) {
	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan []byte, 1)
	go func() {
		out, _ := io.ReadAll(r)
		done <- out
	}()

	runErr := runDemo(context.Background(), nil)
	w.Close()
	os.Stdout = stdout
	out := <-done

	if runErr != nil {
		t.Fatalf("demo failed: %v\n%s", runErr, out)
	}
	for _, marker := range []string{
		"two accounts publish prekey bundles",
		"session established",
		"safety numbers",
		"everything the relay is holding",
		"bytes of ciphertext",
	} {
		if !strings.Contains(string(out), marker) {
			t.Errorf("demo output does not mention %q", marker)
		}
	}
	// runDemo itself fails if a plaintext turns up in the relay's state; this
	// confirms it got far enough to make that check.
	if !strings.Contains(string(out), "asserted, not just claimed") {
		t.Error("the demo did not reach its no-plaintext assertion")
	}
}

// A compiled binary, driven exactly the way the README tells a reader to drive
// it. Testing the packages without testing the entrypoint leaves the one part
// a reader will actually run completely unexercised.
func TestCLIEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary and runs Argon2id several times")
	}

	bin := filepath.Join(t.TempDir(), "e2ee-chat")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	relay := httptest.NewServer(server.NewHandler(server.NewRelay(), slog.New(slog.NewTextHandler(io.Discard, nil))))
	defer relay.Close()

	dir := t.TempDir()
	run := func(t *testing.T, args ...string) string {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(),
			"E2EE_CHAT_PASSPHRASE=a passphrase for the test",
			"E2EE_CHAT_SERVER="+relay.URL,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("e2ee-chat %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	store := func(name string) string { return filepath.Join(dir, name+".keys") }

	for _, name := range []string{"alice", "bob"} {
		out := run(t, "init", "-user", name, "-store", store(name))
		if !strings.Contains(out, "one-time prekeys") {
			t.Fatalf("init for %s printed %q", name, out)
		}
		if _, err := os.Stat(store(name)); err != nil {
			t.Fatalf("init did not create a keystore: %v", err)
		}
	}

	// Alice opens the conversation; Bob has never run anything but init.
	run(t, "send", "-user", "alice", "-store", store("alice"), "-to", "bob", "-m", "the eagle lands at midnight")

	got := run(t, "recv", "-user", "bob", "-store", store("bob"))
	if !strings.Contains(got, "the eagle lands at midnight") {
		t.Fatalf("bob did not receive the message:\n%s", got)
	}
	if !strings.Contains(got, "safety number") {
		t.Fatalf("a new session did not print a safety number:\n%s", got)
	}

	// And back the other way, which steps the DH ratchet.
	run(t, "send", "-user", "bob", "-store", store("bob"), "-to", "alice", "-m", "received and decrypted")
	if got := run(t, "recv", "-user", "alice", "-store", store("alice")); !strings.Contains(got, "received and decrypted") {
		t.Fatalf("alice did not receive the reply:\n%s", got)
	}

	// Both sides print the same safety number.
	aliceNum := digits(run(t, "safety", "-user", "alice", "-store", store("alice"), "-peer", "bob"))
	bobNum := digits(run(t, "safety", "-user", "bob", "-store", store("bob"), "-peer", "alice"))
	if len(aliceNum) != 60 {
		t.Fatalf("alice printed %d digits, want 60", len(aliceNum))
	}
	if aliceNum != bobNum {
		t.Fatalf("safety numbers differ:\nalice %s\nbob   %s", aliceNum, bobNum)
	}

	if users := run(t, "users", "-user", "alice", "-store", store("alice")); !strings.Contains(users, "alice") || !strings.Contains(users, "bob") {
		t.Fatalf("users listed %q", users)
	}

	// A wrong passphrase must not open the keystore.
	cmd := exec.Command(bin, "recv", "-user", "alice", "-store", store("alice"))
	cmd.Env = append(os.Environ(), "E2EE_CHAT_PASSPHRASE=wrong", "E2EE_CHAT_SERVER="+relay.URL)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("a wrong passphrase succeeded: %s", out)
	}
	if !strings.Contains(string(out), "passphrase") {
		t.Fatalf("unhelpful error for a wrong passphrase: %s", out)
	}

	// The keystore on disk is opaque.
	raw, err := os.ReadFile(store("alice"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"alice", "bob", "eagle", "account"} {
		if strings.Contains(string(raw), marker) {
			t.Errorf("%q is readable in the keystore file", marker)
		}
	}
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
