package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahyarNemati/e2ee-chat/internal/x3dh"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func published(t *testing.T, name string, n int) (x3dh.Published, *x3dh.Account) {
	t.Helper()
	acct, err := x3dh.NewAccount(rand.Reader, name, n)
	if err != nil {
		t.Fatal(err)
	}
	return acct.Publish(), acct
}

func TestPublishAndFetchBundle(t *testing.T) {
	r := NewRelay()
	p, acct := published(t, "bob", 3)
	if err := r.Publish(p); err != nil {
		t.Fatal(err)
	}

	b, err := r.Bundle("bob")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(); err != nil {
		t.Fatalf("the relay handed out a bundle that does not verify: %v", err)
	}
	if b.IdentityKey != acct.Identity.Public {
		t.Fatal("the relay changed the identity key")
	}
	if !b.HasOneTimePreKey() {
		t.Fatal("expected a one-time prekey")
	}
}

// Every fetch consumes a different one-time prekey, and the pool runs out
// rather than repeating.
func TestOneTimePreKeysAreHandedOutOnce(t *testing.T) {
	r := NewRelay()
	p, _ := published(t, "bob", 3)
	if err := r.Publish(p); err != nil {
		t.Fatal(err)
	}

	seen := map[uint32]bool{}
	for i := 0; i < 3; i++ {
		b, err := r.Bundle("bob")
		if err != nil {
			t.Fatal(err)
		}
		if !b.HasOneTimePreKey() {
			t.Fatalf("fetch %d: pool exhausted early", i)
		}
		if seen[b.OneTimePreKeyID] {
			t.Fatalf("prekey %d handed out twice", b.OneTimePreKeyID)
		}
		seen[b.OneTimePreKeyID] = true
	}

	b, err := r.Bundle("bob")
	if err != nil {
		t.Fatal(err)
	}
	if b.HasOneTimePreKey() {
		t.Fatal("a fourth prekey appeared from a pool of three")
	}
	if err := b.Verify(); err != nil {
		t.Fatalf("an exhausted bundle must still verify: %v", err)
	}
	if n, err := r.PreKeyCount("bob"); err != nil || n != 0 {
		t.Fatalf("remaining count is %d (%v), want 0", n, err)
	}
}

func TestPublishRejectsBadBundles(t *testing.T) {
	r := NewRelay()
	good, _ := published(t, "bob", 1)

	t.Run("bad signature", func(t *testing.T) {
		p := good
		p.SignedPreKeySignature = bytes.Clone(good.SignedPreKeySignature)
		p.SignedPreKeySignature[0] ^= 0x01
		if err := r.Publish(p); !errors.Is(err, x3dh.ErrBadSignature) {
			t.Fatalf("got %v, want ErrBadSignature", err)
		}
	})
	t.Run("empty name", func(t *testing.T) {
		p := good
		p.Name = ""
		if err := r.Publish(p); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("got %v, want ErrBadRequest", err)
		}
	})
	t.Run("too many prekeys", func(t *testing.T) {
		p := good
		p.OneTimePreKeys = make([]x3dh.PreKey, MaxOneTimePreKeys+1)
		if err := r.Publish(p); !errors.Is(err, ErrTooManyKeys) {
			t.Fatalf("got %v, want ErrTooManyKeys", err)
		}
	})

	if _, err := r.Bundle("bob"); !errors.Is(err, ErrNoSuchUser) {
		t.Fatal("a rejected publish still created an account")
	}
}

func TestUnknownUser(t *testing.T) {
	r := NewRelay()
	if _, err := r.Bundle("nobody"); !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("got %v, want ErrNoSuchUser", err)
	}
	if _, err := r.PreKeyCount("nobody"); !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("got %v, want ErrNoSuchUser", err)
	}
}

func TestMailboxOrderAndDrain(t *testing.T) {
	r := NewRelay()
	for i := 0; i < 5; i++ {
		if _, err := r.Send("alice", "bob", []byte(fmt.Sprintf("ct-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	got := r.Receive("bob")
	if len(got) != 5 {
		t.Fatalf("collected %d messages, want 5", len(got))
	}
	for i, env := range got {
		if string(env.Ciphertext) != fmt.Sprintf("ct-%d", i) {
			t.Fatalf("message %d out of order: %q", i, env.Ciphertext)
		}
		if env.From != "alice" || env.To != "bob" {
			t.Fatalf("message %d has the wrong routing: %+v", i, env)
		}
	}
	if again := r.Receive("bob"); len(again) != 0 {
		t.Fatalf("mailbox still holds %d messages after being drained", len(again))
	}
}

// The relay copies what it is given: a caller mutating its buffer afterwards
// must not change what is queued.
func TestSendCopiesCiphertext(t *testing.T) {
	r := NewRelay()
	buf := []byte("original")
	if _, err := r.Send("alice", "bob", buf); err != nil {
		t.Fatal(err)
	}
	copy(buf, "mutated!")
	if got := string(r.Receive("bob")[0].Ciphertext); got != "original" {
		t.Fatalf("queued ciphertext changed under the relay: %q", got)
	}
}

func TestSendLimits(t *testing.T) {
	r := NewRelay()
	if _, err := r.Send("", "bob", []byte("x")); !errors.Is(err, ErrBadRequest) {
		t.Errorf("empty sender: got %v", err)
	}
	if _, err := r.Send("alice", "", []byte("x")); !errors.Is(err, ErrBadRequest) {
		t.Errorf("empty recipient: got %v", err)
	}
	if _, err := r.Send("alice", "bob", nil); !errors.Is(err, ErrBadRequest) {
		t.Errorf("empty ciphertext: got %v", err)
	}
	if _, err := r.Send("alice", "bob", make([]byte, MaxEnvelopeBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized: got %v", err)
	}
}

// An unbounded mailbox is free storage for whoever wants to fill a disk.
func TestQueueBound(t *testing.T) {
	r := NewRelay()
	for i := 0; i < MaxQueueLength; i++ {
		if _, err := r.Send("alice", "bob", []byte("x")); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := r.Send("alice", "bob", []byte("x")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("got %v, want ErrQueueFull", err)
	}
	// Draining makes room again.
	r.Receive("bob")
	if _, err := r.Send("alice", "bob", []byte("x")); err != nil {
		t.Fatalf("after draining: %v", err)
	}
}

func TestHTTPAPI(t *testing.T) {
	relay := NewRelay()
	srv := httptest.NewServer(NewHandler(relay, quietLogger()))
	defer srv.Close()

	p, _ := published(t, "bob", 2)

	t.Run("health", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("publish and fetch", func(t *testing.T) {
		if code := postJSON(t, srv.URL+"/v1/bundles", p); code != http.StatusCreated {
			t.Fatalf("publish returned %d", code)
		}
		var b x3dh.Bundle
		if code := getJSON(t, srv.URL+"/v1/bundles/bob", &b); code != http.StatusOK {
			t.Fatalf("fetch returned %d", code)
		}
		if err := b.Verify(); err != nil {
			t.Fatalf("fetched bundle does not verify: %v", err)
		}
	})

	t.Run("unknown user is 404", func(t *testing.T) {
		if code := getJSON(t, srv.URL+"/v1/bundles/nobody", &struct{}{}); code != http.StatusNotFound {
			t.Fatalf("status %d, want 404", code)
		}
	})

	t.Run("send and receive", func(t *testing.T) {
		body := map[string]any{"from": "alice", "to": "bob", "ciphertext": []byte("opaque")}
		if code := postJSON(t, srv.URL+"/v1/messages", body); code != http.StatusAccepted {
			t.Fatalf("send returned %d", code)
		}
		var out struct {
			Messages []Envelope `json:"messages"`
		}
		if code := getJSON(t, srv.URL+"/v1/messages/bob", &out); code != http.StatusOK {
			t.Fatalf("receive returned %d", code)
		}
		if len(out.Messages) != 1 || string(out.Messages[0].Ciphertext) != "opaque" {
			t.Fatalf("got %+v", out.Messages)
		}
	})

	t.Run("malformed json is rejected", func(t *testing.T) {
		resp, err := http.Post(srv.URL+"/v1/messages", "application/json", bytes.NewReader([]byte("{")))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", resp.StatusCode)
		}
	})

	t.Run("unknown fields are rejected", func(t *testing.T) {
		body := map[string]any{"from": "alice", "to": "bob", "ciphertext": []byte("x"), "plaintext_hint": "hello"}
		if code := postJSON(t, srv.URL+"/v1/messages", body); code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400: the relay accepted a field it does not understand", code)
		}
	})

	t.Run("users", func(t *testing.T) {
		var out struct {
			Users []string `json:"users"`
		}
		if code := getJSON(t, srv.URL+"/v1/users", &out); code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		if len(out.Users) != 1 || out.Users[0] != "bob" {
			t.Fatalf("got %v", out.Users)
		}
	})
}

func postJSON(t *testing.T, url string, body any) int {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func getJSON(t *testing.T, url string, out any) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return resp.StatusCode
}
