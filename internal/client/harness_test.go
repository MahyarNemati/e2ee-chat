package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"

	"github.com/MahyarNemati/e2ee-chat/internal/server"
)

// recorder captures every byte that crosses the relay's HTTP boundary, in both
// directions. It is what the no-plaintext test searches.
type recorder struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	requests int
}

func (r *recorder) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))

		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, req)

		r.mu.Lock()
		r.requests++
		r.buf.WriteString(req.Method + " " + req.URL.String() + "\n")
		r.buf.Write(body)
		r.buf.WriteByte('\n')
		r.buf.Write(rec.Body.Bytes())
		r.buf.WriteByte('\n')
		r.mu.Unlock()

		for k, vs := range rec.Header() {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.buf.Bytes())
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests
}

type harness struct {
	t        *testing.T
	relay    *server.Relay
	server   *httptest.Server
	recorder *recorder
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	relay := server.NewRelay()
	rec := &recorder{}
	srv := httptest.NewServer(rec.wrap(server.NewHandler(relay, slog.New(slog.NewTextHandler(io.Discard, nil)))))
	t.Cleanup(srv.Close)
	return &harness{t: t, relay: relay, server: srv, recorder: rec}
}

func (h *harness) config() Config {
	return Config{ServerURL: h.server.URL, HTTP: h.server.Client()}
}

// newUser creates a client and publishes its bundle.
func (h *harness) newUser(name string) *Client {
	h.t.Helper()
	c, err := New(name, h.config())
	if err != nil {
		h.t.Fatal(err)
	}
	if err := c.Publish(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	return c
}

// corpus is everything the relay could possibly have seen: the raw HTTP
// traffic, its own stored state, and every base64 blob in either decoded back
// to bytes. Searching only the raw text would be satisfied by base64 hiding a
// plaintext in plain sight.
func (h *harness) corpus() []byte {
	h.t.Helper()
	snapshot, err := h.relay.Snapshot()
	if err != nil {
		h.t.Fatal(err)
	}
	raw := append(h.recorder.bytes(), snapshot...)
	return append(raw, decodeEveryBase64Blob(raw)...)
}

var base64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)

func decodeEveryBase64Blob(in []byte) []byte {
	var out []byte
	for _, match := range base64Blob.FindAll(in, -1) {
		if decoded, err := base64.StdEncoding.DecodeString(string(match)); err == nil {
			out = append(out, decoded...)
			out = append(out, '\n')
		}
	}
	return out
}

func send(t *testing.T, from *Client, to, text string) {
	t.Helper()
	if err := from.Send(context.Background(), to, []byte(text)); err != nil {
		t.Fatalf("%s -> %s %q: %v", from.Name(), to, text, err)
	}
}

// receiveTexts collects a client's messages and fails on any that did not
// decrypt, so a silently dropped message can never look like success.
func receiveTexts(t *testing.T, c *Client) []string {
	t.Helper()
	msgs, err := c.Receive(context.Background())
	if err != nil {
		t.Fatalf("%s receive: %v", c.Name(), err)
	}
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		if m.Err != nil {
			t.Fatalf("%s: message from %s failed: %v", c.Name(), m.From, m.Err)
		}
		out = append(out, m.Text)
	}
	return out
}
