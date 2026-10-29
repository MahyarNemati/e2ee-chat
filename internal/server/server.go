// Package server is the relay. It stores prekey bundles so a sender can start
// a session while the recipient is offline, and it queues ciphertext for
// collection. That is the whole of it.
//
// The relay holds no key it could decrypt with, and it is never given a
// plaintext to hold. What it can do is: see who talks to whom and when, drop or
// delay messages, exhaust a one-time prekey pool, and -- the one that matters --
// hand out a prekey bundle of its own invention. Only the last of those is
// detectable, and only by comparing safety numbers out of band.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/MahyarNemati/e2ee-chat/internal/x3dh"
)

// Limits on what a single client can push into the relay.
const (
	// MaxEnvelopeBytes bounds one stored ciphertext.
	MaxEnvelopeBytes = 1 << 20
	// MaxQueueLength bounds how many undelivered messages a mailbox holds.
	MaxQueueLength = 1024
	// MaxOneTimePreKeys bounds a published prekey pool.
	MaxOneTimePreKeys = 256
	// MaxRequestBytes bounds a request body before it is parsed.
	MaxRequestBytes = 4 << 20
)

// Errors surfaced to clients.
var (
	ErrNoSuchUser  = errors.New("server: no bundle published for that user")
	ErrQueueFull   = errors.New("server: recipient mailbox is full")
	ErrTooLarge    = errors.New("server: message exceeds the size limit")
	ErrBadRequest  = errors.New("server: malformed request")
	ErrTooManyKeys = errors.New("server: too many one-time prekeys")
)

// Envelope is one queued ciphertext as the relay sees it: two names, a
// timestamp it assigned, and an opaque blob.
type Envelope struct {
	ID         uint64    `json:"id"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	ReceivedAt time.Time `json:"received_at"`
	Ciphertext []byte    `json:"ciphertext"`
}

type account struct {
	published      x3dh.Published
	oneTimePreKeys []x3dh.PreKey
}

// Relay is the in-memory store behind the HTTP API.
type Relay struct {
	mu       sync.Mutex
	accounts map[string]*account
	mailbox  map[string][]Envelope
	nextID   uint64
	now      func() time.Time
}

// NewRelay returns an empty relay.
func NewRelay() *Relay {
	return &Relay{
		accounts: make(map[string]*account),
		mailbox:  make(map[string][]Envelope),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// Publish stores a user's prekey bundle, replacing anything already there.
//
// The relay does not and cannot verify that the identity key belongs to the
// name: it has never met the user. It does check the signed prekey's signature,
// which rules out a corrupt upload, but a client that trusts the relay's check
// instead of doing its own has gained nothing -- which is why the client checks
// it again on fetch.
func (r *Relay) Publish(p x3dh.Published) error {
	if p.Name == "" {
		return fmt.Errorf("%w: empty name", ErrBadRequest)
	}
	if len(p.OneTimePreKeys) > MaxOneTimePreKeys {
		return fmt.Errorf("%w: %d (limit %d)", ErrTooManyKeys, len(p.OneTimePreKeys), MaxOneTimePreKeys)
	}
	probe := x3dh.Bundle{
		Name:                  p.Name,
		IdentityKey:           p.IdentityKey,
		SignedPreKeyID:        p.SignedPreKeyID,
		SignedPreKey:          p.SignedPreKey,
		SignedPreKeySignature: p.SignedPreKeySignature,
	}
	if err := probe.Verify(); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.accounts[p.Name] = &account{published: p, oneTimePreKeys: append([]x3dh.PreKey(nil), p.OneTimePreKeys...)}
	return nil
}

// Bundle hands out a prekey bundle and consumes one one-time prekey. When the
// pool is empty the bundle is returned without one; the session is still
// secure, it just loses one layer of forward secrecy for the first message.
func (r *Relay) Bundle(name string) (x3dh.Bundle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	acct, ok := r.accounts[name]
	if !ok {
		return x3dh.Bundle{}, fmt.Errorf("%w: %q", ErrNoSuchUser, name)
	}
	b := x3dh.Bundle{
		Name:                  acct.published.Name,
		IdentityKey:           acct.published.IdentityKey,
		SignedPreKeyID:        acct.published.SignedPreKeyID,
		SignedPreKey:          acct.published.SignedPreKey,
		SignedPreKeySignature: acct.published.SignedPreKeySignature,
	}
	if len(acct.oneTimePreKeys) > 0 {
		k := acct.oneTimePreKeys[0]
		acct.oneTimePreKeys = acct.oneTimePreKeys[1:]
		b.OneTimePreKeyID, b.OneTimePreKey = k.ID, k.PublicKey
	}
	return b, nil
}

// PreKeyCount reports how many one-time prekeys a user has left, so a client
// knows when to top the pool up.
func (r *Relay) PreKeyCount(name string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	acct, ok := r.accounts[name]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrNoSuchUser, name)
	}
	return len(acct.oneTimePreKeys), nil
}

// Send queues a ciphertext. The relay does not require the recipient to exist:
// refusing for an unknown name would turn the mailbox into an account oracle,
// and the sender has already decided who they are talking to.
func (r *Relay) Send(from, to string, ciphertext []byte) (Envelope, error) {
	if from == "" || to == "" {
		return Envelope{}, fmt.Errorf("%w: sender and recipient are required", ErrBadRequest)
	}
	if len(ciphertext) == 0 {
		return Envelope{}, fmt.Errorf("%w: empty ciphertext", ErrBadRequest)
	}
	if len(ciphertext) > MaxEnvelopeBytes {
		return Envelope{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(ciphertext))
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.mailbox[to]) >= MaxQueueLength {
		return Envelope{}, fmt.Errorf("%w: %q", ErrQueueFull, to)
	}
	r.nextID++
	env := Envelope{
		ID:         r.nextID,
		From:       from,
		To:         to,
		ReceivedAt: r.now(),
		Ciphertext: append([]byte(nil), ciphertext...),
	}
	r.mailbox[to] = append(r.mailbox[to], env)
	return env, nil
}

// Receive drains a mailbox. Messages are handed over in arrival order and
// deleted; the relay keeps nothing once a client has collected it.
func (r *Relay) Receive(name string) []Envelope {
	r.mu.Lock()
	defer r.mu.Unlock()
	queued := r.mailbox[name]
	delete(r.mailbox, name)
	return queued
}

// Users lists the names with a published bundle, for the CLI's directory
// command. A relay that can be asked this is a relay that leaks the social
// graph; a real deployment would not expose it.
func (r *Relay) Users() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.accounts))
	for name := range r.accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Handler wires the relay to HTTP.
type Handler struct {
	relay *Relay
	log   *slog.Logger
	mux   *http.ServeMux
}

// NewHandler returns an http.Handler for the relay.
func NewHandler(relay *Relay, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	h := &Handler{relay: relay, log: log, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /healthz", h.health)
	h.mux.HandleFunc("POST /v1/bundles", h.publish)
	h.mux.HandleFunc("GET /v1/bundles/{name}", h.bundle)
	h.mux.HandleFunc("GET /v1/prekeys/{name}/count", h.preKeyCount)
	h.mux.HandleFunc("POST /v1/messages", h.send)
	h.mux.HandleFunc("GET /v1/messages/{name}", h.receive)
	h.mux.HandleFunc("GET /v1/users", h.users)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) { h.mux.ServeHTTP(w, req) }

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) publish(w http.ResponseWriter, req *http.Request) {
	var p x3dh.Published
	if !decodeJSON(w, req, &p) {
		return
	}
	if err := h.relay.Publish(p); err != nil {
		writeError(w, err)
		return
	}
	h.log.Info("bundle published", "user", p.Name, "one_time_prekeys", len(p.OneTimePreKeys))
	writeJSON(w, http.StatusCreated, map[string]any{"name": p.Name, "one_time_prekeys": len(p.OneTimePreKeys)})
}

func (h *Handler) bundle(w http.ResponseWriter, req *http.Request) {
	b, err := h.relay.Bundle(req.PathValue("name"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (h *Handler) preKeyCount(w http.ResponseWriter, req *http.Request) {
	n, err := h.relay.PreKeyCount(req.PathValue("name"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"remaining": n})
}

// sendRequest is the only place a client-supplied blob enters the relay. Note
// what is absent: any field the relay reads out of the ciphertext.
type sendRequest struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Ciphertext []byte `json:"ciphertext"`
}

func (h *Handler) send(w http.ResponseWriter, req *http.Request) {
	var r sendRequest
	if !decodeJSON(w, req, &r) {
		return
	}
	env, err := h.relay.Send(r.From, r.To, r.Ciphertext)
	if err != nil {
		writeError(w, err)
		return
	}
	h.log.Info("message queued", "from", env.From, "to", env.To, "bytes", len(env.Ciphertext))
	writeJSON(w, http.StatusAccepted, map[string]any{"id": env.ID, "received_at": env.ReceivedAt})
}

func (h *Handler) receive(w http.ResponseWriter, req *http.Request) {
	envelopes := h.relay.Receive(req.PathValue("name"))
	if envelopes == nil {
		envelopes = []Envelope{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": envelopes})
}

func (h *Handler) users(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"users": h.relay.Users()})
}

func decodeJSON(w http.ResponseWriter, req *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, req.Body, MaxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, fmt.Errorf("%w: %v", ErrBadRequest, err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, ErrNoSuchUser):
		status = http.StatusNotFound
	case errors.Is(err, ErrQueueFull):
		status = http.StatusTooManyRequests
	case errors.Is(err, ErrTooLarge):
		status = http.StatusRequestEntityTooLarge
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// Snapshot serialises everything the relay holds: published bundles, remaining
// prekeys and every queued envelope. It exists so that "the relay can decrypt
// nothing" can be asserted against the relay's actual state rather than against
// a description of it.
func (r *Relay) Snapshot() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state := struct {
		Accounts map[string]struct {
			Published      x3dh.Published `json:"published"`
			OneTimePreKeys []x3dh.PreKey  `json:"remaining_one_time_prekeys"`
		} `json:"accounts"`
		Mailboxes map[string][]Envelope `json:"mailboxes"`
	}{
		Accounts: map[string]struct {
			Published      x3dh.Published `json:"published"`
			OneTimePreKeys []x3dh.PreKey  `json:"remaining_one_time_prekeys"`
		}{},
		Mailboxes: r.mailbox,
	}
	for name, acct := range r.accounts {
		state.Accounts[name] = struct {
			Published      x3dh.Published `json:"published"`
			OneTimePreKeys []x3dh.PreKey  `json:"remaining_one_time_prekeys"`
		}{acct.published, acct.oneTimePreKeys}
	}
	return json.MarshalIndent(state, "", "  ")
}
