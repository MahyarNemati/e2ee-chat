// Package client drives the protocol: it owns the account, establishes sessions
// through the relay and encrypts and decrypts messages.
//
// Everything it sends the relay is either a public key or a ciphertext. The
// test that proves it, rather than the comment that asserts it, is
// TestRelaySeesNoPlaintext.
package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/MahyarNemati/e2ee-chat/internal/keystore"
	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
	"github.com/MahyarNemati/e2ee-chat/internal/ratchet"
	"github.com/MahyarNemati/e2ee-chat/internal/safetynum"
	"github.com/MahyarNemati/e2ee-chat/internal/wire"
	"github.com/MahyarNemati/e2ee-chat/internal/x3dh"
)

// DefaultPreKeyPool is how many one-time prekeys a new account publishes.
const DefaultPreKeyPool = 32

// ErrNoSession is returned when a safety number is asked for before a session
// with that peer exists.
var ErrNoSession = errors.New("client: no session with that peer")

// Config holds the knobs a Client needs.
type Config struct {
	// ServerURL is the relay's base URL.
	ServerURL string
	// HTTP is the client used to reach it; nil means a 30 second default.
	HTTP *http.Client
	// Ratchet bounds the skipped-key cache.
	Ratchet ratchet.Config
	// Rand is the randomness source; nil means crypto/rand.
	Rand io.Reader
}

// session is one conversation: the ratchet plus the peer identity key the
// safety number is computed from.
type session struct {
	PeerIdentity primitives.PublicKey `json:"peer_identity"`
	Ratchet      *ratchet.Session     `json:"-"`
	Raw          json.RawMessage      `json:"ratchet"`
}

type persisted struct {
	Account  *x3dh.Account       `json:"account"`
	Sessions map[string]*session `json:"sessions"`
}

// Client is one user's state and its connection to the relay. It is not safe
// for concurrent use.
type Client struct {
	cfg      Config
	rng      io.Reader
	tr       transport
	account  *x3dh.Account
	sessions map[string]*session
}

// New creates a client around a freshly generated account.
func New(name string, cfg Config) (*Client, error) {
	rng := cfg.Rand
	if rng == nil {
		rng = rand.Reader
	}
	acct, err := x3dh.NewAccount(rng, name, DefaultPreKeyPool)
	if err != nil {
		return nil, err
	}
	return newClient(acct, nil, cfg), nil
}

func newClient(acct *x3dh.Account, sessions map[string]*session, cfg Config) *Client {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if sessions == nil {
		sessions = make(map[string]*session)
	}
	return &Client{
		cfg:      cfg,
		rng:      cfg.Rand,
		tr:       transport{baseURL: cfg.ServerURL, http: cfg.HTTP},
		account:  acct,
		sessions: sessions,
	}
}

// Name is the account name.
func (c *Client) Name() string { return c.account.Name }

// IdentityKey is the account's public identity key.
func (c *Client) IdentityKey() primitives.PublicKey { return c.account.Identity.Public }

// Save encrypts the whole of the client's state under a passphrase and writes
// it to path. The state includes root and chain keys, so this is the only form
// in which it is ever allowed to touch a disk.
func (c *Client) Save(path string, passphrase []byte, params keystore.Params) error {
	for _, s := range c.sessions {
		raw, err := json.Marshal(s.Ratchet)
		if err != nil {
			return fmt.Errorf("client: encode session: %w", err)
		}
		s.Raw = raw
	}
	blob, err := json.Marshal(persisted{Account: c.account, Sessions: c.sessions})
	if err != nil {
		return fmt.Errorf("client: encode state: %w", err)
	}
	defer primitives.Zero(blob)
	return keystore.Save(path, passphrase, blob, params)
}

// Load decrypts a client's state from path.
func Load(path string, passphrase []byte, cfg Config) (*Client, error) {
	blob, err := keystore.LoadFile(path, passphrase)
	if err != nil {
		return nil, err
	}
	defer primitives.Zero(blob)

	var p persisted
	if err := json.Unmarshal(blob, &p); err != nil {
		return nil, fmt.Errorf("client: decode state: %w", err)
	}
	if p.Account == nil {
		return nil, errors.New("client: keystore contains no account")
	}
	rng := cfg.Rand
	if rng == nil {
		rng = rand.Reader
	}
	for peer, s := range p.Sessions {
		s.Ratchet, err = ratchet.Load(rng, cfg.Ratchet, s.Raw)
		if err != nil {
			return nil, fmt.Errorf("client: restore session with %q: %w", peer, err)
		}
	}
	return newClient(p.Account, p.Sessions, cfg), nil
}

// Publish uploads the account's prekey bundle so others can start sessions with
// it while it is offline.
func (c *Client) Publish(ctx context.Context) error {
	return c.tr.publish(ctx, c.account.Publish())
}

// TopUpPreKeys refills the one-time prekey pool if the relay has handed out
// most of it, and republishes. An exhausted pool is not a security failure, but
// it does cost the first message of each new session one Diffie-Hellman.
func (c *Client) TopUpPreKeys(ctx context.Context, low int) (int, error) {
	remaining, err := c.tr.preKeyCount(ctx, c.account.Name)
	if err != nil {
		return 0, err
	}
	if remaining >= low {
		return remaining, nil
	}
	added := DefaultPreKeyPool - remaining
	if err := c.account.AddOneTimePreKeys(c.rng, added); err != nil {
		return remaining, err
	}
	if err := c.Publish(ctx); err != nil {
		return remaining, err
	}
	return remaining + added, nil
}

// Users lists the names the relay knows about.
func (c *Client) Users(ctx context.Context) ([]string, error) { return c.tr.users(ctx) }

// Send encrypts plaintext for peer and hands the ciphertext to the relay,
// establishing a session first if there is not one already.
func (c *Client) Send(ctx context.Context, peer string, plaintext []byte) error {
	s, ok := c.sessions[peer]
	if !ok {
		return c.sendFirst(ctx, peer, plaintext)
	}
	msg, err := s.Ratchet.Encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("client: encrypt for %q: %w", peer, err)
	}
	env := wire.Envelope{Type: wire.TypeNormal, Message: msg}
	return c.tr.send(ctx, c.account.Name, peer, env.Marshal())
}

// sendFirst runs X3DH against a fetched bundle and sends a prekey message. The
// recipient may be offline throughout; that is the property X3DH exists for.
func (c *Client) sendFirst(ctx context.Context, peer string, plaintext []byte) error {
	bundle, err := c.tr.bundle(ctx, peer)
	if err != nil {
		return err
	}
	if bundle.Name != peer {
		return fmt.Errorf("client: asked the relay for %q and got a bundle for %q", peer, bundle.Name)
	}
	// Initiate verifies the signed prekey's signature. The relay checked it
	// too, but a client that relies on the relay's check has delegated its
	// security to the party it is defending against.
	agreed, err := x3dh.Initiate(c.rng, c.account.Identity, bundle)
	if err != nil {
		return fmt.Errorf("client: key agreement with %q: %w", peer, err)
	}

	rt, err := ratchet.NewSender(c.rng, c.cfg.Ratchet, agreed.SharedSecret, agreed.RemoteRatchetKey, agreed.AssociatedData)
	if err != nil {
		return err
	}
	msg, err := rt.Encrypt(plaintext)
	if err != nil {
		return err
	}

	env := wire.Envelope{
		Type:            wire.TypePreKey,
		IdentityKey:     c.account.Identity.Public,
		EphemeralKey:    agreed.EphemeralKey,
		SignedPreKeyID:  agreed.SignedPreKeyID,
		OneTimePreKeyID: agreed.OneTimePreKeyID,
		Message:         msg,
	}
	if err := c.tr.send(ctx, c.account.Name, peer, env.Marshal()); err != nil {
		return err
	}
	c.sessions[peer] = &session{PeerIdentity: bundle.IdentityKey, Ratchet: rt}
	return nil
}

// Message is one decrypted message, or the reason one could not be decrypted.
type Message struct {
	From string
	Text string
	At   time.Time
	// NewSession is true when this message established the session.
	NewSession bool
	// Err is set when this envelope failed. A failure is reported rather than
	// dropped: silently discarding what will not decrypt is how a client hides
	// an attack in progress.
	Err error
}

// Receive collects everything queued for this account and decrypts it. One bad
// envelope does not stop the rest: each is reported in order.
func (c *Client) Receive(ctx context.Context) ([]Message, error) {
	envelopes, err := c.tr.receive(ctx, c.account.Name)
	if err != nil {
		return nil, err
	}
	out := make([]Message, 0, len(envelopes))
	for _, env := range envelopes {
		m := Message{From: env.From, At: env.ReceivedAt}
		text, isNew, err := c.open(env.From, env.Ciphertext)
		m.Text, m.NewSession, m.Err = text, isNew, err
		out = append(out, m)
	}
	return out, nil
}

func (c *Client) open(from string, raw []byte) (string, bool, error) {
	env, err := wire.ParseEnvelope(raw)
	if err != nil {
		return "", false, err
	}

	// An existing session gets first refusal, even for a prekey message: a peer
	// that reinstalled will send a new prekey message, but a replayed old one
	// must not be allowed to tear down a working session.
	if s, ok := c.sessions[from]; ok {
		if text, err := s.Ratchet.Decrypt(env.Message); err == nil {
			return string(text), false, nil
		} else if env.Type != wire.TypePreKey {
			return "", false, fmt.Errorf("client: message from %q: %w", from, err)
		}
	}

	if env.Type != wire.TypePreKey {
		return "", false, fmt.Errorf("client: message from %q with no session: %w", from, ratchet.ErrNoSendingChain)
	}

	accepted, err := x3dh.Accept(c.account, env.IdentityKey, env.EphemeralKey, env.SignedPreKeyID, env.OneTimePreKeyID)
	if err != nil {
		return "", false, fmt.Errorf("client: key agreement from %q: %w", from, err)
	}
	rt := ratchet.NewReceiver(c.rng, c.cfg.Ratchet, accepted.SharedSecret, accepted.RatchetKeyPair, accepted.AssociatedData)
	text, err := rt.Decrypt(env.Message)
	if err != nil {
		// The agreement succeeded but the message did not open: the one-time
		// prekey has been consumed, and no session is recorded.
		return "", false, fmt.Errorf("client: first message from %q: %w", from, err)
	}
	c.sessions[from] = &session{PeerIdentity: accepted.RemoteIdentityKey, Ratchet: rt}
	return string(text), true, nil
}

// SafetyNumber returns the 60 digits this client and peer should compare over a
// channel the relay does not control. If they match, no bundle was substituted.
// If they do not, something between the two of you is reading the conversation.
func (c *Client) SafetyNumber(peer string) (string, error) {
	s, ok := c.sessions[peer]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrNoSession, peer)
	}
	return safetynum.SafetyNumber(c.account.Identity.Public, s.PeerIdentity, c.account.Name, peer), nil
}

// PeerIdentityKey returns the identity key in use for a peer.
func (c *Client) PeerIdentityKey(peer string) (primitives.PublicKey, error) {
	s, ok := c.sessions[peer]
	if !ok {
		return primitives.PublicKey{}, fmt.Errorf("%w: %q", ErrNoSession, peer)
	}
	return s.PeerIdentity, nil
}

// Peers lists the names this client has a session with.
func (c *Client) Peers() []string {
	names := make([]string, 0, len(c.sessions))
	for name := range c.sessions {
		names = append(names, name)
	}
	return names
}
