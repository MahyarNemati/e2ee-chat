// Package ratchet implements the Double Ratchet of Signal's specification:
// a symmetric-key ratchet that advances once per message, and a Diffie-Hellman
// ratchet that advances once per round trip.
//
// The two together give the properties the whole project exists to show:
//
//   - Forward secrecy. Each message key is derived from a chain key and then
//     thrown away, and the chain key is replaced by its own successor. Nothing
//     retained after sending a message can reconstruct an earlier message key.
//   - Post-compromise security ("healing"). Every round trip mixes a fresh
//     Diffie-Hellman output into the root key, so an attacker holding a full
//     copy of the state is locked out one round trip later -- provided they
//     stayed passive.
//
// Out-of-order delivery is handled by caching the message keys of messages that
// have not arrived yet, under a hard bound: an attacker who claims a message
// number far in the future must not be able to make a client allocate without
// limit.
package ratchet

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
	"github.com/MahyarNemati/e2ee-chat/internal/wire"
)

// Info strings domain-separate the three key derivations.
const (
	rootInfo    = "e2ee-chat/ratchet/root/v1"
	messageInfo = "e2ee-chat/ratchet/message/v1"
)

// Chain key derivation constants, from the specification.
const (
	messageKeyByte = 0x01
	chainKeyByte   = 0x02
)

// Errors a caller is expected to distinguish.
var (
	// ErrSkipLimit means a header claimed a message number so far ahead that
	// honouring it would mean deriving and storing more keys than the bound
	// allows. Refusing is the point: the alternative is unbounded memory
	// controlled by whoever can inject a header.
	ErrSkipLimit = errors.New("ratchet: too many skipped messages")
	// ErrReplay means this message number has already been consumed on this
	// receiving chain.
	ErrReplay = errors.New("ratchet: message already received")
	// ErrNoSendingChain means Encrypt was called on a responder that has not
	// yet received anything, so it has no sending chain.
	ErrNoSendingChain = errors.New("ratchet: no sending chain yet")
)

// Default bounds. MaxSkip is per chain; MaxSkippedKeys bounds the whole cache
// across chains, after which the oldest cached key is dropped.
const (
	DefaultMaxSkip        = 1000
	DefaultMaxSkippedKeys = 2000
)

// Config bounds the skipped-key cache.
type Config struct {
	// MaxSkip is the largest gap a single header may open in one chain.
	MaxSkip uint32
	// MaxSkippedKeys is the total number of cached message keys retained; the
	// oldest is evicted once it is exceeded. An evicted key means a very late
	// message is no longer decryptable, which is the right trade: bounded
	// memory beats indefinite decryptability.
	MaxSkippedKeys int
}

func (c Config) withDefaults() Config {
	if c.MaxSkip == 0 {
		c.MaxSkip = DefaultMaxSkip
	}
	if c.MaxSkippedKeys == 0 {
		c.MaxSkippedKeys = DefaultMaxSkippedKeys
	}
	return c
}

type chainKey [32]byte
type rootKey [32]byte
type messageKey [32]byte

// skippedID identifies a cached message key. Keying on the ratchet public key
// as well as the number keeps keys from two different chains apart.
type skippedID struct {
	RatchetKey primitives.PublicKey
	Number     uint32
}

// Session is one end of a double ratchet conversation. It is not safe for
// concurrent use.
type Session struct {
	cfg Config
	rng io.Reader

	// associatedData comes from X3DH and binds both identity keys into every
	// AEAD tag for the life of the session.
	associatedData []byte

	sendKeyPair primitives.KeyPair
	recvKey     primitives.PublicKey
	hasRecvKey  bool

	root      rootKey
	sendChain chainKey
	hasSend   bool
	recvChain chainKey
	hasRecv   bool

	sendCount     uint32
	recvCount     uint32
	prevSendCount uint32

	skipped map[skippedID]messageKey
	order   []skippedID
}

// NewSender starts the ratchet as the party that sent the X3DH initial
// message. remoteRatchetKey is the recipient's signed prekey.
func NewSender(r io.Reader, cfg Config, sharedSecret [32]byte, remoteRatchetKey primitives.PublicKey, associatedData []byte) (*Session, error) {
	kp, err := primitives.GenerateKeyPair(r)
	if err != nil {
		return nil, err
	}
	s := newSession(cfg, r, associatedData)
	s.sendKeyPair = kp
	s.recvKey, s.hasRecvKey = remoteRatchetKey, true
	dh, err := primitives.DH(kp.Private, remoteRatchetKey)
	if err != nil {
		return nil, fmt.Errorf("ratchet: initial DH: %w", err)
	}
	s.root, s.sendChain = kdfRoot(rootKey(sharedSecret), dh)
	s.hasSend = true
	return s, nil
}

// NewReceiver starts the ratchet as the party that accepted the X3DH initial
// message. ratchetKeyPair is that party's signed prekey pair, which is also its
// first ratchet key pair; it has no sending chain until it receives.
func NewReceiver(r io.Reader, cfg Config, sharedSecret [32]byte, ratchetKeyPair primitives.KeyPair, associatedData []byte) *Session {
	s := newSession(cfg, r, associatedData)
	s.sendKeyPair = ratchetKeyPair
	s.root = rootKey(sharedSecret)
	return s
}

func newSession(cfg Config, r io.Reader, ad []byte) *Session {
	return &Session{
		cfg:            cfg.withDefaults(),
		rng:            r,
		associatedData: slices.Clone(ad),
		skipped:        make(map[skippedID]messageKey),
	}
}

// Encrypt advances the symmetric-key ratchet by one and seals plaintext. The
// header is authenticated but not encrypted: the relay has to read the ratchet
// key and message number to deliver, and the AEAD tag stops it changing them.
func (s *Session) Encrypt(plaintext []byte) (wire.Message, error) {
	if !s.hasSend {
		return wire.Message{}, ErrNoSendingChain
	}
	mk, next := kdfChain(s.sendChain)
	header := wire.Header{
		RatchetKey:          s.sendKeyPair.Public,
		PreviousChainLength: s.prevSendCount,
		Number:              s.sendCount,
	}
	ct, err := sealWith(mk, s.associatedData, header, plaintext)
	if err != nil {
		return wire.Message{}, err
	}
	s.sendChain, s.sendCount = next, s.sendCount+1
	return wire.Message{Header: header, Ciphertext: ct}, nil
}

// Decrypt authenticates and decrypts a message.
//
// It runs against a copy of the session and commits only on success, so a
// forged, replayed or corrupted message cannot leave the session in a state
// that breaks the next genuine one. Getting this wrong is how a toy
// implementation turns an attacker's single junk packet into a permanent
// denial of service.
func (s *Session) Decrypt(m wire.Message) ([]byte, error) {
	work := s.clone()
	plaintext, err := work.decrypt(m)
	if err != nil {
		return nil, err
	}
	*s = *work
	return plaintext, nil
}

func (s *Session) decrypt(m wire.Message) ([]byte, error) {
	id := skippedID{RatchetKey: m.Header.RatchetKey, Number: m.Header.Number}
	if mk, ok := s.skipped[id]; ok {
		plaintext, err := openWith(mk, s.associatedData, m)
		if err != nil {
			return nil, err
		}
		s.dropSkipped(id)
		return plaintext, nil
	}

	if !s.hasRecvKey || m.Header.RatchetKey != s.recvKey {
		if err := s.skipMessageKeys(m.Header.PreviousChainLength); err != nil {
			return nil, err
		}
		if err := s.dhRatchet(m.Header.RatchetKey); err != nil {
			return nil, err
		}
	}
	if err := s.skipMessageKeys(m.Header.Number); err != nil {
		return nil, err
	}

	mk, next := kdfChain(s.recvChain)
	plaintext, err := openWith(mk, s.associatedData, m)
	if err != nil {
		return nil, err
	}
	s.recvChain, s.recvCount = next, s.recvCount+1
	return plaintext, nil
}

// dhRatchet performs a Diffie-Hellman ratchet step: adopt the peer's new
// ratchet key, derive a receiving chain from it, generate our own new ratchet
// key pair and derive the next sending chain. This is the step that heals the
// session after a compromise.
func (s *Session) dhRatchet(theirKey primitives.PublicKey) error {
	s.prevSendCount, s.sendCount, s.recvCount = s.sendCount, 0, 0
	s.recvKey, s.hasRecvKey = theirKey, true

	dh, err := primitives.DH(s.sendKeyPair.Private, theirKey)
	if err != nil {
		return fmt.Errorf("ratchet: receiving DH: %w", err)
	}
	s.root, s.recvChain = kdfRoot(s.root, dh)
	s.hasRecv = true

	kp, err := primitives.GenerateKeyPair(s.rng)
	if err != nil {
		return err
	}
	s.sendKeyPair = kp
	dh, err = primitives.DH(kp.Private, theirKey)
	if err != nil {
		return fmt.Errorf("ratchet: sending DH: %w", err)
	}
	s.root, s.sendChain = kdfRoot(s.root, dh)
	s.hasSend = true
	return nil
}

// skipMessageKeys derives and caches the message keys for everything between
// the current position and until, so that the messages they belong to can still
// be decrypted when they arrive late.
func (s *Session) skipMessageKeys(until uint32) error {
	if !s.hasRecv {
		if until > 0 {
			return fmt.Errorf("%w: header claims %d earlier messages on a chain that has none", ErrSkipLimit, until)
		}
		return nil
	}
	if until < s.recvCount {
		return fmt.Errorf("%w: message %d, chain is at %d", ErrReplay, until, s.recvCount)
	}
	if until-s.recvCount > s.cfg.MaxSkip {
		return fmt.Errorf("%w: header asks to skip %d, bound is %d", ErrSkipLimit, until-s.recvCount, s.cfg.MaxSkip)
	}
	for s.recvCount < until {
		mk, next := kdfChain(s.recvChain)
		s.putSkipped(skippedID{RatchetKey: s.recvKey, Number: s.recvCount}, mk)
		s.recvChain, s.recvCount = next, s.recvCount+1
	}
	return nil
}

func (s *Session) putSkipped(id skippedID, mk messageKey) {
	if _, exists := s.skipped[id]; !exists {
		s.order = append(s.order, id)
	}
	s.skipped[id] = mk
	// Evict oldest first. The cache is a convenience for late delivery, so the
	// bound is enforced by forgetting rather than by failing.
	for len(s.order) > s.cfg.MaxSkippedKeys {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.skipped, oldest)
	}
}

func (s *Session) dropSkipped(id skippedID) {
	delete(s.skipped, id)
	if i := slices.Index(s.order, id); i >= 0 {
		s.order = slices.Delete(s.order, i, i+1)
	}
}

// SkippedKeyCount reports how many message keys are cached. Exposed so that the
// bound can be asserted by a test rather than assumed.
func (s *Session) SkippedKeyCount() int { return len(s.skipped) }

// SendingRatchetKey is this session's current ratchet public key.
func (s *Session) SendingRatchetKey() primitives.PublicKey { return s.sendKeyPair.Public }

func (s *Session) clone() *Session {
	c := *s
	c.associatedData = slices.Clone(s.associatedData)
	c.skipped = maps.Clone(s.skipped)
	c.order = slices.Clone(s.order)
	return &c
}

func kdfRoot(rk rootKey, dh primitives.SharedSecret) (rootKey, chainKey) {
	out := primitives.HKDF(rk[:], dh[:], rootInfo, 64)
	defer primitives.Zero(out)
	var next rootKey
	var ck chainKey
	copy(next[:], out[:32])
	copy(ck[:], out[32:])
	return next, ck
}

func kdfChain(ck chainKey) (messageKey, chainKey) {
	var mk messageKey
	var next chainKey
	copy(mk[:], primitives.HMACSHA256(ck[:], []byte{messageKeyByte}))
	copy(next[:], primitives.HMACSHA256(ck[:], []byte{chainKeyByte}))
	return mk, next
}

// messageKeyMaterial expands a message key into an AEAD key and nonce. The
// nonce is derived rather than transmitted: a message key is used exactly once,
// so there is nothing to vary.
func messageKeyMaterial(mk messageKey) (key, nonce []byte) {
	salt := make([]byte, 32)
	out := primitives.HKDF(salt, mk[:], messageInfo, primitives.AEADKeyLen+primitives.AEADNonceLen)
	return out[:primitives.AEADKeyLen], out[primitives.AEADKeyLen:]
}

// associatedDataFor is the exact byte string the AEAD authenticates: the
// session's X3DH associated data followed by the full ratchet header. Any
// change to the ratchet key, the previous chain length or the message number
// makes the tag fail.
func associatedDataFor(sessionAD []byte, h wire.Header) []byte {
	ad := make([]byte, 0, len(sessionAD)+wire.HeaderLen)
	ad = append(ad, sessionAD...)
	return append(ad, h.Marshal()...)
}

func sealWith(mk messageKey, sessionAD []byte, h wire.Header, plaintext []byte) ([]byte, error) {
	key, nonce := messageKeyMaterial(mk)
	defer primitives.Zero(key)
	return primitives.Seal(key, nonce, plaintext, associatedDataFor(sessionAD, h))
}

func openWith(mk messageKey, sessionAD []byte, m wire.Message) ([]byte, error) {
	key, nonce := messageKeyMaterial(mk)
	defer primitives.Zero(key)
	return primitives.Open(key, nonce, m.Ciphertext, associatedDataFor(sessionAD, m.Header))
}
