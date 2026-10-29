package ratchet

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
)

// Sessions outlive a process: the CLI's send and receive are separate runs. The
// serialised form contains root and chain keys, so it is only ever written
// through the passphrase-encrypted keystore.

type skippedEntry struct {
	RatchetKey primitives.PublicKey `json:"ratchet_key"`
	Number     uint32               `json:"number"`
	MessageKey []byte               `json:"message_key"`
}

type sessionState struct {
	AssociatedData []byte               `json:"associated_data"`
	SendKeyPair    primitives.KeyPair   `json:"send_key_pair"`
	RecvKey        primitives.PublicKey `json:"recv_key"`
	HasRecvKey     bool                 `json:"has_recv_key"`
	Root           []byte               `json:"root"`
	SendChain      []byte               `json:"send_chain,omitempty"`
	HasSend        bool                 `json:"has_send"`
	RecvChain      []byte               `json:"recv_chain,omitempty"`
	HasRecv        bool                 `json:"has_recv"`
	SendCount      uint32               `json:"send_count"`
	RecvCount      uint32               `json:"recv_count"`
	PrevSendCount  uint32               `json:"prev_send_count"`
	Skipped        []skippedEntry       `json:"skipped,omitempty"`
}

// MarshalJSON serialises the ratchet state, preserving the insertion order of
// the skipped-key cache so that eviction stays first-in-first-out across a
// reload.
func (s *Session) MarshalJSON() ([]byte, error) {
	st := sessionState{
		AssociatedData: s.associatedData,
		SendKeyPair:    s.sendKeyPair,
		RecvKey:        s.recvKey,
		HasRecvKey:     s.hasRecvKey,
		Root:           s.root[:],
		HasSend:        s.hasSend,
		HasRecv:        s.hasRecv,
		SendCount:      s.sendCount,
		RecvCount:      s.recvCount,
		PrevSendCount:  s.prevSendCount,
	}
	if s.hasSend {
		st.SendChain = s.sendChain[:]
	}
	if s.hasRecv {
		st.RecvChain = s.recvChain[:]
	}
	for _, id := range s.order {
		mk := s.skipped[id]
		st.Skipped = append(st.Skipped, skippedEntry{
			RatchetKey: id.RatchetKey,
			Number:     id.Number,
			MessageKey: slices.Clone(mk[:]),
		})
	}
	return json.Marshal(st)
}

// Load restores a session serialised by MarshalJSON. The bounds and the random
// source are supplied by the caller rather than stored, so a stale file cannot
// talk a client into a larger cache than it is configured for.
func Load(r io.Reader, cfg Config, data []byte) (*Session, error) {
	var st sessionState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("ratchet: decode session: %w", err)
	}
	if len(st.Root) != 32 {
		return nil, fmt.Errorf("ratchet: root key is %d bytes, want 32", len(st.Root))
	}
	s := newSession(cfg, r, st.AssociatedData)
	s.sendKeyPair = st.SendKeyPair
	s.recvKey, s.hasRecvKey = st.RecvKey, st.HasRecvKey
	copy(s.root[:], st.Root)
	s.hasSend, s.hasRecv = st.HasSend, st.HasRecv
	s.sendCount, s.recvCount, s.prevSendCount = st.SendCount, st.RecvCount, st.PrevSendCount
	if st.HasSend {
		if len(st.SendChain) != 32 {
			return nil, fmt.Errorf("ratchet: sending chain key is %d bytes, want 32", len(st.SendChain))
		}
		copy(s.sendChain[:], st.SendChain)
	}
	if st.HasRecv {
		if len(st.RecvChain) != 32 {
			return nil, fmt.Errorf("ratchet: receiving chain key is %d bytes, want 32", len(st.RecvChain))
		}
		copy(s.recvChain[:], st.RecvChain)
	}
	for _, e := range st.Skipped {
		if len(e.MessageKey) != 32 {
			return nil, fmt.Errorf("ratchet: skipped message key is %d bytes, want 32", len(e.MessageKey))
		}
		var mk messageKey
		copy(mk[:], e.MessageKey)
		s.putSkipped(skippedID{RatchetKey: e.RatchetKey, Number: e.Number}, mk)
	}
	return s, nil
}
