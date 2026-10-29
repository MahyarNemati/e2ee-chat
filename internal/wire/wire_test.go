package wire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/MahyarNemati/e2ee-chat/internal/primitives"
)

func sampleHeader() Header {
	var k primitives.PublicKey
	for i := range k {
		k[i] = byte(i)
	}
	return Header{RatchetKey: k, PreviousChainLength: 7, Number: 42}
}

func TestHeaderRoundTrip(t *testing.T) {
	h := sampleHeader()
	raw := h.Marshal()
	if len(raw) != HeaderLen {
		t.Fatalf("header marshalled to %d bytes, want %d", len(raw), HeaderLen)
	}
	got, err := ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("round trip changed the header:\n got %+v\nwant %+v", got, h)
	}
}

// The header's bytes are fed to the AEAD as associated data, so the encoding
// must be injective: two different headers may never produce the same bytes.
func TestHeaderEncodingIsInjective(t *testing.T) {
	base := sampleHeader()
	variants := []Header{
		base,
		{RatchetKey: base.RatchetKey, PreviousChainLength: 42, Number: 7},
		{RatchetKey: base.RatchetKey, PreviousChainLength: 7, Number: 43},
		{RatchetKey: primitives.PublicKey{1}, PreviousChainLength: 7, Number: 42},
	}
	seen := map[string]int{}
	for i, h := range variants {
		enc := string(h.Marshal())
		if j, dup := seen[enc]; dup {
			t.Fatalf("headers %d and %d encode identically", j, i)
		}
		seen[enc] = i
	}
}

func TestParseHeaderRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, HeaderLen - 1, HeaderLen + 1} {
		if _, err := ParseHeader(make([]byte, n)); !errors.Is(err, ErrMalformed) {
			t.Errorf("length %d: got %v, want ErrMalformed", n, err)
		}
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	ciphertext := bytes.Repeat([]byte{0xAB}, 64)
	for _, e := range []Envelope{
		{
			Type:            TypePreKey,
			IdentityKey:     primitives.PublicKey{1, 2, 3},
			EphemeralKey:    primitives.PublicKey{4, 5, 6},
			SignedPreKeyID:  9,
			OneTimePreKeyID: 11,
			Message:         Message{Header: sampleHeader(), Ciphertext: ciphertext},
		},
		{
			Type:    TypeNormal,
			Message: Message{Header: sampleHeader(), Ciphertext: ciphertext},
		},
	} {
		raw := e.Marshal()
		got, err := ParseEnvelope(raw)
		if err != nil {
			t.Fatalf("type %d: %v", e.Type, err)
		}
		if got.Type != e.Type || got.Message.Header != e.Message.Header {
			t.Fatalf("type %d: header changed", e.Type)
		}
		if !bytes.Equal(got.Message.Ciphertext, ciphertext) {
			t.Fatalf("type %d: ciphertext changed", e.Type)
		}
		if e.Type == TypePreKey {
			if got.IdentityKey != e.IdentityKey || got.EphemeralKey != e.EphemeralKey ||
				got.SignedPreKeyID != e.SignedPreKeyID || got.OneTimePreKeyID != e.OneTimePreKeyID {
				t.Fatal("prekey fields changed")
			}
		}
	}
}

// Everything a relay can hand a client has to be refused cleanly rather than
// panicking or silently producing a half-parsed envelope.
func TestParseEnvelopeRejectsGarbage(t *testing.T) {
	valid := Envelope{Type: TypeNormal, Message: Message{Header: sampleHeader(), Ciphertext: bytes.Repeat([]byte{1}, 32)}}.Marshal()

	cases := map[string][]byte{
		"empty":            {},
		"magic only":       []byte(Magic),
		"bad magic":        append([]byte("XXXX"), valid[4:]...),
		"bad version":      append([]byte(Magic), append([]byte{99, byte(TypeNormal)}, valid[6:]...)...),
		"unknown type":     append([]byte(Magic), append([]byte{Version, 77}, valid[6:]...)...),
		"truncated header": valid[:10],
		"no tag room":      valid[:6+HeaderLen+primitives.AEADTagLen-1],
		"prekey truncated": append([]byte(Magic), Version, byte(TypePreKey)),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEnvelope(raw); err == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}

	// Positive control: the input the mutations were derived from does parse.
	if _, err := ParseEnvelope(valid); err != nil {
		t.Fatalf("the reference envelope does not parse: %v", err)
	}
}

// Every byte of a valid envelope matters: flipping any single bit either breaks
// parsing or changes the parsed result. This catches a field that is written
// but never read.
func TestEveryByteOfAnEnvelopeIsParsed(t *testing.T) {
	e := Envelope{
		Type:            TypePreKey,
		IdentityKey:     primitives.PublicKey{1},
		EphemeralKey:    primitives.PublicKey{2},
		SignedPreKeyID:  3,
		OneTimePreKeyID: 4,
		Message:         Message{Header: sampleHeader(), Ciphertext: bytes.Repeat([]byte{5}, 32)},
	}
	raw := e.Marshal()
	reference, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}

	for i := range raw {
		mutated := bytes.Clone(raw)
		mutated[i] ^= 0x01
		got, err := ParseEnvelope(mutated)
		if err != nil {
			continue // rejected outright, which is also fine
		}
		if got.Type == reference.Type && got.IdentityKey == reference.IdentityKey &&
			got.EphemeralKey == reference.EphemeralKey && got.SignedPreKeyID == reference.SignedPreKeyID &&
			got.OneTimePreKeyID == reference.OneTimePreKeyID && got.Message.Header == reference.Message.Header &&
			bytes.Equal(got.Message.Ciphertext, reference.Message.Ciphertext) {
			t.Fatalf("flipping bit 0 of byte %d changed nothing: that byte is not being read", i)
		}
	}
}
