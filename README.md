# e2ee-chat

End-to-end encrypted chat built from the published Signal specifications: an
X3DH asynchronous key agreement and a double ratchet, over a server that stores
ciphertext and public keys and can decrypt nothing.

> **This is an educational implementation and it has not been audited.** It
> exists to be read and tested, not to protect anything real. See
> [SECURITY.md](SECURITY.md). If you need end-to-end encryption, use
> [Signal](https://signal.org).

Written in Go with no cgo. Every primitive is checked against its published test
vectors, and every property the protocol claims has an adversarial test that
tries to break it.

```
$ e2ee-chat demo
```

runs a whole conversation in one process -- key agreement while the recipient is
offline, out-of-order and replayed delivery, a tampered message, safety numbers,
keys at rest -- and then prints everything the relay was holding the entire time.

---

## Contents

- [The properties, and the test for each](#the-properties-and-the-test-for-each)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [How the protocol works](#how-the-protocol-works)
- [What the relay sees](#what-the-relay-sees)
- [The trust assumption](#the-trust-assumption)
- [Testing](#testing)
- [Reference](#reference)
- [What this does not defend against](#what-this-does-not-defend-against)
- [Layout](#layout)

---

## The properties, and the test for each

A cryptographic claim with no adversarial test behind it is decoration. Each row
is a property this implementation claims and the test that tries to falsify it.

| Property | Test |
|---|---|
| Primitives match the published vectors | `primitives.TestX25519Vectors`, `TestChaCha20Poly1305Vector`, `TestHKDFVectors`, `TestHMACSHA256Vector` |
| A first message can be sent while the recipient is offline | `client.TestTwoPartyConversation` |
| An unsigned or re-labelled signed prekey is refused | `x3dh.TestInitiateRefusesUnsignedBundle`, `TestBundleVerifyRejectsTampering` |
| A one-time prekey is used exactly once | `x3dh.TestOneTimePreKeyIsConsumedOnce` |
| **Forward secrecy**: stealing the state does not open earlier messages | `ratchet.TestForwardSecrecy` |
| **Post-compromise security**: the session heals after a round trip | `ratchet.TestPostCompromiseSecurity` |
| Out-of-order and late messages still decrypt | `ratchet.TestOutOfOrderDelivery`, `client.TestOutOfOrderDeliveryThroughTheRelay` |
| Skipped-key state is bounded in both directions | `ratchet.TestSkipLimitEnforced`, `TestSkippedKeyCacheIsBounded`, `TestAbsurdMessageNumberRefused` |
| A replayed message is rejected | `ratchet.TestDuplicateDeliveryRejected`, `client.TestReplayedEnvelopeIsRejected`, `TestReplayedFirstMessageIsRejected` |
| A tampered header or ciphertext is rejected, and the session survives | `ratchet.TestTamperedHeaderRejected`, `client.TestTamperedCiphertextIsReportedAndTheSessionSurvives` |
| **The relay never sees plaintext** | `client.TestRelaySeesNoPlaintext` |
| A substituted bundle is undetectable *except* by safety number | `client.TestSubstitutedBundleReadsTheConversationButChangesTheSafetyNumber` |
| Keys at rest are unreadable without the passphrase | `keystore.TestSealedFileContainsNoPlaintext`, `client.TestKeystoreFileContainsNoKeyMaterial` |
| The CLI a reader will actually run works end to end | `main.TestCLIEndToEnd` |

CI will not go green unless each of these ran *by name*: a suite that compiles,
runs and tests nothing is the failure mode these projects keep hitting, so the
workflow greps the verbose output for every one of them.

---

## Architecture

```
        alice                            relay                             bob
   ┌──────────────┐              ┌──────────────────┐              ┌──────────────┐
   │ identity key │              │                  │              │ identity key │
   │ signed prekey│   publish    │  prekey bundles  │   publish    │ signed prekey│
   │ one-time keys│ ───────────► │   (public keys)  │ ◄─────────── │ one-time keys│
   └──────┬───────┘              │                  │              └───────┬──────┘
          │                      │                  │                      │
          │   GET /v1/bundles/bob│                  │                      │
          │ ◄────────────────────┤   one bundle,    │                      │
          │                      │   one-time key   │                      │
          │                      │    consumed      │                      │
   ┌──────▼───────┐              │                  │              ┌───────▼──────┐
   │ X3DH         │              │                  │              │ X3DH         │
   │ 4 × X25519   │              │                  │              │ 4 × X25519   │
   │  → shared    │              │   mailboxes      │              │  → same      │
   │    secret    │              │  (opaque bytes)  │              │    secret    │
   └──────┬───────┘              │                  │              └───────┬──────┘
          │                      │                  │                      │
   ┌──────▼───────┐   POST       │  ┌────────────┐  │   GET        ┌───────▼──────┐
   │ double       │  /v1/messages│  │ ciphertext │  │ /v1/messages │ double       │
   │ ratchet      │ ───────────► │  │ + header   │  │ ───────────► │ ratchet      │
   │ ChaCha20-    │              │  └────────────┘  │              │ ChaCha20-    │
   │ Poly1305     │              │                  │              │ Poly1305     │
   └──────────────┘              └──────────────────┘              └──────────────┘
          │                                                                │
   ┌──────▼───────┐                                                ┌───────▼──────┐
   │ keystore     │   Argon2id(passphrase) → XChaCha20-Poly1305    │ keystore     │
   │ alice.keys   │                                                │ bob.keys     │
   └──────────────┘                                                └──────────────┘

                    safety number: 43658 76209 17727 47423 ...
                    compared out of band -- the only check the relay cannot forge
```

The relay is a `net/http` server with two maps: name → published bundle, and
name → queue of opaque envelopes. It holds no key it could decrypt with, and it
is never given a plaintext to hold.

---

## Quickstart

Go 1.25 or newer. No cgo, no database, no external services.

```bash
go build -o bin/e2ee-chat ./cmd/e2ee-chat
```

### The whole thing in one command

```bash
./bin/e2ee-chat demo
```

This starts a relay on a loopback port, creates two accounts, and plays a
conversation through it, asserting as it goes -- it exits non-zero if any of its
own claims fail. The last section prints the relay's complete state.

### Two people, three terminals

```bash
# terminal 1 -- the relay
./bin/e2ee-chat serve -v

# terminal 2 -- alice
export E2EE_CHAT_PASSPHRASE='a long passphrase'      # or be prompted
./bin/e2ee-chat init -user alice
./bin/e2ee-chat chat -user alice -to bob

# terminal 3 -- bob
export E2EE_CHAT_PASSPHRASE='a different passphrase'
./bin/e2ee-chat init -user bob
./bin/e2ee-chat chat -user bob -to alice
```

The first message each way prints a safety number. Compare them. See
[the trust assumption](#the-trust-assumption) for why that is not optional.

Bob does not have to be running when Alice sends her first message -- that is
the whole purpose of X3DH. Try it: `init` bob, stop, have alice `send`, and
start bob later.

### Docker

```bash
docker compose up relay              # the relay on :8080
docker compose run --rm demo         # the scripted conversation
```

---

## How the protocol works

### X3DH -- starting a session with someone who is offline

Each account publishes a bundle of **public** keys to the relay:

| Key | Lifetime | Purpose |
|---|---|---|
| Identity key `IK` | permanent | who you are; also signs the signed prekey |
| Signed prekey `SPK` | rotated | the recipient's first ratchet key; signed by `IK` |
| One-time prekeys `OPK` | single use | one extra Diffie-Hellman for the first message |

A sender fetches one bundle, **verifies the signed prekey's signature**, and
computes four Diffie-Hellman results:

```
DH1 = DH(IK_A, SPK_B)    authenticates the sender to the recipient
DH2 = DH(EK_A, IK_B)     authenticates the recipient to the sender
DH3 = DH(EK_A, SPK_B)    forward secrecy against a later identity compromise
DH4 = DH(EK_A, OPK_B)    forward secrecy against a signed-prekey compromise

SK  = HKDF-SHA256(0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4)
```

`EK_A` is a fresh ephemeral key, sent in the first message along with the ids of
the prekeys used. DH4 is dropped when the pool is exhausted; the session is
still secure, it just loses one layer for the first message. The associated
data for the rest of the session is `IK_A ‖ IK_B`, so both identity keys are
bound into every ciphertext from then on.

**The signature matters.** Without it, the relay could pair the genuine identity
key with a signed prekey of its own, complete the agreement itself, and relay
re-encrypted messages to the real recipient; nothing either end could see would
be out of place. With it, the relay has to substitute the identity key too --
which is the one thing a user can check. `x3dh.TestInitiateRefusesUnsignedBundle`
pins the refusal; `TestASelfConsistentSubstitutedBundleVerifies` pins what the
signature does *not* buy you.

### The double ratchet -- a new key for every message

Two ratchets turn:

- A **symmetric-key ratchet**, once per message. A chain key becomes a message
  key and its own successor:
  `mk = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)`. The old chain key is discarded,
  so nothing kept after sending can reconstruct an earlier message key. That is
  forward secrecy.
- A **Diffie-Hellman ratchet**, once per round trip. Receiving a message under a
  new ratchet public key makes you generate your own fresh ratchet key pair and
  mix two new DH results into the root key. An attacker holding a full copy of
  the state is locked out as soon as each side has contributed a ratchet key
  they never saw. That is post-compromise security, and
  `ratchet.TestPostCompromiseSecurity` traces the exact point at which each
  direction closes -- it is a full round trip, not instant, and the test says so
  rather than overclaiming.

Messages are sealed with ChaCha20-Poly1305 under a key and nonce expanded from
the message key, with the X3DH associated data **and the full ratchet header**
as the AEAD's associated data. The header is authenticated but not encrypted:
the relay has to read the ratchet key and message number to deliver, and the tag
stops it changing them.

### Out of order, and the part most toy implementations skip

Networks reorder and delay. When a message arrives with a number ahead of the
chain, the keys in between are derived and cached so that the late messages
still decrypt. Cached keys are deleted the moment they are used, which is what
makes a replay fail.

A header, though, is attacker-controlled. "Message number 2³¹" would mean
deriving and storing two billion keys. So the cache is bounded twice:

- `MaxSkip` (default 1000) is the largest gap a single header may open in one
  chain. Beyond it the message is **refused** -- `ratchet.ErrSkipLimit`.
- `MaxSkippedKeys` (default 2000) bounds the whole cache across chains; beyond
  it the **oldest cached key is evicted**. A very late message then no longer
  decrypts, which is the right trade: bounded memory beats indefinite
  decryptability.

Decryption runs against a *copy* of the session and commits only on success, so
a forged, replayed or corrupted message cannot leave the ratchet in a state that
breaks the next genuine one. Getting that wrong turns one junk packet into a
permanent denial of service.

---

## What the relay sees

`e2ee-chat demo` ends by dumping the relay's entire state:

```
   accounts:
     alice  identity Kz8IqJwfYa4XNHs1xySdKoK35asqAPJ82Sb+dJfNq1k=
            signed prekey #1 xMy/oS0zThfg+R9X8R7Z1XRo3P4pjtA3787K5clxhQ4=
            32 one-time prekeys left
     bob    identity S8gP8c79U2vDe/VqrLV2swwlnpjkQRIPoF+2krW6zR4=
            signed prekey #1 ySKiwhEVFIWY6KUBBNg6FgAJ65VmI7ZXgap1X+teVzM=
            31 one-time prekeys left
   mailboxes:
     #19 alice -> bob at 02:10:11
        89 bytes of ciphertext: 4532454501022dbee1cc380e339a9a5a58949f503ff69dac...
```

Public keys, two names, a timestamp, and opaque bytes.

The claim is checked rather than asserted. `client.TestRelaySeesNoPlaintext`
records **every byte** crossing the relay's HTTP boundary in both directions,
adds the relay's own stored state, decodes every base64 blob in either, and
searches the lot for each plaintext and for every word of eight characters or
more in them.

A negative test like that is only worth as much as its controls, so it also
checks that the capture is non-trivial, that it contains the markers it should,
and -- the important one -- that a **canary plaintext pushed through the relay
the same way a ciphertext travels is found**. Without that last check the test
would also pass for a search that cannot see through base64 at all, which is the
only place a leak could realistically hide.

---

## The trust assumption

Everything above holds **as long as the identity key you have for someone is
really theirs**.

Nothing in the protocol can establish that. The relay hands out bundles; a
malicious relay can hand out its own, signed with its own identity key, and
every check inside the protocol passes, because the bundle is internally
consistent. It then holds one session with you and another with the person you
meant, and reads everything in between.

The single observable consequence is the **safety number**: 60 digits derived
from both identity keys (5200 iterations of SHA-512, Signal's construction, in
`internal/safetynum`). Both sides compute the same digits from the same pair of
keys. Substitute one key and the digits change.

```bash
e2ee-chat safety -user alice -peer bob
```

Read them to each other over a channel the relay does not control -- in person,
over a voice call you recognise. If they match, no bundle was substituted. If
they do not, someone is between you, and nothing else in this system will tell
you.

`client.TestSubstitutedBundleReadsTheConversationButChangesTheSafetyNumber`
mounts exactly this attack: an impostor republishes under the name `bob`, reads
the message Alice sends, the real Bob receives nothing -- and the safety numbers
no longer match. The attack succeeds, which is the point of the test.

---

## Testing

```bash
make test       # everything
make race       # with the race detector (needs cgo)
make vectors    # just the known-answer tests, verbosely
make demo       # the scripted conversation
```

### Known-answer tests

The primitives are checked against the published vectors. If an implementation
disagrees with a vector, it is the implementation that is wrong -- and a
round-trip test would happily agree with itself forever.

| Primitive | Source |
|---|---|
| X25519 scalar multiplication | RFC 7748 §5.2 |
| X25519 Diffie-Hellman | RFC 7748 §6.1 |
| ChaCha20-Poly1305 AEAD | RFC 8439 §2.8.2 |
| HKDF-SHA256 (extract, expand, one-shot) | RFC 5869 appendix A.1-A.3 |
| HMAC-SHA256 | RFC 4231 case 2 |

XEdDSA has no published vectors, so it is checked structurally instead: the
Montgomery-to-Edwards conversion is cross-checked against `edwards25519`'s
independent inverse map, in both branches of the sign-bit fix-up, and the test
fails if a run did not exercise both. Argon2id has no RFC 9106 vector usable
here either -- the published one uses a secret key and associated data, which
`x/crypto/argon2` does not expose -- so it is checked for determinism, salt
sensitivity and parameter sensitivity instead, and the file header is
authenticated so the cost parameters cannot be rewritten.

### Adversarial tests

Beyond the properties table: every byte of a valid wire envelope is flipped and
the parse must change or fail (a field that is written but never read would
otherwise go unnoticed); every byte of the keystore header is flipped and must
refuse to open; low-order X25519 points, non-canonical signature scalars,
truncated ciphertexts, mislabelled envelope types, absurd message numbers and
oversized uploads all have their own case.

**One real bug this found.** The keystore test that flips every header byte hung
the suite: a flipped bit in the Argon2id pass count turned three passes into
sixteen million, and `Open` derives the key before it does anything else. The
parameters in the header are now bounded before Argon2id is allowed to run.

---

## Reference

### Commands

| Command | What it does |
|---|---|
| `serve -addr :8080 [-v]` | run the relay |
| `init -user NAME [-force]` | generate keys, publish a bundle, write the keystore |
| `send -user NAME -to PEER -m TEXT` | encrypt and queue (reads stdin if `-m` is omitted) |
| `recv -user NAME [-watch 2s]` | collect and decrypt |
| `chat -user NAME -to PEER [-poll 1s]` | interactive session |
| `safety -user NAME -peer PEER` | the 60-digit number to compare out of band |
| `users -user NAME` | names the relay has bundles for |
| `demo [-keep-state]` | a whole conversation in one process |
| `version` | the build version |

Common flags: `-server` (relay URL, default `http://localhost:8080`), `-store`
(keystore path, default `~/.e2ee-chat/<user>.keys`).

### Environment

| Variable | Meaning |
|---|---|
| `E2EE_CHAT_PASSPHRASE` | keystore passphrase; prompted without echo if unset |
| `E2EE_CHAT_SERVER` | default relay URL |

There is deliberately no `-passphrase` flag: a command line ends up in the
shell history and in `/proc`.

### Relay HTTP API

| Method | Path | Body / result |
|---|---|---|
| `GET` | `/healthz` | `{"status":"ok"}` |
| `POST` | `/v1/bundles` | a published bundle; the signature is verified before it is stored |
| `GET` | `/v1/bundles/{name}` | one bundle, consuming a one-time prekey |
| `GET` | `/v1/prekeys/{name}/count` | how many one-time prekeys remain |
| `POST` | `/v1/messages` | `{"from","to","ciphertext"}` -- the ciphertext is opaque |
| `GET` | `/v1/messages/{name}` | drains the mailbox |
| `GET` | `/v1/users` | names with a published bundle |

Limits: 1 MiB per envelope, 1024 queued messages per mailbox, 256 one-time
prekeys per bundle, 4 MiB per request. Unknown JSON fields are rejected -- a
relay that silently accepts a field it does not understand is a relay you cannot
reason about.

`GET /v1/users` leaks the social graph and a real deployment would not expose
it. It is here so the CLI has a directory.

### Wire format

```
envelope := "E2EE" ‖ version:u8 ‖ type:u8
            [ type == prekey: IK_A:32 ‖ EK_A:32 ‖ spk_id:u32 ‖ otpk_id:u32 ]
            header ‖ ciphertext

header   := ratchet_key:32 ‖ previous_chain_length:u32 ‖ message_number:u32   (40 bytes)
AEAD ad  := "e2ee-chat/X3DH/ad/v1" ‖ IK_A ‖ IK_B ‖ header
```

Explicit rather than reflective, because the header's exact bytes are the AEAD's
associated data: "what the header is" has to be one unambiguous thing.

### Keystore format

```
"E2EEKEY1" ‖ kdf:u8 ‖ time:u32 ‖ memory_kib:u32 ‖ lanes:u8 ‖ salt:16 ‖ nonce:24 ‖ ciphertext
└──────────────────────── authenticated as associated data ────────────────────────┘
```

Argon2id (64 MiB, 3 passes, 4 lanes by default -- RFC 9106 §4's second
recommended option) derives an XChaCha20-Poly1305 key. The header is associated
data, so the cost parameters cannot be rewritten down and handed back, and they
are bounded on read so a hostile file cannot ask for sixteen million passes.
Saves are atomic (write to a temporary file, then rename) and mode `0600`.

---

## What this does not defend against

Being specific about this is part of the work.

- **Metadata.** The relay sees who talks to whom, when, how often and how much.
  Sealed sender, padding and cover traffic are not implemented.
- **A compromised endpoint.** If the machine running the client is owned, the
  plaintext is owned. Nothing in a messaging protocol helps with that.
- **Timing side channels.** The pure-Go primitives in `x/crypto` and
  `filippo.io/edwards25519` are written with care, but this project has measured
  nothing. Every authenticator comparison here is constant-time
  (`primitives.ConstantTimeEqual`), and that is as far as the claim goes.
- **Memory forensics.** `primitives.Zero` wipes buffers, but Go may already have
  copied the value, and the passphrase passes through strings and the
  environment.
- **A quantum adversary recording traffic today.** X25519 alone. Signal's PQXDH
  is not implemented.
- **Denial of service by the relay.** It can drop, delay and reorder freely. It
  can also exhaust a one-time prekey pool; sessions then form without DH4, which
  is weaker but not broken.
- **Key transparency.** Safety numbers only work if two people actually compare
  them. There is no directory you can audit, no gossip, no transparency log.
- **Multi-device, group messaging, message franking, disappearing messages.**
  Not implemented, and each is a real design problem rather than a missing
  feature.

---

## Layout

```
cmd/e2ee-chat/        the CLI: serve, init, send, recv, chat, safety, demo
internal/primitives/  X25519, XEdDSA, HKDF, HMAC, ChaCha20-Poly1305 + the vectors
internal/x3dh/        identity, prekeys, bundles, the four-DH agreement
internal/ratchet/     the double ratchet, skipped keys, session serialisation
internal/wire/        the byte-level envelope and header encoding
internal/safetynum/   Signal's fingerprint construction
internal/keystore/    Argon2id + XChaCha20-Poly1305 keys at rest
internal/server/      the relay: bundles in, ciphertext through
internal/client/      account, sessions, and the end-to-end tests
```

Dependencies: `golang.org/x/crypto` (X25519, ChaCha20-Poly1305, Argon2id),
`filippo.io/edwards25519` (the Edwards arithmetic XEdDSA needs),
`golang.org/x/term` (reading a passphrase without echo). Everything else is the
standard library.

## Reading

- [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [XEdDSA and VXEdDSA](https://signal.org/docs/specifications/xeddsa/)

## License

MIT -- see [LICENSE](LICENSE).
