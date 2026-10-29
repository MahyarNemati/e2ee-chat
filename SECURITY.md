# Security

## This is an educational implementation. It has not been audited.

`e2ee-chat` is a from-scratch implementation of two published Signal
specifications, written to be read and tested. It is a portfolio and teaching
artefact.

**Do not use it to protect anything real.** Not because any particular flaw is
known, but because "no known flaw" is not a security property. Real messaging
security comes from implementations that have been reviewed by people who break
things for a living, deployed at a scale that surfaces the failure modes nobody
predicted, and maintained by someone who will still be there next year. This
project has had none of that. If you need end-to-end encryption, use
[Signal](https://signal.org) or [libsignal](https://github.com/signalapp/libsignal).

## What has been done

- Every primitive is checked against its published test vectors (RFC 7748,
  RFC 8439, RFC 5869, RFC 4231) rather than only against itself.
- The protocol's claimed properties each have an adversarial test: forward
  secrecy, post-compromise security, replay rejection, header and ciphertext
  tampering, bounded skipped-key state, and a test that searches everything the
  relay saw for plaintext.
- `go vet`, the race detector and `govulncheck` run on every push.

## What has not been done

- No external review, no formal analysis, no fuzzing campaign beyond the
  bit-flipping the test suite does.
- No constant-time audit. The pure-Go primitives used here
  (`golang.org/x/crypto`, `filippo.io/edwards25519`) are written with care, but
  this project has measured nothing, and the code above them has not been
  reviewed for data-dependent branches or memory access.
- No protection against a compromised endpoint. If the machine running the
  client is owned, the plaintext is owned.
- No metadata protection. The relay sees who talks to whom, when, and how much.
- No key transparency. The safety number is the only defence against a
  substituted prekey bundle, and it only works if two people actually compare
  it over a channel the relay does not control.
- No post-quantum key agreement. X25519 alone is not resistant to a future
  quantum adversary recording traffic today; Signal's PQXDH is not implemented.
- `primitives.Zero` overwrites buffers, but Go gives no guarantee that a value
  was not already copied by the garbage collector, and the keystore passphrase
  passes through strings and environment variables. Treat key zeroing here as
  hygiene, not as a defence against memory forensics.

## Reporting

If you find a flaw, please open an issue. There is no bounty, no embargo and no
production deployment at risk -- a public issue with a clear reproduction is the
most useful thing you can do, and is welcome.
