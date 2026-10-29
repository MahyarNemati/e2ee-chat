package primitives

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
)

// HKDF is HKDF-SHA256 (RFC 5869): extract-then-expand in one call.
func HKDF(salt, ikm []byte, info string, length int) []byte {
	out, err := hkdf.Key(sha256.New, ikm, salt, info, length)
	if err != nil {
		// hkdf.Key only fails for a length beyond 255*HashLen; every caller in
		// this package asks for 32, 44 or 64 bytes.
		panic("primitives: hkdf: " + err.Error())
	}
	return out
}

// HKDFExtract exposes the extract step on its own, for the test vectors.
func HKDFExtract(salt, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		panic("primitives: hkdf extract: " + err.Error())
	}
	return prk
}

// HKDFExpand exposes the expand step on its own, for the test vectors.
func HKDFExpand(prk []byte, info string, length int) []byte {
	out, err := hkdf.Expand(sha256.New, prk, info, length)
	if err != nil {
		panic("primitives: hkdf expand: " + err.Error())
	}
	return out
}

// HMACSHA256 drives the double ratchet's symmetric-key chain.
func HMACSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
