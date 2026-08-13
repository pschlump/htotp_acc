package main

import (
	"encoding/base64"
	"testing"
)

func TestHashPassword_Deterministic(t *testing.T) {
	h1 := HashPassword("secret-key")
	h2 := HashPassword("secret-key")
	if len(h1) != 32 {
		t.Fatalf("expected 32-byte sha256 hash, got %d bytes", len(h1))
	}
	if string(h1) != string(h2) {
		t.Fatal("HashPassword is not deterministic for the same input")
	}
	h3 := HashPassword("other-key")
	if string(h1) == string(h3) {
		t.Fatal("different keys produced the same hash")
	}
}

func TestHashPassword_MultiPart(t *testing.T) {
	// Concatenated writes must equal a single write of the joined string.
	if string(HashPassword("ab", "cd")) != string(HashPassword("abcd")) {
		t.Fatal("multi-part hash does not match hash of concatenation")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := "test-encryption-key"
	plaintext := []byte(`{"ac_config_item":[{"Name":"/example.com:bob"}]}`)

	enc, err := EncryptString(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptString failed: %s", err)
	}
	if enc == "" {
		t.Fatal("EncryptString returned empty string")
	}
	// Output must be valid base64.
	if _, err := base64.StdEncoding.DecodeString(enc); err != nil {
		t.Fatalf("encrypted output is not valid base64: %s", err)
	}

	dec, err := DecryptString(enc, key)
	if err != nil {
		t.Fatalf("DecryptString failed: %s", err)
	}
	if string(dec) != string(plaintext) {
		t.Fatalf("round trip mismatch:\n got: %s\nwant: %s", dec, plaintext)
	}
}

func TestEncrypt_NonceIsRandom(t *testing.T) {
	key := "test-encryption-key"
	plaintext := []byte("same plaintext")

	enc1, err := EncryptString(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptString failed: %s", err)
	}
	enc2, err := EncryptString(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptString failed: %s", err)
	}
	if enc1 == enc2 {
		t.Fatal("two encryptions of the same plaintext produced identical output (nonce reuse)")
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	enc, err := EncryptString([]byte(""), "key")
	if err != nil {
		t.Fatalf("EncryptString failed on empty input: %s", err)
	}
	dec, err := DecryptString(enc, "key")
	if err != nil {
		t.Fatalf("DecryptString failed on empty input round trip: %s", err)
	}
	if len(dec) != 0 {
		t.Fatalf("expected empty plaintext back, got %q", dec)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	enc, err := EncryptString([]byte("sensitive data"), "right-key")
	if err != nil {
		t.Fatalf("EncryptString failed: %s", err)
	}
	if _, err := DecryptString(enc, "wrong-key"); err == nil {
		t.Fatal("DecryptString with wrong key should fail (GCM auth), but succeeded")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	if _, err := DecryptString("!!!not-base64!!!", "key"); err == nil {
		t.Fatal("DecryptString should fail on invalid base64 input")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	// Valid base64 but shorter than the GCM nonce must error, not panic.
	short := base64.StdEncoding.EncodeToString([]byte("tiny"))
	if _, err := DecryptString(short, "key"); err == nil {
		t.Fatal("DecryptString should fail on ciphertext shorter than the nonce")
	}
}

func TestEncrypt_V2Format(t *testing.T) {
	enc, err := EncryptString([]byte("payload"), "pw")
	if err != nil {
		t.Fatalf("EncryptString failed: %s", err)
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("output not valid base64: %s", err)
	}
	if len(raw) < len(encMagic)+saltLen+12 {
		t.Fatalf("v2 blob too short: %d bytes", len(raw))
	}
	if got := string(raw[:len(encMagic)]); got != encMagic {
		t.Fatalf("missing v2 magic prefix: got %q, want %q", got, encMagic)
	}
}

func TestEncrypt_SaltIsRandom(t *testing.T) {
	// A per-file salt means the same plaintext encrypts to different output
	// (this already held for the nonce; the salt is an independent source of
	// variation that also makes each derived key unique).
	a, _ := EncryptString([]byte("same"), "pw")
	b, _ := EncryptString([]byte("same"), "pw")
	if a == b {
		t.Fatal("two encryptions produced identical output (salt reuse)")
	}
}

func TestDecrypt_LegacyBlob(t *testing.T) {
	// A config file written by an older version (no magic prefix, SHA-256 key)
	// must still decrypt, then re-encrypt as v2.
	legacy, err := encryptLegacy([]byte("old config body"), "pw")
	if err != nil {
		t.Fatalf("encryptLegacy failed: %s", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(legacy)
	if len(raw) >= len(encMagic) && string(raw[:len(encMagic)]) == encMagic {
		t.Fatal("legacy blob unexpectedly carries the v2 magic")
	}

	dec, err := DecryptString(legacy, "pw")
	if err != nil {
		t.Fatalf("legacy blob did not decrypt via DecryptString: %s", err)
	}
	if string(dec) != "old config body" {
		t.Fatalf("legacy round trip mismatch: got %q", dec)
	}
	if _, err := DecryptString(legacy, "wrong"); err == nil {
		t.Fatal("legacy decrypt with wrong key should fail (GCM auth)")
	}

	// Re-encrypting upgrades to v2, which must round-trip under the new key.
	enc, err := EncryptString(dec, "pw")
	if err != nil {
		t.Fatalf("re-encrypt failed: %s", err)
	}
	reRaw, _ := base64.StdEncoding.DecodeString(enc)
	if string(reRaw[:len(encMagic)]) != encMagic {
		t.Fatal("re-encrypted blob is not v2")
	}
}
