package main

// Copyright (C) Philip Schlump, 2015-2019.
// This file is MIT Clause licensed.
// See ./LICENSE.mit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// ---------------------------------------------------------------------------
// Key derivation and at-rest encryption for the config file.
//
// The encryption key is derived from the user's passphrase with Argon2id and a
// fresh per-file salt (RFC 9106). This replaces the older single-pass SHA-256
// derivation, which offered no defense against offline brute force.
//
// Encrypted blobs are versioned. The current (v2) wire format is:
//
//	base64( magic[4] || salt[16] || nonce[12] || ciphertext+tag )
//
// where key = Argon2id(passphrase, salt). Blobs without the magic prefix are
// the legacy SHA-256 format; they are still accepted on decrypt so existing
// config files keep opening, and re-saving re-encrypts them as v2.
// ---------------------------------------------------------------------------

const (
	encMagic = "acc2" // version tag for the Argon2id format (v2)

	saltLen = 16

	// Argon2id parameters (RFC 9106). Derived once per config read/write on a
	// developer laptop; 64 MiB / t=1 / p=4 is a modern interactive default.
	argonTime      = 1
	argonMemoryKiB = 64 * 1024 // 64 MiB
	argonParallel  = 4
	keyLen         = 32 // AES-256
)

// HashPassword derives the legacy (v1) key material: a single unsalted
// SHA-256 over the concatenated inputs. It is retained only to decrypt config
// files written by older versions of this tool. New writes use deriveKeyV2.
func HashPassword(a ...string) []byte {
	h := sha256.New()
	for _, z := range a {
		h.Write([]byte(z))
	}
	return h.Sum(nil)
}

// deriveKeyV2 derives the AES-256 key from a passphrase with Argon2id and salt.
func deriveKeyV2(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemoryKiB, argonParallel, keyLen)
}

// EncryptString encrypts plaintext under passphrase using the v2 format
// (Argon2id + per-file salt + AES-256-GCM). The salt and nonce are random per
// call, so identical plaintexts encrypt to different ciphertexts.
func EncryptString(plaintext []byte, passphrase string) (encryptedString string, err error) {

	salt := make([]byte, saltLen)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return
	}
	key := deriveKeyV2([]byte(passphrase), salt)

	// Create a new Cipher Block from the derived key.
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	// Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	// Create a nonce. Nonce is taken from GCM and is random.
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}

	// Encrypt the data using aesGCM.Seal. Layout: magic || salt || nonce || ct.
	// Seal appends ciphertext+tag to dst, so the nonce must be written out
	// explicitly (it is NOT prepended by Seal).
	out := make([]byte, 0, len(encMagic)+len(salt)+len(nonce)+len(plaintext)+aesGCM.Overhead())
	out = append(out, encMagic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = aesGCM.Seal(out, nonce, plaintext, nil)

	// Convert to base 64 string
	return base64.StdEncoding.EncodeToString(out), nil
}

// DecryptString decrypts a blob produced by EncryptString. v2 blobs (Argon2id)
// are handled directly; blobs lacking the v2 magic are treated as the legacy
// SHA-256 format so existing config files still open.
func DecryptString(encryptedString string, passphrase string) (decrypted []byte, err error) {

	raw, err := base64.StdEncoding.DecodeString(encryptedString)
	if err != nil {
		return
	}

	if len(raw) >= len(encMagic) && string(raw[:len(encMagic)]) == encMagic {
		return decryptV2(raw[len(encMagic):], passphrase)
	}
	return decryptLegacy(raw, passphrase)
}

// decryptV2 decrypts the v2 format: raw = salt || nonce || ciphertext+tag.
func decryptV2(raw []byte, passphrase string) ([]byte, error) {

	key := deriveKeyV2([]byte(passphrase), raw[:saltLen])

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(raw) < saltLen+nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes, need at least %d", len(raw), saltLen+nonceSize)
	}

	nonce, ciphertext := raw[saltLen:saltLen+nonceSize], raw[saltLen+nonceSize:]

	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

// encryptLegacy / decryptLegacy implement the pre-v2 format
// (base64(nonce || ciphertext), key = SHA-256(passphrase)). Kept for backward
// compatibility: decryptLegacy is reachable via DecryptString for old config
// files; encryptLegacy is retained as the faithful reference implementation of
// v1 and is used to exercise the legacy decrypt path in tests.
func encryptLegacy(plaintext []byte, passphrase string) (string, error) {
	key := HashPassword(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptLegacy(raw []byte, passphrase string) ([]byte, error) {
	key := HashPassword(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(raw) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes, need at least %d", len(raw), nonceSize)
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

/* vim: set noai ts=4 sw=4: */
