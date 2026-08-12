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
)

func HashPassword(a ...string) []byte {
	h := sha256.New()
	for _, z := range a {
		h.Write([]byte(z))
	}
	return h.Sum(nil)
}

func EncryptString(plaintext []byte, keyString string) (encryptedString string, err error) {

	key := HashPassword(keyString)

	// Create a new Cipher Block from the using key
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	// Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	// See : https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	// Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}

	// Encrypt the data using aesGCM.Seal
	// Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the
	// encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	// Convert to base 64 string
	so := base64.StdEncoding.EncodeToString(ciphertext)

	return so, nil
}

func DecryptString(encryptedString string, keyString string) (decrypted []byte, err error) {

	key := HashPassword(keyString)

	enc, err := base64.StdEncoding.DecodeString(encryptedString)
	if err != nil {
		return
	}

	// Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	// Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	// The ciphertext must at least hold the nonce.
	if len(enc) < nonceSize {
		err = fmt.Errorf("ciphertext too short: %d bytes, need at least %d", len(enc), nonceSize)
		return
	}

	// Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	// Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}

	return plaintext, nil
}

/* vim: set noai ts=4 sw=4: */
