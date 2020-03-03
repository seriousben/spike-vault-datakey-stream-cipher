package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

const (
	// keySize represents the number of bytes expected for the AES block cipher.
	//
	// 32 bytes is AES-256
	keySize = 32
)

// EncryptWriter wraps a io.Writer into an encryting io.Writer.
//
// The wrapping io.Writer uses an AES block cipher requiring an AES-256 key of 32 bytes
// and an initialization vector (iv) of 16 bytes.
func EncryptWriter(w io.Writer, key []byte, cipherModeIV []byte) (io.Writer, error) {
	if len(key) != keySize {
		return nil, errors.New("unexpected key size")
	}

	if len(cipherModeIV) != aes.BlockSize {
		return nil, errors.New("unexpected iv size")
	}

	// Create the AES block cipher.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Return the encrypted writer.
	return &cipher.StreamWriter{
		S: cipher.NewCTR(block, cipherModeIV),
		W: w,
	}, nil
}

// EncryptReader wraps an io.Reader into an encryting io.Reader.
//
// The wrapping io.Reader uses an AES block cipher requiring an AES-256 key of 32 bytes
// and an initialization vector (iv) of 16 bytes.
func EncryptReader(r io.Reader, key []byte, cipherModeIV []byte) (io.Reader, error) {
	if len(key) != keySize {
		return nil, errors.New("unexpected key size")
	}

	if len(cipherModeIV) != aes.BlockSize {
		return nil, errors.New("unexpected iv size")
	}

	// Create the AES block cipher.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Return the encrypted reader.
	return &cipher.StreamReader{
		S: cipher.NewCTR(block, cipherModeIV),
		R: r,
	}, nil
}
