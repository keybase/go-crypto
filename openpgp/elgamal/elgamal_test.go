// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package elgamal

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

// This is the 1024-bit MODP group from RFC 5114, section 2.1:
const primeHex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"

const generatorHex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

func fromHex(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("failed to parse hex number")
	}
	return n
}

func TestEncryptDecrypt(t *testing.T) {
	priv := &PrivateKey{
		PublicKey: PublicKey{
			G: fromHex(generatorHex),
			P: fromHex(primeHex),
		},
		X: fromHex("42"),
	}
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	message := []byte("hello world")
	c1, c2, err := Encrypt(rand.Reader, &priv.PublicKey, message)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}
	message2, err := Decrypt(priv, c1, c2)
	if err != nil {
		t.Errorf("error decrypting: %s", err)
	}
	if !bytes.Equal(message2, message) {
		t.Errorf("decryption failed, got: %x, want: %x", message2, message)
	}
}

func TestEncryptDecryptShortMessage(t *testing.T) {
	priv := &PrivateKey{
		PublicKey: PublicKey{
			G: fromHex(generatorHex),
			P: fromHex(primeHex),
		},
		X: fromHex("42"),
	}
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	for _, n := range []int{0, 1, 2} {
		message := make([]byte, n)
		c1, c2, err := Encrypt(rand.Reader, &priv.PublicKey, message)
		if err != nil {
			t.Fatalf("n=%d: encrypt: %s", n, err)
		}
		got, err := Decrypt(priv, c1, c2)
		if err != nil {
			t.Fatalf("n=%d: decrypt: %s", n, err)
		}
		if !bytes.Equal(got, message) {
			t.Fatalf("n=%d: got %x, want %x", n, got, message)
		}
	}
}

func TestDecryptBadKey(t *testing.T) {
	priv := &PrivateKey{
		PublicKey: PublicKey{
			G: fromHex(generatorHex),
			P: fromHex("2"),
		},
		X: fromHex("42"),
	}
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)
	c1, c2 := fromHex("8"), fromHex("8")
	_, err := Decrypt(priv, c1, c2)
	if err == nil || err.Error() != "elgamal: decryption error" {
		t.Fatalf("c1=%s: Decrypt: got %v", c1, err)
	}
}

func TestDecryptNonInvertibleCiphertext(t *testing.T) {
	priv := &PrivateKey{
		PublicKey: PublicKey{
			G: fromHex(generatorHex),
			P: fromHex(primeHex),
		},
		X: fromHex("42"),
	}
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	// c1 = 0 and c1 = P are 0 mod P, so c1^X mod P is 0 and has no inverse.
	// The prime and exponent are valid; the ciphertext is not.
	for _, c1 := range []*big.Int{big.NewInt(0), priv.P} {
		_, err := Decrypt(priv, c1, priv.G)
		if err == nil || err.Error() != "elgamal: decryption error" {
			t.Fatalf("c1=%s: Decrypt: got %v", c1, err)
		}
	}
}

func TestDecryptZeroPlaintext(t *testing.T) {
	priv := &PrivateKey{
		PublicKey: PublicKey{
			G: fromHex(generatorHex),
			P: fromHex(primeHex),
		},
		X: fromHex("42"),
	}
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	// c1 = G is coprime to P, so the inverse exists. c2 = 0 and c2 = P both
	// reduce to 0, and the recovered block is empty.
	for _, c2 := range []*big.Int{big.NewInt(0), priv.P} {
		_, err := Decrypt(priv, priv.G, c2)
		if err == nil || err.Error() != "elgamal: decryption error" {
			t.Fatalf("c2=%s: Decrypt: got %v", c2, err)
		}
	}
}
