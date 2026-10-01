// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/keybase/go-crypto/openpgp/ecdh"
	"github.com/keybase/go-crypto/openpgp/elgamal"
	"github.com/keybase/go-crypto/openpgp/errors"
	"github.com/keybase/go-crypto/rsa"
)

func bigFromBase10(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bigFromBase10 failed")
	}
	return b
}

var encryptedKeyPub = rsa.PublicKey{
	E: 65537,
	N: bigFromBase10("115804063926007623305902631768113868327816898845124614648849934718568541074358183759250136204762053879858102352159854352727097033322663029387610959884180306668628526686121021235757016368038585212410610742029286439607686208110250133174279811431933746643015923132833417396844716207301518956640020862630546868823"),
}

var encryptedKeyRSAPriv = &rsa.PrivateKey{
	PublicKey: encryptedKeyPub,
	D:         bigFromBase10("32355588668219869544751561565313228297765464314098552250409557267371233892496951383426602439009993875125222579159850054973310859166139474359774543943714622292329487391199285040721944491839695981199720170366763547754915493640685849961780092241140181198779299712578774460837139360803883139311171713302987058393"),
}

var encryptedKeyPriv = &PrivateKey{
	PublicKey: PublicKey{
		PubKeyAlgo: PubKeyAlgoRSA,
	},
	PrivateKey: encryptedKeyRSAPriv,
}

func TestDecryptingEncryptedKey(t *testing.T) {
	for i, encryptedKeyHex := range []string{
		"c18c032a67d68660df41c70104005789d0de26b6a50c985a02a13131ca829c413a35d0e6fa8d6842599252162808ac7439c72151c8c6183e76923fe3299301414d0c25a2f06a2257db3839e7df0ec964773f6e4c4ac7ff3b48c444237166dd46ba8ff443a5410dc670cb486672fdbe7c9dfafb75b4fea83af3a204fe2a7dfa86bd20122b4f3d2646cbeecb8f7be8",
		// MPI can be shorter than the length of the key.
		"c18b032a67d68660df41c70103f8e520c52ae9807183c669ce26e772e482dc5d8cf60e6f59316e145be14d2e5221ee69550db1d5618a8cb002a719f1f0b9345bde21536d410ec90ba86cac37748dec7933eb7f9873873b2d61d3321d1cd44535014f6df58f7bc0c7afb5edc38e1a974428997d2f747f9a173bea9ca53079b409517d332df62d805564cffc9be6",
	} {
		const expectedKeyHex = "d930363f7e0308c333b9618617ea728963d8df993665ae7be1092d4926fd864b"

		p, err := Read(readerFromHex(encryptedKeyHex))
		if err != nil {
			t.Errorf("#%d: error from Read: %s", i, err)
			return
		}
		ek, ok := p.(*EncryptedKey)
		if !ok {
			t.Errorf("#%d: didn't parse an EncryptedKey, got %#v", i, p)
			return
		}

		if ek.KeyId != 0x2a67d68660df41c7 || ek.Algo != PubKeyAlgoRSA {
			t.Errorf("#%d: unexpected EncryptedKey contents: %#v", i, ek)
			return
		}

		err = ek.Decrypt(encryptedKeyPriv, nil)
		if err != nil {
			t.Errorf("#%d: error from Decrypt: %s", i, err)
			return
		}

		if ek.CipherFunc != CipherAES256 {
			t.Errorf("#%d: unexpected EncryptedKey contents: %#v", i, ek)
			return
		}

		keyHex := fmt.Sprintf("%x", ek.Key)
		if keyHex != expectedKeyHex {
			t.Errorf("#%d: bad key, got %s want %s", i, keyHex, expectedKeyHex)
		}
	}
}

func TestEncryptingEncryptedKey(t *testing.T) {
	key := []byte{1, 2, 3, 4}
	const expectedKeyHex = "01020304"
	const keyId = 42

	pub := &PublicKey{
		PublicKey:  &encryptedKeyPub,
		KeyId:      keyId,
		PubKeyAlgo: PubKeyAlgoRSAEncryptOnly,
	}

	buf := new(bytes.Buffer)
	err := SerializeEncryptedKey(buf, pub, CipherAES128, key, nil)
	if err != nil {
		t.Errorf("error writing encrypted key packet: %s", err)
	}

	p, err := Read(buf)
	if err != nil {
		t.Errorf("error from Read: %s", err)
		return
	}
	ek, ok := p.(*EncryptedKey)
	if !ok {
		t.Errorf("didn't parse an EncryptedKey, got %#v", p)
		return
	}

	if ek.KeyId != keyId || ek.Algo != PubKeyAlgoRSAEncryptOnly {
		t.Errorf("unexpected EncryptedKey contents: %#v", ek)
		return
	}

	err = ek.Decrypt(encryptedKeyPriv, nil)
	if err != nil {
		t.Errorf("error from Decrypt: %s", err)
		return
	}

	if ek.CipherFunc != CipherAES128 {
		t.Errorf("unexpected EncryptedKey contents: %#v", ek)
		return
	}

	keyHex := fmt.Sprintf("%x", ek.Key)
	if keyHex != expectedKeyHex {
		t.Errorf("bad key, got %s want %s", keyHex, expectedKeyHex)
	}
}

func TestSerializingEncryptedKey(t *testing.T) {
	const encryptedKeyHex = "c18c032a67d68660df41c70104005789d0de26b6a50c985a02a13131ca829c413a35d0e6fa8d6842599252162808ac7439c72151c8c6183e76923fe3299301414d0c25a2f06a2257db3839e7df0ec964773f6e4c4ac7ff3b48c444237166dd46ba8ff443a5410dc670cb486672fdbe7c9dfafb75b4fea83af3a204fe2a7dfa86bd20122b4f3d2646cbeecb8f7be8"

	p, err := Read(readerFromHex(encryptedKeyHex))
	if err != nil {
		t.Fatalf("error from Read: %s", err)
	}
	ek, ok := p.(*EncryptedKey)
	if !ok {
		t.Fatalf("didn't parse an EncryptedKey, got %#v", p)
	}

	var buf bytes.Buffer
	ek.Serialize(&buf)

	if bufHex := hex.EncodeToString(buf.Bytes()); bufHex != encryptedKeyHex {
		t.Fatalf("serialization of encrypted key differed from original. Original was %s, but reserialized as %s", encryptedKeyHex, bufHex)
	}
}

func TestDecryptingShortECDHKey(t *testing.T) {
	priv, err := ecdh.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %s", err)
	}
	pk := NewECDHPrivateKey(time.Now(), priv)
	pub := pk.PublicKey.PublicKey.(*ecdh.PublicKey)

	// An empty plaintext is padded to eight 0x08 bytes. 0x08 is AES-192, so
	// the unwrapped buffer is shorter than the cipher key plus checksum.
	Vx, Vy, C, err := pub.Encrypt(rand.Reader, ECDHKdfParams(&pk.PublicKey), nil, crypto.SHA512, CipherAES256.KeySize())
	if err != nil {
		t.Fatalf("encrypt: %s", err)
	}
	mpi, _ := ecdh.Marshal(pub.Curve, Vx, Vy)
	ek := &EncryptedKey{
		Algo:          PubKeyAlgoECDH,
		encryptedMPI1: parsedMPI{bytes: mpi},
		ecdh_C:        C,
	}

	err = ek.Decrypt(pk, nil)
	if err != errors.InvalidArgumentError("invalid padding while ECDH") {
		t.Fatalf("Decrypt: got %v, want invalid padding error", err)
	}
}

func TestDecryptingEmptyECDHUnwrap(t *testing.T) {
	priv, err := ecdh.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %s", err)
	}
	pk := NewECDHPrivateKey(time.Now(), priv)
	pub := pk.PublicKey.PublicKey.(*ecdh.PublicKey)
	// The static public point is a valid ephemeral point. Its shared secret
	// does not matter: an 8-byte 0xA6 unwrap does not use the AES key.
	mpi, _ := ecdh.Marshal(pub.Curve, pub.X, pub.Y)
	ek := &EncryptedKey{
		Algo:          PubKeyAlgoECDH,
		encryptedMPI1: parsedMPI{bytes: mpi},
		ecdh_C:        bytes.Repeat([]byte{0xA6}, 8),
	}
	err = ek.Decrypt(pk, nil)
	if err != errors.InvalidArgumentError("invalid unwrap while ECDH") {
		t.Fatalf("Decrypt: got %v, want invalid unwrap error", err)
	}
}

func TestDecryptingZeroECDHUnwrap(t *testing.T) {
	priv, err := ecdh.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %s", err)
	}
	pk := NewECDHPrivateKey(time.Now(), priv)
	pub := pk.PublicKey.PublicKey.(*ecdh.PublicKey)
	// A wrapped-key length of 0 is rejected before the first AES block is read.
	mpi, _ := ecdh.Marshal(pub.Curve, pub.X, pub.Y)
	ek := &EncryptedKey{
		Algo:          PubKeyAlgoECDH,
		encryptedMPI1: parsedMPI{bytes: mpi},
		ecdh_C:        []byte{},
	}
	err = ek.Decrypt(pk, nil)
	if err == nil || err.Error() != "cipherText must not be zero length" {
		t.Fatalf("Decrypt: got %v, want cipherText must not be zero length", err)
	}
}

func TestDecryptingShortRSAKey(t *testing.T) {
	for _, n := range []int{0, 1, 2} {
		ct, err := rsa.EncryptPKCS1v15(rand.Reader, &encryptedKeyPub, make([]byte, n))
		if err != nil {
			t.Fatalf("n=%d: encrypt: %s", n, err)
		}
		ek := &EncryptedKey{
			Algo:          PubKeyAlgoRSA,
			encryptedMPI1: parsedMPI{bytes: ct},
		}
		err = ek.Decrypt(encryptedKeyPriv, nil)
		if err != errors.StructuralError("truncated session key") {
			t.Fatalf("n=%d: Decrypt: got %v, want truncated session key", n, err)
		}
	}
}

// RFC 5114, section 2.1, 1024-bit MODP group. Same parameters as elgamal_test.go.
const elGamalPrimeHex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
const elGamalGeneratorHex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

func TestDecryptingShortElGamalKey(t *testing.T) {
	p, ok := new(big.Int).SetString(elGamalPrimeHex, 16)
	if !ok {
		t.Fatal("bad prime")
	}
	g, ok := new(big.Int).SetString(elGamalGeneratorHex, 16)
	if !ok {
		t.Fatal("bad generator")
	}
	x := big.NewInt(0x42)
	elgPriv := &elgamal.PrivateKey{
		PublicKey: elgamal.PublicKey{
			G: g,
			P: p,
			Y: new(big.Int).Exp(g, x, p),
		},
		X: x,
	}
	packetPriv := &PrivateKey{
		PublicKey:  PublicKey{PubKeyAlgo: PubKeyAlgoElGamal},
		PrivateKey: elgPriv,
	}

	for _, n := range []int{0, 1, 2} {
		c1, c2, err := elgamal.Encrypt(rand.Reader, &elgPriv.PublicKey, make([]byte, n))
		if err != nil {
			t.Fatalf("n=%d: encrypt: %s", n, err)
		}
		ek := &EncryptedKey{
			Algo:          PubKeyAlgoElGamal,
			encryptedMPI1: parsedMPI{bytes: c1.Bytes()},
			encryptedMPI2: parsedMPI{bytes: c2.Bytes()},
		}
		err = ek.Decrypt(packetPriv, nil)
		if err != errors.StructuralError("truncated session key") {
			t.Fatalf("n=%d: Decrypt: got %v, want truncated session key", n, err)
		}
	}
}
