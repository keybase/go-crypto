package packet

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/keybase/go-crypto/openpgp/ecdh"
	"github.com/keybase/go-crypto/openpgp/errors"
)

func TestDecryptKeyECDHRejectsShortKDFHash(t *testing.T) {
	raw, err := ecdh.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %s", err)
	}
	pk := NewECDHPrivateKey(time.Now(), raw)

	want := errors.InvalidArgumentError("invalid KDF output while ECDH")
	for _, tc := range []struct {
		name string
		hash byte
	}{
		{name: "md5 shorter than aes256", hash: 1},      // MD5
		{name: "sha1 shorter than aes256", hash: 2},     // SHA1
		{name: "sha224 shorter than aes256", hash: 11},  // SHA224
	} {
		t.Run(tc.name, func(t *testing.T) {
			pk.ecdh.KdfHash = kdfHashFunction(tc.hash)
			pk.ecdh.KdfAlgo = kdfAlgorithm(CipherAES256)
			_, err := decryptKeyECDH(pk, raw.PublicKey.X, raw.PublicKey.Y, nil)
			if err != want {
				t.Fatalf("decryptKeyECDH: got %v, want %v", err, want)
			}
		})
	}
}

func TestDecryptKeyECDHRejectsUnavailableRIPEMD160(t *testing.T) {
	raw, err := ecdh.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %s", err)
	}
	pk := NewECDHPrivateKey(time.Now(), raw)
	pk.ecdh.KdfHash = kdfHashFunction(3) // RIPEMD160
	pk.ecdh.KdfAlgo = kdfAlgorithm(CipherAES256)

	want := errors.InvalidArgumentError("unavailable hash in private key")
	_, err = decryptKeyECDH(pk, raw.PublicKey.X, raw.PublicKey.Y, nil)
	if err != want {
		t.Fatalf("decryptKeyECDH: got %v, want %v", err, want)
	}
}
