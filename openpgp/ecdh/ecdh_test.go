package ecdh

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // registers SHA-224 for TestShortKDFHashRejected
	_ "crypto/sha512" // registers SHA-512 for the encrypt/decrypt cases
	"io"
	"math/big"
	"testing"

	"github.com/keybase/go-crypto/brainpool"
	"github.com/keybase/go-crypto/curve25519"
)

// AES-256, matching the KDF cipher used by the packet-level ECDH tests.
const testKDFKeySize = 32

func TestCurves(t *testing.T) {
	for _, curve := range []elliptic.Curve{
		curve25519.Cv25519(),
		elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521(),
		brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1(),
	} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			fingerprint := make([]byte, 20)
			if _, err := io.ReadFull(rand.Reader, fingerprint); err != nil {
				t.Fatal(err)
			}

			priv := testGenerate(t, curve)
			testEncryptDecrypt(t, priv, fingerprint)
			testScalarMatchesPublic(t, priv)
			testDecryptInvalidPadding(t, priv, fingerprint)

			priv = testGenerate(t, curve)
			testMarshalUnmarshal(t, priv)
		})
	}
}

func testGenerate(t *testing.T, curve elliptic.Curve) *PrivateKey {
	t.Helper()
	priv, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func testEncryptDecrypt(t *testing.T, priv *PrivateKey, kdfParams []byte) {
	t.Helper()
	message := []byte("hello world")

	vx, vy, ciphertext, err := priv.PublicKey.Encrypt(rand.Reader, kdfParams, message, crypto.SHA512, testKDFKeySize)
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}

	shared := priv.DecryptShared(vx, vy)
	key := priv.KDF(shared, kdfParams, crypto.SHA512)
	if len(key) < testKDFKeySize {
		t.Fatalf("KDF output %d is shorter than the cipher key", len(key))
	}
	unwrapped, err := AESKeyUnwrap(key[:testKDFKeySize], ciphertext)
	if err != nil {
		t.Fatalf("error decrypting: %s", err)
	}
	message2 := UnpadBuffer(unwrapped, len(message))
	if !bytes.Equal(message2, message) {
		t.Errorf("decryption failed, got: %x, want: %x", message2, message)
	}
}

// testDecryptInvalidPadding wraps the same malformed session key the
// ProtonMail suite uses (cipher id 0x09 and a trailing 0xFF). The wrap
// itself is valid. The buffer is shorter than an AES-256 session key,
// so UnpadBuffer rejects it.
func testDecryptInvalidPadding(t *testing.T, priv *PrivateKey, kdfParams []byte) {
	t.Helper()
	ephemeral, vx, vy, err := elliptic.GenerateKey(priv.Curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sx, _ := priv.Curve.ScalarMult(priv.PublicKey.X, priv.PublicKey.Y, ephemeral)
	key := priv.KDF(sx.Bytes(), kdfParams, crypto.SHA512)
	if len(key) < testKDFKeySize {
		t.Fatal("KDF output is shorter than the cipher key")
	}

	malformed := []byte{0x09, 'A', 'B', 'C', 'D', 'E', 'F', 0xFF}
	ciphertext, err := AESKeyWrap(key[:testKDFKeySize], malformed)
	if err != nil {
		t.Fatal(err)
	}

	shared := priv.DecryptShared(vx, vy)
	key = priv.KDF(shared, kdfParams, crypto.SHA512)
	unwrapped, err := AESKeyUnwrap(key[:testKDFKeySize], ciphertext)
	if err != nil {
		t.Fatalf("unwrap of a well-wrapped payload failed: %s", err)
	}
	// 0x09 is AES-256: 32-byte key, cipher id, and a 2-byte checksum.
	if UnpadBuffer(unwrapped, testKDFKeySize+3) != nil {
		t.Fatal("expected invalid padding to be rejected")
	}
}

// testScalarMatchesPublic checks that the stored public point is the
// scalar times the base point, then that a flipped scalar is not.
func testScalarMatchesPublic(t *testing.T, priv *PrivateKey) {
	t.Helper()
	scalar := scalarBytes(priv)
	x, y := priv.Curve.ScalarBaseMult(scalar)
	if x.Cmp(priv.PublicKey.X) != 0 || y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("valid key does not match its public point")
	}

	scalar[len(scalar)/2] ^= 1
	x, y = priv.Curve.ScalarBaseMult(scalar)
	if x.Cmp(priv.PublicKey.X) == 0 && y.Cmp(priv.PublicKey.Y) == 0 {
		t.Fatal("failed to detect a modified private scalar")
	}
}

func testMarshalUnmarshal(t *testing.T, priv *PrivateKey) {
	t.Helper()
	point, _ := Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)

	parsed := &PrivateKey{}
	parsed.Curve = priv.Curve
	parsed.PublicKey.X, parsed.PublicKey.Y = Unmarshal(priv.Curve, point)
	if parsed.PublicKey.X == nil {
		t.Fatal("unable to unmarshal point")
	}
	// Curve25519 scalars are clamped in GenerateKey before they are stored.
	parsed.X = new(big.Int).SetBytes(priv.X.Bytes())

	x, y := parsed.Curve.ScalarBaseMult(scalarBytes(parsed))
	if parsed.PublicKey.X.Cmp(priv.PublicKey.X) != 0 || parsed.PublicKey.Y.Cmp(priv.PublicKey.Y) != 0 || parsed.X.Cmp(priv.X) != 0 || x.Cmp(parsed.PublicKey.X) != 0 || y.Cmp(parsed.PublicKey.Y) != 0 {
		t.Fatal("failed to marshal/unmarshal correctly")
	}
}

// scalarBytes returns the private scalar padded to the width
// ScalarBaseMult expects. Curve25519 reads exactly 32 bytes.
func scalarBytes(priv *PrivateKey) []byte {
	size := (priv.Curve.Params().BitSize + 7) / 8
	raw := priv.X.Bytes()
	if len(raw) >= size {
		return append([]byte(nil), raw...)
	}
	out := make([]byte, size)
	copy(out[size-len(raw):], raw)
	return out
}

func TestShortKDFHashRejected(t *testing.T) {
	priv, err := GenerateKey(curve25519.Cv25519(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// `msg` is arbitrary, Encrypt rejects before it even uses it.
	msg := make([]byte, 24)
	// SHA-224 is 28 bytes, shorter than an AES-256 key.
	if _, _, _, err := priv.PublicKey.Encrypt(rand.Reader, nil, msg, crypto.SHA224, testKDFKeySize); err == nil {
		t.Error("expected error when the KDF hash is shorter than the KDF cipher key")
	}
}
