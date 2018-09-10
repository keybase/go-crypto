package openpgp

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/keybase/go-crypto/openpgp/packet"
)

// Keep key in parts that we concatenate in different ways to get different
// result.

const keyAndIds = `c652045b6ddf5c13082a8648ce3d0301070203048045029015d8888429bacbb832095232fe6486260846e828dc24f4e3b935bc0c21876e13d2a083416247b96b14a4c4de39b2011c8c133248a3a83f0af47528f3cd264d69636861c582205067702054657374203c6e6f742d7a617075406b6579626173652e696f3ec2640413130a001605025b6ddf5c09102d2bdc8ff918a03b021b0302190100004f7e00fb071eb0b897ceca4652667d9a4e958d23e89f41e355ef244876de389ed21561ca00fe2fc2b260e39c5cf7fb2fdb8d0aa126d85f4c07a0ca3f91c26e0e3dcfde9ba4bb`
const subkey = `ce6d045b6ddf5c010300ef5ba59300be1cb017b7c9e1f1646766c162b51c1193bbe892277488b0554998758e88741aac10202f27cd48bf464c1e6982b703e4b3202d807e256d01a0d6e738aae332b0a1f79da3602fa092c11ffbc89b9a2dde1583811f51883870c57fcf0011010001`

// Signature with Flags=Sign, valid cross-signature, and expiring 4 years from
// now.
const flagSignSig = `c2c01b0418130a001905025b6ddf5c09102d2bdc8ff918a03b021b0205090784ce00007473200419010a000605025b6ddf5c0000499d0300c5e7a9740421c674cca7374422e802dcdc6e85b6312c389f19232f2df812a137795508f91144edab7e166a421657f2dd8ec9b9d3453102ba7ec5e41387bcbf0d095f8fedd95ccf01148efdace5117c94aaea177ffbc70c4c3ba12fb6fd5415f283040100b2bcb6f4a7861c162ce7fdae50ba5017fb779026b49260ad8158f61449a753ef010081ba0a267c641c18d6f01fd59966cc19e4eec68457dc5acbb120137f5abbda5c`

// Signature with Flags=Encrypt, no cross-signature (not needed), and never
// expiring. When both are present in bundle, this one will win and key will
// become encryption key.
const flagEncryptSig = `c2610418130a001305025b6ddf5c09102d2bdc8ff918a03b021b0c0000ff2c00ff7ca3194202858f9904c939551425b8943b646b3348f57d149fb4500f2ecf2c520100cad11801d70bd362b7ed0ce890582550fd09b167afefdff73c75eae223e9808a`

const multiSigMessage = `
-----BEGIN PGP MESSAGE-----

xA0DAAoB8yxD5M0JBc0By+F0AOIAAAAA5GhlbGxvIGNyb3NzIHNpZ27jZWQgd29y
bGQAwnwEAAEKABAFAluWvdwJEPMsQ+TNCQXNAADlxgMArqKsm9evebQFpSxk3oRy
eNVGDxPDX+p4/60hgoYAijP4BFZ8r1DedFDih+fU/qYYgb88A9dlADOuWMTrqIVH
h6YAkkaVK7Y2qx2pubRJShMhiVhnFgDX+8ABfGPWKoTD
=ipmT
-----END PGP MESSAGE-----

`

func ConfigWithDate(dateStr string) *packet.Config {
	return &packet.Config{
		Time: func() time.Time {
			time1, _ := time.Parse("2006-01-02", dateStr)
			return time1
		},
	}
}

func TestKeyEncryptSigWins(t *testing.T) {
	config := ConfigWithDate("2018-09-10")

	// `flagEncryptSig`` is "fresher" than `flagSignSig`` so the key will be
	// considered encryption key and not signing key.
	keyStr := keyAndIds + subkey + flagSignSig + flagEncryptSig
	kring, err := ReadKeyRing(hex.NewDecoder(strings.NewReader(keyStr)))
	if err != nil {
		t.Fatal(err)
	}
	if len(kring[0].Subkeys) == 0 {
		t.Fatalf("Subkey was not loaded")
	}
	if kring[0].Subkeys[0].Sig.FlagSign {
		t.Fatalf("Got unexpected FlagSign subkey=1")
	}
	sig, err := armor.Decode(strings.NewReader(multiSigMessage))
	if err != nil {
		t.Fatal(err)
	}
	md, err := ReadMessage(sig.Body, kring, nil, config)
	if err != nil {
		t.Fatal(err)
	}
	if !md.IsSigned {
		t.Fatalf("Expecting md.IsSigned")
	}
	// When we don't find the signing public key, SignedByKeyId will still have
	// the correct id, but SignedBy will be nil.
	if md.SignedByKeyId != kring[0].Subkeys[0].PublicKey.KeyId {
		t.Fatalf("Expected message should appear to be signed by subkey=0 (key id does not match)")
	}
	if md.SignedBy != nil {
		t.Fatalf("Expecting md.SignedBy to be nil, got: %v", md.SignedBy)
	}
}

func TestKeySignSigWins(t *testing.T) {
	config := ConfigWithDate("2018-09-10")

	// Do not add last signature this time, should be able to verify the
	// message.
	keyStr := keyAndIds + subkey + flagSignSig
	kring, err := ReadKeyRing(hex.NewDecoder(strings.NewReader(keyStr)))
	if err != nil {
		t.Fatal(err)
	}
	if len(kring[0].Subkeys) == 0 {
		t.Fatalf("Subkey was not loaded")
	}
	if !kring[0].Subkeys[0].Sig.FlagSign {
		t.Fatalf("Got unexpected FlagSign subkey=0")
	}
	sig, err := armor.Decode(strings.NewReader(multiSigMessage))
	if err != nil {
		t.Fatal(err)
	}
	md, err := ReadMessage(sig.Body, kring, nil, config)
	if err != nil {
		t.Fatal(err)
	}
	if !md.IsSigned {
		t.Fatalf("Expecting md.IsSigned")
	}
	// When we don't find the signing public key, SignedByKeyId will still have
	// the correct id, but SignedBy will be nil.
	if md.SignedByKeyId != kring[0].Subkeys[0].PublicKey.KeyId {
		t.Fatalf("Expected message should appear to be signed by subkey=0 (key id does not match)")
	}
	if md.SignedBy == nil || md.SignedBy.PublicKey.KeyId != md.SignedByKeyId {
		t.Fatalf("Got unexpected md.SignedBy: %v", md.SignedBy)
	}
}
