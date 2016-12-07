package openpgp

import (
	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/keybase/go-crypto/openpgp/packet"
	"strings"
	"testing"
)

// Here is some test data to actually get ECDH encryption and
// decryption working. At the time of the work in CORE-3806 (internal
// bug tracker), we didn't actually need the ECDH key to work,
// just to deserialize properly, so we didn't go down the path
// of debugging those code paths. However, we did generate these
// test vectors.

const privKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lNIEV+7iWhMFK4EEACIDAwSxj2UpOqGEAUZQc43HIoE2htc9+5nOePeDHqJi5czo
ecYAS5liyPFAJ3NIAqRh7UJ6pfgoz/mjvgH2fn6YLWv15hKWuSNxa0+RbWvU3lTi
nB/aBgkqTIQkJlkH/IP2Om/+BwMC1yIjA1zY/tDrYXLaotDLdkh17bvPJ5mlEqTK
dpwqgYJvg6z0V9scUM3axHBvOzFgapRP3yEgRdE9T1bS/Uq5CQRWe/AV3kVjNQta
D737y28b4XHQskb9yk2VRrZTvAO0Jk1heCBFQ0MgMzg0IDx0aGVtYXgrZWNjLTM4
NEBnbWFpbC5jb20+iJkEExMJACEFAlfu4loCGwMFCwkIBwIGFQgJCgsCBBYCAwEC
HgECF4AACgkQ5ynPBjIBakqqUQF/dAiY/YEKrGxfEiXlM0PkIPX7l2usSNsTCg4K
GY6nZfDOsqlotBqGKDHOAT3Og83TAX9SG7qG7vQvjrkR2VjnG5J9tXY8+ZotC2bW
yJlOjLm47Is58ehoWbIxOORpaBzoo+Gc1gRX7uJaEgUrgQQAIgMDBLaJ+2BLw65B
8ApW5hZ1AbiPCrXfG+ADBg3mdmKK419qxN4gFdh96+HoRlyqmnK743zLYaEYs8mF
S3cIiDQYCTJ3VeyTXEqk8vWCXBsXXzOtwtcg45+b1qNTOBjiOad39wMBCQn+BwMC
G8W4E8jtuznrjyFq9Gr1klnNQuh19pfecveH5oVle/tVCZzfLYctq5vxbIiHduzT
Pnf42FXz4iyVn0zb3bjgfDsMRcHQpWnhidBNQiw351Z4qIQCvocZIgN8Vv/iVBiI
gQQYEwkACQUCV+7iWgIbDAAKCRDnKc8GMgFqSlzYAX9XQX/GynVsIWV9ju7Gvs+z
GIxAujUbJBdFBLivrGNoM/+4OEufal/lbL0uqWIWXsIBgL/Fr+IDnXs+nyC9CXoE
siHEVKaKfz1oilbbrAma6U/in5NXDVtuYMbxxGPbIRiREg==
=aFgY
-----END PGP PRIVATE KEY BLOCK-----`

const pubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mG8EV+7iWhMFK4EEACIDAwSxj2UpOqGEAUZQc43HIoE2htc9+5nOePeDHqJi5czo
ecYAS5liyPFAJ3NIAqRh7UJ6pfgoz/mjvgH2fn6YLWv15hKWuSNxa0+RbWvU3lTi
nB/aBgkqTIQkJlkH/IP2Om+0Jk1heCBFQ0MgMzg0IDx0aGVtYXgrZWNjLTM4NEBn
bWFpbC5jb20+iJkEExMJACEFAlfu4loCGwMFCwkIBwIGFQgJCgsCBBYCAwECHgEC
F4AACgkQ5ynPBjIBakqqUQF/dAiY/YEKrGxfEiXlM0PkIPX7l2usSNsTCg4KGY6n
ZfDOsqlotBqGKDHOAT3Og83TAX9SG7qG7vQvjrkR2VjnG5J9tXY8+ZotC2bWyJlO
jLm47Is58ehoWbIxOORpaBzoo+G4cwRX7uJaEgUrgQQAIgMDBLaJ+2BLw65B8ApW
5hZ1AbiPCrXfG+ADBg3mdmKK419qxN4gFdh96+HoRlyqmnK743zLYaEYs8mFS3cI
iDQYCTJ3VeyTXEqk8vWCXBsXXzOtwtcg45+b1qNTOBjiOad39wMBCQmIgQQYEwkA
CQUCV+7iWgIbDAAKCRDnKc8GMgFqSlzYAX9XQX/GynVsIWV9ju7Gvs+zGIxAujUb
JBdFBLivrGNoM/+4OEufal/lbL0uqWIWXsIBgL/Fr+IDnXs+nyC9CXoEsiHEVKaK
fz1oilbbrAma6U/in5NXDVtuYMbxxGPbIRiREg==
=tfMD
-----END PGP PUBLIC KEY BLOCK-----`

const gpgEncryption = `-----BEGIN PGP MESSAGE-----

hJ4DzvP5Ex/d4TYSAwMEpjdfscEAp/NyYwViM2H6dPUr8vLA1fJ8pLefQi9u8pRU
JYnAzt3rf1NflTv/bHGuLxXvM+g8DvqT9yMHbTszmM40ghDgbfESCRT2w0SY6dnZ
1IadR8JH4lQEnG76EnJZMA1wq5TFcQ7/F8V+rJlpfBJ09PTFOZIq4eWG3Ql3ciLW
UNc5HhvHycU8U7ZohrXQs9JIAZ/QiU0irj8G2yAoOMGi/XVz3qyz4ZwtxhTHfMlI
NfBc9h72rI/hIjOdSM8ClO2ijOShevljVrd8YOxnTeJgVwtwFd3S9IA1
=KFaW
-----END PGP MESSAGE-----`

const passphrase = `abcd`

const decryption = `test message`

func openAndDecryptKey(t *testing.T, key string, passphrase string) EntityList {
	entities, err := ReadArmoredKeyRing(strings.NewReader(key))
	if err != nil {
		t.Fatalf("error opening keys: %v", err)
	}
	if len(entities) != 1 {
		t.Fatal("expected only 1 key")
	}
	k := entities[0]
	unlocker := func(k *packet.PrivateKey) {
		if !k.Encrypted {
			t.Fatal("expected a locked key")
		}
		err := k.Decrypt([]byte(passphrase))
		if err != nil {
			t.Fatalf("failed to unlock key: %s", err)
		}
	}
	unlocker(k.PrivateKey)
	for _, subkey := range k.Subkeys {
		unlocker(subkey.PrivateKey)
	}
	return entities
}

func TestECDHDecryptionNotImplemented(t *testing.T) {
	keys := openAndDecryptKey(t, privKey, passphrase)
	b, err := armor.Decode(strings.NewReader(gpgEncryption))
	if err != nil {
		t.Fatal(err)
	}
	source := b.Body
	_, err = ReadMessage(source, keys, nil, nil)
	if err == nil {
		t.Fatal("expected a failure, since this feature isn't implemented yet")
	}
}
