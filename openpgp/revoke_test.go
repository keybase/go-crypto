package openpgp

import (
	"bytes"
	"testing"

	"github.com/keybase/go-crypto/openpgp/packet"
)

func TestRevokedKey(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(revokedKey1))
	if err != nil || len(el) != 1 {
		t.Fatalf("Failed to read key: %v", err)
	}
	entity := el[0]
	if revLen := len(entity.Revocations); revLen != 1 {
		t.Fatalf("Expected to see 1 revocation, got %v", revLen)
	}
	if urevLen := len(entity.UnverifiedRevocations); urevLen != 0 {
		t.Fatalf("Expected to see 0 unverified revocations, got %v", urevLen)
	}
	iden, ok := entity.Identities["Alice"]
	if !ok {
		t.Fatal("Expected to find \"Alice\" identity.")
	}
	if iden.SelfSignature == nil {
		t.Fatal("Identity.SelfSignature is nil.")
	}
	if idenLen := len(iden.Signatures); idenLen != 0 {
		t.Fatalf("Expected to see 0 Identity.Signatures, got %v", idenLen)
	}
}

func TestKeyRevocation2(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(revokedKeyHex))
	if err != nil || len(kring) != 1 {
		t.Fatalf("Failed to read key: %v", err)
	}
	key := kring[0]
	if len(key.Revocations) != 1 {
		t.Fatalf("Expected to see one revocation.")
	}
	revocation := kring[0].Revocations[0]
	if *revocation.IssuerKeyId != key.PrimaryKey.KeyId {
		t.Fatalf("Expected IsserKeyId to be %x, got %x", key.PrimaryKey.KeyId, *revocation.IssuerKeyId)
	}
	if revocation.RevocationReason == nil {
		t.Fatal("Expected revocation reason not to be nil.")
	}
}

func TestRevokedIdentityKey(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(revokedIdentityKey))
	if err != nil || len(el) != 1 {
		t.Fatalf("Failed to read key: %v", err)
	}
	entity := el[0]
	if len(entity.Identities) != 2 {
		t.Fatal("Expected two identities")
	}
	if id, ok := entity.Identities["This One WIll be rev0ked"]; ok && id.Revocation != nil {
		t.Fatalf("Unexpected valid identity (%v)", entity.Identities)
	}
	if id, ok := entity.Identities["Hello AA"]; ok && id.Revocation == nil {
		t.Fatalf("Unexpected bad identity (%v)", entity.Identities)
	}
}

func TestDesignatedRevoker(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(designatedRevokedKey))
	if err != nil || len(el) != 1 {
		t.Fatalf("Failed to read key: %v", err)
	}
	entity := el[0]
	if len(entity.Revocations) != 0 || len(entity.UnverifiedRevocations) != 1 {
		t.Fatal("Expected unverified revocation")
	}
	rev := entity.UnverifiedRevocations[0]
	if issuer := *rev.IssuerKeyId; issuer != 0x9AD4C1F7C4EE24FE {
		t.Fatalf("Unexpected revocation issuer: %x", issuer)
	}

	// Designated revocation should not affect KeysByIdUsage searching.
	id := uint64(4595481070173372547)
	keys := el.KeysById(id, nil)
	if len(keys) != 1 {
		t.Errorf("Expected KeysById to find revoked key %X, but got %d matches", id, len(keys))
	}
	keys = el.KeysByIdUsage(id, nil, 0)
	if len(keys) != 1 {
		t.Errorf("Expected KeysByIdUsage to revoked key %X, but got %d matches", id, len(keys))
	}
}

func TestDesignatedRevoker2(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(designatedRevokedKey2))
	if err != nil || len(el) != 1 {
		t.Fatalf("Failed to read key: %v", err)
	}
	entity := el[0]
	if len(entity.Revocations) != 0 || len(entity.UnverifiedRevocations) != 1 {
		t.Fatal("Expected unverified revocation")
	}
	rev := entity.UnverifiedRevocations[0]
	if issuer := *rev.IssuerKeyId; issuer != 0x9086605E0B5C4673 {
		t.Fatalf("Unexpected revocation issuer: %x", issuer)
	}

	// Try a couple of "invalid" FindVerifiedDesignatedRevoke calls,
	// with keysets that should not verify revocation.
	sig, key := FindVerifiedDesignatedRevoke(el, entity)
	if sig != nil || key != nil {
		t.Fatal("FindVerifiedDesignatedRevoke verified revocation when given invalid keyset")
	}

	var emptyList EntityList
	sig, key = FindVerifiedDesignatedRevoke(emptyList, entity)
	if sig != nil || key != nil {
		t.Fatal("FindVerifiedDesignatedRevoke verified revocation when given empty keyset")
	}

	revokerList, err := ReadArmoredKeyRing(bytes.NewBufferString(designatedRevoker1))
	if err != nil || len(revokerList) != 1 {
		t.Fatalf("Failed to read revoker's key: %v", err)
	}

	sig, key = FindVerifiedDesignatedRevoke(revokerList, entity)
	if sig == nil || key == nil {
		t.Fatal("FindVerifiedDesignatedRevoke returned nil")
	}
	if sig != entity.UnverifiedRevocations[0] || key.PublicKey != revokerList[0].PrimaryKey {
		t.Fatal("FindVerifiedDesignatedRevoke did not find proper sig and/or key.")
	}
}

func TestNoopFindDesignated(t *testing.T) {
	// Test calling FindVerifiedDesignatedRevoke on key that does not
	// have any UnverifiedRevocations.
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(revokedIdentityKey))
	if err != nil || len(el) != 1 {
		t.Fatalf("Failed to read key: %v", err)
	}
	sig, key := FindVerifiedDesignatedRevoke(el, el[0])
	if sig != nil || key != nil {
		t.Fatal("FindVerifiedDesignatedRevoke should return nil, nil")
	}
}

func TestDesignatedBadSig(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(designatedRevokedKey2))
	if err != nil || len(el) != 1 {
		t.Fatalf("Failed to read key: %v", err)
	}
	entity := el[0]
	if len(entity.UnverifiedRevocations) != 1 {
		t.Fatal("Expected one unverified revocation.")
	}
	// Break UnverifiedRevocation signature, it should not pass
	// verification in FindVerifiedDesignatedRevoke anymore.
	entity.UnverifiedRevocations[0].EdDSASigR = packet.FromBytes([]byte{0x01, 0x02, 0x03})

	revokerList, err := ReadArmoredKeyRing(bytes.NewBufferString(designatedRevoker1))
	sig, key := FindVerifiedDesignatedRevoke(revokerList, entity)
	if sig != nil || key != nil {
		t.Fatal("FindVerifiedDesignatedRevoke did not fail verification")
	}
}

func TestMisplacedRevocation(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(keyMisplacedRevocation))
	if err != nil || len(el) != 1 {
		t.Fatalf("Failed to read key: %v", err)
	}
	entity := el[0]
	if len(entity.Revocations) != 1 {
		t.Fatal("Expected revocation")
	}
	iden, ok := entity.Identities["Alice"]
	if !ok {
		t.Fatal("Expected to find \"Alice\" identity.")
	}
	if iden.SelfSignature == nil {
		t.Fatal("Identity.SelfSignature is nil.")
	}
	if idenLen := len(iden.Signatures); idenLen != 0 {
		t.Fatalf("Expected to see 0 Identity.Signatures, got %v", idenLen)
	}
}

func TestDesignatedRevokerShortFingerprint(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(designatedRevokedKeyShortFingerprint))
	if err != nil || len(el) != 1 {
		t.Fatalf("Failed to read key: %v", err)
	}
	entity := el[0]
	if _, ok := entity.Identities["Revokee"]; !ok {
		t.Fatal("Expected to find \"Revokee\" identity.")
	}
	// The short fingerprint is skipped, so the foreign revocation is not recorded.
	if len(entity.Revocations) != 0 || len(entity.UnverifiedRevocations) != 0 {
		t.Fatalf("revocations = %d, unverified = %d", len(entity.Revocations), len(entity.UnverifiedRevocations))
	}
}

func TestDesignatedRevokerTruncatedSubpacket(t *testing.T) {
	_, err := ReadArmoredKeyRing(bytes.NewBufferString(designatedRevokedKeyTruncatedRevoker))
	if err == nil || err.Error() != "openpgp: invalid data: invalid revocation key subpacket" {
		t.Fatalf("got %v", err)
	}
}

// Self-revoked key
const revokedKey1 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQFCBFj3GqwRAwC922rw75mP/WuF/wdZOcAPVfqukqGd5S5x7ajUGi77sXqqhAnr
j+XsneekldcHqlJuti7IHxMcbOZQN0rYinpk6ODfB3J1ShcHTC2IpWsngzt+tL6V
zSIXbR5rLUGg2RMAoPMi18hqBq8xQQDG2rEWCRybRvnvAv0axMy37OAeye6Ky8m2
0l1vDFeNO7/OH9eO5oNEwNuVG/shjZkGTD/YuB8huPvcyMR3xxs6Qmjn0XRfUWxt
xPvfctP9HS7MPeDqa/DsMZ5hh7B1eiwmk2cj5E6ZOFk2G8sC/jtcA3wVF7eHsJvA
CL14MLeQ9g+04CT7VhvPt2f3X3GF7XQ/2pgBfnzDi26VU9ND75NBmwVulbJw8QG7
JOpMi3FeHhsWtbQGcZg3Vcw8IamnqhEaFJ9Nb/hV4rKm0IXfgohJBCARAgAJBQJY
9xqvAh0AAAoJEDl/NacbGDDEyDYAn3QKeWn52B9lHes3pNlRqFS4/VlvAJ9DP+Kf
Ec8PxRr9qYH8KpacyYWua7QFQWxpY2WIYQQTEQIAIQUCWPcarAIbAwULCQgHAgYV
CAkKCwIEFgIDAQIeAQIXgAAKCRA5fzWnGxgwxB00AJ4inWM/H4FuFxd8A2TmmN1J
nb/W7ACgozlKd8s90o72ccJq4zxLLOC/ik25AQ0EWPcarBAEAMNfbgy0zfpDz6zi
kU+9ysCnQPaAQjNrFCu3JnJ29TGTRjGq95NOYgaU3/guAf8d1QSBAPzC+c+o/TWQ
2+y6qKJnZbsvFzVjBiJW6zpFDyWvupfATzKE3rsWYeyCwdPfwHTejWGXeoJKkSAy
em+0wm2VI6CKRsrf88UCwD9wk7VrAAMFBAC1+2hcC1TcJuZwwhDd3xllXgrMHGyG
I92RmaTjttJgOvlN5Pyz6q5HgB5EFkzbW3YCGm/YY+KTXKWUp9u2Eh9cc8R9Pm7c
HzJlEINC+VMe/+Nzd15ceySNGNIUW6D9OTtzMmgrkXCvRnZ0DDsnexVOM4pI6Up4
afCdmQfHhocmZ4hJBBgRAgAJBQJY9xqsAhsMAAoJEDl/NacbGDDEsCgAn2RJ+SJB
i7W/Rh1FjTXpL+d7zPqzAJ0Vzhg3SkrLt8/VGRRSJRUMpb4bPw==
=w/2P
-----END PGP PUBLIC KEY BLOCK-----
`

// Public key that has two identities, one of which is revoked.
const revokedIdentityKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWOIZOBYJKwYBBAHaRw8BAQdAOw15aNPr+v1ACWdSwaKmT+vAfpZJu2aiX/ED
NR70fYm0GFRoaXMgT25lIFdJbGwgYmUgcmV2MGtlZIh5BBMWCAAhBQJY4hlKAhsD
BQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEIUbNJhCKy361LQBAPH+mCf0r0z9
SZXw4B8fJ+jCl//0ato6Nk8bsedA2MyjAP4tx/h9XHjmANhKpue9YCyUFdV2NSKs
TIJ/EpNwz1QjArQISGVsbG8gQUGIYQQwFggACQUCWOIZcgIdIAAKCRCFGzSYQist
+nW9AQCaXyyTOmUw9gaw0SsS27NLtsYcu/affY4KLYQRW2ZjlgD9GLR5IKYtlX21
n/8Gw7KAuHaIQLK+wcbXnFabzM7TYA2IeQQTFggAIQUCWOIZOAIbAwULCQgHAgYV
CAkKCwIEFgIDAQIeAQIXgAAKCRCFGzSYQist+lGFAP9EFlJ0BCgOe6ART8xk93f3
fF+wOdMzdQ+6hni8wqW3OQEAq3VufchOPYJSL4fA+Oq7uEw5Z5Q9tBViES2Br7+I
1Au4OARY4hk4EgorBgEEAZdVAQUBAQdAAfA2+lbpmA1YXqHefB8gShHq201PsJmA
AQ2EB67c/XcDAQgHiGEEGBYIAAkFAljiGTgCGwwACgkQhRs0mEIrLfqOYwD/TaDI
Y81Z5IXtMVSMjg7sgNI93W9+xY5u0fHH5KThko4BAM7utt+MrMl67IrSLj0HLtVt
iO3AEa577DoHC0fseUgG
=uJYe
-----END PGP PUBLIC KEY BLOCK-----
`

// Key that has a designated revoker direct sig and also a designated
// revocation signature.
const designatedRevokedKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWN6JhRYJKwYBBAHaRw8BAQdA6NMRLTcnG9zXYIlH8aTxXttm6Ibnd+JcdnZR
7ZaarAOIYQQgFggACQUCWN6J+wIdAwAKCRCa1MH3xO4k/kqzAQCJRWV9XtLuBALs
pLfqb3V8+dumX9dNZhzrJejoOyNwIwEAzjpTdaSApbvfdon0ndf05UB+hkR2Sal5
bDXHANjltAiIeQQfFggAIQUCWN6J0RcMgBbsLs6ylR7EOEBNML2a1MH3xO4k/gIH
AAAKCRA/xm2vd7dAgxE6AP45XxRMDBG4MSvyqZw3zQ3XT0DzZyDfwmh4bNd2FZJg
lgD9ErTgyWuxVo4c/k/W6vowu6tV0rhMjH9MfwxmzY20igu0B1Jldm9rZWWIeQQT
FggAIQUCWN6JhQIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRA/xm2vd7dA
g0wmAPwOALfHBhKEiMTxCtAJ4ynJLiVXYmb+AdxLb6Q+ISmNuAEAt6uDcdM9pfX8
BjB78WoVjkxwRZpIMM3tcjz6VcR15w+4OARY3omFEgorBgEEAZdVAQUBAQdApcyK
X+duQaFIZV882qD8PZd3b9qS/ZN1EJSBOkJNiWQDAQgHiGEEGBYIAAkFAljeiYUC
GwwACgkQP8Ztr3e3QIO2KAD+NUOcZekVrfgx7STVdx2N9/zaK8cZSVgp2dWJ4DKE
1PsA+gM9O4+vwInhP8xGtH816FXJtGiw/mAyxCUeRTgi8KEH
=qbn3
-----END PGP PUBLIC KEY BLOCK-----
`

// Direct signature with a hashed revocation-key subpacket whose fingerprint
// is one byte. The signature verifies, and parse keeps the short fingerprint.
// Generated by: go run -tags testtool ./openpgp/test-tool
const designatedRevokedKeyShortFingerprint = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xsBNBF4L4QABCADkLkDtSOBXojBCLv2W/oIBP0nZuV3HAxdAXzYkJjbhVFjgofyD
msZpxO12NP43YSd1sqpE1GCv7b+HN/oiyUxoMaTH+NbHjDEG9632pvAngCAXzKJH
FeZ83swKsFCf4TrIHyHXdZ/QwrGzOGVqtJg+i0f+y1NXI5stfk2+8LLAxJqiN8j0
UvK2zpoWKwPEFIWnKDDQUcm/Dxb1lhkHs8ZhyXnI69vj1Yb1X7jSaJlvQ6NrEFak
fqFOe8XEE12ERT1afrtKlB5G1r8IrfGsCniJE7aZqLw45XM57jPq8iAlJRFUdvje
2FWj7m0Lf3gb0zYz8TParkMDUU71MPQUbG1LABEBAAHCwGEEHwEIABUFAl4L4QAJ
EL35Dc5Hyx3+BAyAAQEAAKs7CAAxKixV6RWuIvpY51EY9zq/SKCf+3Nljdcv2pQ+
DuGuvlIJiWqH+J4GqF9sBZ2nDBtpfhUcUxawROVvWuIcdYSP34RNAiIRc+GSYe62
K8Y/YMdWj1GjHWeHjW3A18qP2zOBMRMsQXrgn0eIPByO2LS18L4FHHUBe4Jh2srP
bXonsprBM79ejfTFFEhvASuaAR1gKTfCAZC8d7CUik8zkzuxM7GmFLzzfIXa0Atf
TQmX9Bu19AQavsvfJgM5wM2qX5rB5+RMhTmcd8FArDHMClC5/Xza+6NVECIt/zvJ
x2eXizCp/uWSEzDnM+orzW440m8wCBJeP79Pm3FCzlQNWBSSzQdSZXZva2VlwsBf
BBMBCAATBQJeC+EACRC9+Q3OR8sd/gIbAwAA7fcIAHB9UuGYiH4qQtjL2MhLZDvr
DVFYsWmmQcklVvq0VmIavXENqZ+TjvUzcbzg5pPyMJ4gRR9L1bwxliEq4IS5+FiM
HjClG4EQaoLXJqYORZj+GtYv43zdCfFpvZ9L3Q5KfNWaCReVP2F95dPpxMGhWuA5
0m1qgruP0Sqh9Cq1m/jdfls5LJx4VymqzYH2mTtykvE+yK/EQITICPM2m0QhWItm
LBMd09/x4jPUNzlF20yBd1x/x3bAlHxdr3aYXYu7WzqKg6Rgshfh9Owua8Ujqp6/
lYJ7tzPZnw0VRT5ahbHPsUIQN8g4lja4FaGaUkS8lTeoFOPvUIYAn4V6R2fiSSvC
wFwEIAEIABAFAl4L4QAJEPNKXSIwCqX3AAD5MggAvJkD8/395qBZ8sdnCd+uYDg3
eg5wsQW0X2yv6qmhbfjvNSHZm0z3urECCdg2wdtvRhG2RJIWKnn0OcLPIgASop87
cINo7ywTS3SbqMklNMPd7E9kYr1AR8GCOJXAzA4aCtlCD80zGZ6XwfhuhJnuR/Ji
JQZRG4AujCZCcQjzoalPqS5jggs76TI+DsWjN/+5BSg8SSaqYyIBlY28ykDOEVb3
+YqS8gzRe39AyDQFEczOt5Pe1SahdaOqWZ/mPYpMG73v/nrdP0nRDvkIt7PSX/lG
aoKHClPzCTrK/lugORWkF2i3aiNyL3psts8ijKEw0y08amoA4b3wevf3g5b9lQ==
=9S60
-----END PGP PUBLIC KEY BLOCK-----
`

// Direct signature with a hashed revocation-key subpacket whose body is only
// the class byte. The signature covers that body. Parse rejects it before the
// fingerprint is stored.
// Generated by: go run -tags testtool ./openpgp/test-tool
const designatedRevokedKeyTruncatedRevoker = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xsBNBF4L4QABCADg49NVh6TFnLuGd6c8cqt5ax3uY71xmqQPtJ9QxFHZRTyhmXFZ
Lk3j7BlcYeJoWcHNWp8GBJWu9iCsGlqDRtvL3lEVXBk5+a7EPRCv9dnuvsunb9sO
nGc2FcrAhP81TSwPiM0KszhbY9TbptCKx/6LRY56vef12fLxBQm8Azh6EbVC1DLj
Ma7DiAxjMfK6aoG/lfDcLGlWBETXAx+xNRbC1LsUVtOuCxH60V0qHvwwPiGEsmko
wR/TXo75nmNCIsCgaeEdYfaPZIRcbVt2hWXJe1M8m7JUwFsloXjbZhFEWhurpGZy
z/7tIcjeY8iJn/ggoP8lkDbJAph+7RnQiuu7ABEBAAHCwF8EHwEIABMFAl4L4QAJ
EHCzbW52fm8+AgyAAAA1HggAYNuFphHv3U1ZeWrCElQtwLsS8okKVKo53yi7U3AA
Bw2BGXVaQiqclvm5qRtA28zjHTID9Iehj/j7xJWbXBdOWAswYasr6KdlE5BVFH2O
wXQYOuypjDlTa5ovNo7wSghTxB26onkQ5TL0fTO72VtCXH8WZlLVQaxAHJGjYqZn
VwmTYlFrEaMLUSpk3nPHcblNb48UW4wwRZUgZmLgnr1kd8XptEtrAlIfnQdMNJk9
xcOdb84E82izNYJp4xzj5kERKGViqyDANvMpZ2zMUhTKJ4O6VSXZ+N1+vWM4sn0C
IpRIFfbLwkvGtKdoc5GxLrtI+OOrONq9kQJJrcN901SOJM0HUmV2b2tlZcLAXwQT
AQgAEwUCXgvhAAkQcLNtbnZ+bz4CGwMAAAFHCABRf8DwYIa6ZDH9KgYv1AaBORMI
pJGInUHxgyT5tADopF86TJr7uybPM9WWwS1gXSWuku62npTDrWzAkVlHFYkeYtWr
u1ue0f+o3M0Q0E3KwqB1u+Ya2pAlyG/RXZHRjYo6vvw2moTVgvLRWgnMRN/e+rkx
zidVni4n8cajL8LQgDsFceuUnBH8WLzdQTzToYHou8Egjq28BQpcK+DX2Wz4tgcw
ghZRnaO3zFftDHpBTyp16rRv8lurts3b90Gul6gDkp9ejpbXe4DpruclQjt/AXi7
cTGoXNlA2xSrlM3xrEaOscC/P43PbAvlEQ0PW7Vk1hKxrbTQwoYn32g3B17SwsBc
BCABCAAQBQJeC+EACRCrPgf9OV8eoAAANmIIAJdUQCzgSGj76QU99N8jEKoinzj/
Hh7QVpbCVqOg3Rjssv6QOUgl88WZ4gPW17bbBhDgMcU4h23fkCK6gYI1S0PkzFtG
SpYjscMzlpaV4U5AFR6g6jvR0xv/Z3oIg2qHNctj58qN0JGj3YCQjHep1myqQfvs
JSYeqsJdmOjBTm/U6qVZOWekXsl8OeXeR2CRnnICScWGBPqGH+PgLrJiCY92gUx9
td5q4CnOK0diwjVNuxfqIoJ+79EjnDrIeLcMCEYncdQfyVGDpC/v1VdBoYxhOXFD
Fg+WKM0rmHjKEZvbt1uPPKQMDPYVc7R3u+T6cwrFfrwNAC50yRcBI+Z+rPQ=
=HlMf
-----END PGP PUBLIC KEY BLOCK-----
`

// Key that has been designated by designatedRevoker1 and contains a
// verifiable revocation signature.
const designatedRevokedKey2 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWPY5DhYJKwYBBAHaRw8BAQdATJ1ECHK+nn/iRBTSJ+tGAVn9TtlOzAQeSNIh
FCbqkmSIYQQgFggACQUCWPY52gIdAgAKCRCQhmBeC1xGcwULAQDH4ohXPkNND4Ez
LRyXPNhCSC7IW8bfHqLWj0VH/cXBFwD/ci+R1C/pNXKzawLDw2k2Kqd1gn5Gd16C
RAU/0Q4MWAqIeQQfFggAIQUCWPY5TxcMgBbJcZz6AbUchwVji8mQhmBeC1xGcwIH
AAAKCRAYEqe7+/Ynv5hkAP0YaIHYyP55EVqiM/8JZJYK/A8x273QpfttY7KG8op0
cAD+J0nz4RnGJfhrfZGa1EwFNlQ6uyF8/BAJeat42x6w5gW0CEpvaG4gRG9liHkE
ExYIACEFAlj2OQ4CGwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQGBKnu/v2
J7+B3QEAlnd3pLw0X8ccY/J7q0lvsZqhjg5JUCHE/VhHv9ff804BAN+9pttBx91G
AK/J0xl/dFxg4nAb+MrJabMlFJBfU2cKuDgEWPY5DhIKKwYBBAGXVQEFAQEHQNIf
z8EWK30QHiLVcO0yNlXRKpsygbQR9TnCzySnZlV/AwEIB4hhBBgWCAAJBQJY9jkO
AhsMAAoJEBgSp7v79ie/rccA/2JVMMi0lCB+pgNXtsy+VsGQN1Wn93hMtp96jTH6
ZXu5AP9gPV6r//WSuvfLl0yO4agWaa+lersoYwyovTEkqe0UAQ==
=hUOq
-----END PGP PUBLIC KEY BLOCK-----
`

// Revoker key that signed revocation of designatedRevokedKey2.
const designatedRevoker1 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWPY5HxYJKwYBBAHaRw8BAQdAS7VZfelXtQ13zj/1vC9w6KijlYF5Q0wknInU
7vXikhe0DEphY2sgUmV2b2tlcoh5BBMWCAAhBQJY9jkfAhsDBQsJCAcCBhUICQoL
AgQWAgMBAh4BAheAAAoJEJCGYF4LXEZzF+AA/3yM9sepkr7FXXOWd+fx+R4/0iMZ
HE4ykX7nhRsXE72BAQDRt/5NrJg5jdGgaE9ho9aXEv854Dx1FJxBxiQomKLmArg4
BFj2OR8SCisGAQQBl1UBBQEBB0A3KqdTAoZN2mMJfwvKwbC8Ibv7cDjHL+2zGm+R
/ur3PAMBCAeIYQQYFggACQUCWPY5HwIbDAAKCRCQhmBeC1xGcyDJAQDG9QqWpV4c
Sm3K1NCp/0bIlRI/aFycA65lhHNoIZgPZwEApkjPInTzm1ZyVl4zgZxFltLgPbnU
J25shXYSVsIQJQ0=
=wIyY
-----END PGP PUBLIC KEY BLOCK-----
`

// In this bundle, key revocation packet appears after identities.
// gpg2 does not mark that key as revoked, we are more flexible in
// uid/subkey parsing so we happen to mark that key as revoked.
const keyMisplacedRevocation = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xsCCBFj3GqwRAwC922rw75mP/WuF/wdZOcAPVfqukqGd5S5x7ajUGi77sXqqhAnr
j+XsneekldcHqlJuti7IHxMcbOZQN0rYinpk6ODfB3J1ShcHTC2IpWsngzt+tL6V
zSIXbR5rLUGg2RMAoPMi18hqBq8xQQDG2rEWCRybRvnvAv0axMy37OAeye6Ky8m2
0l1vDFeNO7/OH9eO5oNEwNuVG/shjZkGTD/YuB8huPvcyMR3xxs6Qmjn0XRfUWxt
xPvfctP9HS7MPeDqa/DsMZ5hh7B1eiwmk2cj5E6ZOFk2G8sC/jtcA3wVF7eHsJvA
CL14MLeQ9g+04CT7VhvPt2f3X3GF7XQ/2pgBfnzDi26VU9ND75NBmwVulbJw8QG7
JOpMi3FeHhsWtbQGcZg3Vcw8IamnqhEaFJ9Nb/hV4rKm0IXfgs0FQWxpY2XCYQQT
EQIAIQUCWPcarAIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRA5fzWnGxgw
xB00AJ4inWM/H4FuFxd8A2TmmN1Jnb/W7ACgozlKd8s90o72ccJq4zxLLOC/ik3C
SQQgEQIACQUCWPcarwIdAAAKCRA5fzWnGxgwxMg2AJ90Cnlp+dgfZR3rN6TZUahU
uP1ZbwCfQz/inxHPD8Ua/amB/CqWnMmFrmvOwE0EWPcarBAEAMNfbgy0zfpDz6zi
kU+9ysCnQPaAQjNrFCu3JnJ29TGTRjGq95NOYgaU3/guAf8d1QSBAPzC+c+o/TWQ
2+y6qKJnZbsvFzVjBiJW6zpFDyWvupfATzKE3rsWYeyCwdPfwHTejWGXeoJKkSAy
em+0wm2VI6CKRsrf88UCwD9wk7VrAAMFBAC1+2hcC1TcJuZwwhDd3xllXgrMHGyG
I92RmaTjttJgOvlN5Pyz6q5HgB5EFkzbW3YCGm/YY+KTXKWUp9u2Eh9cc8R9Pm7c
HzJlEINC+VMe/+Nzd15ceySNGNIUW6D9OTtzMmgrkXCvRnZ0DDsnexVOM4pI6Up4
afCdmQfHhocmZ8JJBBgRAgAJBQJY9xqsAhsMAAoJEDl/NacbGDDEsCgAn2RJ+SJB
i7W/Rh1FjTXpL+d7zPqzAJ0Vzhg3SkrLt8/VGRRSJRUMpb4bPw==
=riYc
-----END PGP PUBLIC KEY BLOCK-----
`
