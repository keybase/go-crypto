package openpgp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keybase/go-crypto/openpgp/clearsign"
	"github.com/keybase/go-crypto/openpgp/errors"
)

func TestBadElgamal(t *testing.T) {
	// When algo 20 key is read, we go ahead with parsing and
	// verifying, but the key ends up in BadSubkeys with
	// DeprecatedKeyError.
	entities, err := ReadArmoredKeyRing(strings.NewReader(publicKey))
	if err != nil {
		t.Fatalf("error opening keys: %v", err)
	}
	if len(entities) != 1 {
		t.Fatal("expected only 1 key")
	}
	entity := entities[0]
	if len(entity.Subkeys) != 1 {
		t.Fatal("expected 1 subkey")
	}
	if len(entity.BadSubkeys) != 1 {
		t.Fatal("expected 1 bad subkey")
	}
	err = entity.BadSubkeys[0].Err
	if _, ok := err.(errors.DeprecatedKeyError); !ok {
		t.Fatal("expected DeprecatedKeyError")
	}

	// When reading a signature produced by algo 20 key, checking
	// should fail with UnsupportedError - signatures also have
	// algorithm field, and  PubKeyAlgoBadElGamal is not recognized
	// there. See signature_v3.go:parse.
	b, _ := clearsign.Decode([]byte(clearsignMsg))
	if b == nil {
		t.Fatal("Failed to decode clearsign msg")
	}
	_, err = CheckDetachedSignature(entities, bytes.NewBuffer(b.Bytes), b.ArmoredSignature.Body)
	if err == nil {
		t.Fatal("Expected to see error when checking clearsign")
	}
	if _, ok := err.(errors.UnsupportedError); !ok {
		t.Fatalf("Unexpected error type: %s", err)
	}
}

const publicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.2.0 (GNU/Linux)

mQGiBFpM17MRBADdWeXsUegcrx7rUON8+a0douslKTkj/z8E1FFLP6u25UJSsLdj
/39ClQJVreLNbNuDSM/Z5gX8oRIkYGMK5TAa1M47+ZOXfkbsP4NVx0iwWxcktmpG
I/GOo2Wc2a8McX5HQ1o9l0AjVM+0JOvnmidlVAh8b4MuGlXnb+EpCFpOOwCgvnC3
5z8lUmaDXJ5dU41UwgZcQAkD/AnB/NLrN9J6vK2hbTpCexsHrttIqLykCuwC4R5V
aVM/Qy0FK9BA7Jw+P+se01qfj8r6p7H4WP7l+ByGF2SwZ50PuAdeTVMo4LqP9pXs
kz7tM4uM8PBta+o2QOvnjpdlGwbN7kTd9B2UyaI8GnDL7k0el6oZB7o3R+GD8Xii
pWdxA/4naRWXes0ZTER1mq8ssogNLtTrjWjF5naQE5rhPcoM+3GT0HTk3PySBRPI
Dk9M9V+6OmqxqCHcUBNd58I8mqwicfBrG6I3Jb9u+YCdty7XF2AvXQwkfL35Zq8u
0TRASP5PG2l5KdUpWstZOWPEGRGsZP49+ewoLeqcV6msoOsj07QORWxnYW1hbCBU
ZXN0ZXKIWQQTEQIAGQUCWkzXswQLBwMCAxUCAwMWAgECHgECF4AACgkQl+HNHuDC
7kWSqgCcDFgo+4EO+IiZTuXgeUWsH0alzawAnRK7rIxMqciYkrpHNsXIno1R+kJQ
uM0EWkzXsxADAO6EHCPdw6EUAnZsd1GWmsYHEqdfduoqWtJCzsgDW0OSQe70bH15
kaxITv/QpJr6gPs7aW13gcF4l9Q/rW+BJlSbSOwtp1ndq9GQ7E5QGCjgflFGCmZw
1OLlSLZyQukVfwADBQMAwasRRlXw/uideJAgSUDcE5m7DBZrTExl2nC/oOogyIaW
H5I+FFEfNXs7whjK/1ixoLJTFaiwkW4mvYYoGzDeTHIgRLeVHeAuSRfC3oBAua3f
BokQ68fgEHGDADVJoQj7iEYEGBECAAYFAlpM17MACgkQl+HNHuDC7kXMDQCgp90K
3OsRXnsK/LLvYeNCDrRGyrsAn3pj+2rTU75VMwyDb5mndZAGH2TjuM0EWkzX1xQD
AJbyZopv9OdtX4j4to3jX8PgFrpSEEQT+qiHben8CYTtiOzWClurYHhZdHq6dhqc
EACvLGNQM8EXmmGHs1Aa6eRf4WLYo8hRs2Wf7275Mu4iw5h0X2kgSj02tXEaPwkt
4wADBQL+M4x1R90WDz1h92lJ/YcgFeINW8hxGVwCeeeZ+62vc4SLB3i/jfN6dx4Q
9vjLd+BrnzkwFzc6QW9UqpL3TvB9xruunJJMqybAiJshyOabu6urVUPw1eMg1La8
wd0afBLHiEYEGBECAAYFAlpM19cACgkQl+HNHuDC7kU26wCdEXpc0j9DutGh2ABg
ygm0xrHw5xEAoJonEzW5F3oDhft9cfKk4mR+QAnv
=qGLg
-----END PGP PUBLIC KEY BLOCK-----`

const clearsignMsg = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

aaa
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.2.0 (GNU/Linux)

iNcDBQFaTOUbUXZ9JopEDEYUAmtOAv427hD+yJD5i8lv2HISIB4XnG5NQcX3HMbp
4JzS/17T0PVzhbUaoguK4S4HbCy2TKDAiqFW+uTPVD2g/hDdz3iigdZC0q2qATfS
F4cO0rBiZy0h/MadrW54md5VPd3cruQC/j9P1MQF1pzp1R8DKrI/aD2zUxzv3tR2
5kMs9zLJFk+sEY3ppati3sUZpwukn4tNXsMVq5VUjKu81jUxr5Te/114gjbk6Oqo
bvEOhvf8VAzGswfr7Ur2/KN0D5n1Zr5wmA==
=yqX0
-----END PGP SIGNATURE-----`
