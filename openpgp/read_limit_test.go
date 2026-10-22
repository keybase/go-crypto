package openpgp

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	goerrors "errors"
	"io"
	"testing"

	"github.com/keybase/go-crypto/openpgp/errors"
	"github.com/keybase/go-crypto/openpgp/packet"
)

const limitTestPayloadSize = 64 * 1024

func serializeLiteralForLimitTest(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := packet.SerializeLiteral(noOpCloser{&buf}, true, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func wrapCompressedForLimitTest(t *testing.T, inner []byte, level int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := packet.SerializeCompressed(noOpCloser{&buf}, packet.CompressionZLIB, &packet.CompressionConfig{Level: level})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(inner); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// buildNestedForLimitTest wraps a literal packet in storedLayers zlib layers
// that do not expand (NoCompression), then in one final layer with outerLevel.
// It also returns the decompressed size of every layer, innermost first, so
// the last entry is what the outermost layer inflates to.
func buildNestedForLimitTest(t *testing.T, storedLayers int, outerLevel int) (msg []byte, inflated []int64) {
	t.Helper()
	msg = serializeLiteralForLimitTest(t, bytes.Repeat([]byte{'T'}, limitTestPayloadSize))
	for i := 0; i < storedLayers; i++ {
		inflated = append(inflated, int64(len(msg)))
		msg = wrapCompressedForLimitTest(t, msg, packet.NoCompression)
	}
	inflated = append(inflated, int64(len(msg)))
	return wrapCompressedForLimitTest(t, msg, outerLevel), inflated
}

// nestedLimitBounds brackets the budget charged for reading a message from
// buildNestedForLimitTest to the end. The outermost layer is charged its raw
// bytes plus whatever it inflates beyond them, which is nothing for a stored
// layer. Every inner layer is charged its whole decompressed output. Each
// layer has to produce the full payload, and the outermost one also reads
// packet headers on top of it. Return vals: a budget of `over` is always
// exceeded, and a budget of `within` never is.
func nestedLimitBounds(msg []byte, inflated []int64, outerLevel int) (over, within int64) {
	outer := len(inflated) - 1
	over = int64(len(inflated)) * limitTestPayloadSize
	within = int64(len(msg)) + 1
	for _, n := range inflated[:outer] {
		within += n
	}
	if outerLevel != packet.NoCompression {
		within += inflated[outer]
	}
	return over, within
}

func readAllWithLimit(msg []byte, limit int64) error {
	config := &packet.Config{MaxMessageSize: &limit}
	md, err := ReadMessage(bytes.NewReader(msg), EntityList{}, nil, config)
	if err != nil {
		return err
	}
	_, err = io.ReadAll(md.UnverifiedBody)
	return err
}

func TestReadMessageLimitSingleCompressedLayer(t *testing.T) {
	msg, inflated := buildNestedForLimitTest(t, 0, packet.BestCompression)
	over, within := nestedLimitBounds(msg, inflated, packet.BestCompression)
	t.Logf("raw message size: %d, over: %d, within: %d", len(msg), over, within)

	if err := readAllWithLimit(msg, within); err != nil {
		t.Fatalf("single layer within limit %d: %v", within, err)
	}

	err := readAllWithLimit(msg, over)
	if !goerrors.Is(err, errors.ErrMessageTooLarge) {
		t.Fatalf("limit %d: expected ErrMessageTooLarge, got %v", over, err)
	}
}

// Every nested layer runs its whole input through a decompressor, so ten
// stored layers around a 64 KiB payload are charged more than 11x the
// payload.
func TestReadMessageLimitNestedCompression(t *testing.T) {
	const storedLayers = 10

	cases := []struct {
		name       string
		outerLevel int
	}{
		{"compressed outer", packet.BestCompression},
		{"stored outer", packet.NoCompression},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, inflated := buildNestedForLimitTest(t, storedLayers, tc.outerLevel)
			over, within := nestedLimitBounds(msg, inflated, tc.outerLevel)
			t.Logf("raw message size: %d, over: %d, within: %d", len(msg), over, within)

			if err := readAllWithLimit(msg, within); err != nil {
				t.Fatalf("nested message within limit %d: %v", within, err)
			}

			err := readAllWithLimit(msg, over)
			if !goerrors.Is(err, errors.ErrMessageTooLarge) {
				t.Fatalf("limit %d: expected ErrMessageTooLarge, got %v", over, err)
			}
		})
	}
}

// emptyStoredBlocksZlib returns a zlib stream made of empty stored deflate
// blocks. It decompresses to nothing.
func emptyStoredBlocksZlib(blocks int) []byte {
	var buf bytes.Buffer
	// Zlib header
	buf.Write([]byte{0x78, 0x01})
	for i := 0; i < blocks-1; i++ {
		buf.Write([]byte{0x00, 0x00, 0x00, 0xff, 0xff})
	}
	buf.Write([]byte{0x01, 0x00, 0x00, 0xff, 0xff})
	// Adler-32 of empty input.
	buf.Write([]byte{0x00, 0x00, 0x00, 0x01})
	return buf.Bytes()
}

// rawCompressedPacket frames body as a new-format Compressed Data packet with
// a five-octet length.
func rawCompressedPacket(body []byte, algo packet.CompressionAlgo) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0xc0 | 8)
	buf.WriteByte(0xff)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(body)+1))
	buf.Write(length[:])
	buf.WriteByte(byte(algo))
	buf.Write(body)
	return buf.Bytes()
}

func zlibCompressForLimitTest(t *testing.T, data []byte, level int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, level)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A small outer layer inflates to a large inner compressed packet that
// produces no output, so only the outer layer's excess can stop it. The
// literal packet after it is only reachable once the inner decompressor has
// walked its whole stream and verified the checksum.
func TestReadMessageLimitNestedZeroOutputBomb(t *testing.T) {
	const innerStreamSize = 1 << 20
	payload := []byte("ok")

	inner := rawCompressedPacket(emptyStoredBlocksZlib(innerStreamSize/5), packet.CompressionZLIB)
	content := append(append([]byte{}, inner...), serializeLiteralForLimitTest(t, payload)...)
	// The outer packet needs a definite length: with partial lengths the
	// final zero-length chunk header stays unread after the zlib checksum,
	// and the next top-level packet read fails on it.
	msg := rawCompressedPacket(zlibCompressForLimitTest(t, content, zlib.BestCompression), packet.CompressionZLIB)
	t.Logf("raw message size: %d, inner packet size: %d", len(msg), len(inner))
	if len(msg)*100 > len(inner) {
		t.Fatalf("outer layer does not amplify enough: %d -> %d", len(msg), len(inner))
	}

	// ReadMessage without MaxMessageSize should work.
	md, err := ReadMessage(bytes.NewReader(msg), EntityList{}, nil, nil)
	if err != nil {
		t.Fatalf("unlimited: %v", err)
	}
	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("unlimited: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("unlimited: got body %q, want %q", body, payload)
	}

	// The inner layer outputs nothing, so the whole charge comes from the
	// outer layer: its raw bytes plus what it inflates beyond them. That is at
	// most len(msg)+len(content). It has to inflate the entire inner packet
	// and also reads its own header, so the charge is more than len(inner).
	within := int64(len(msg)+len(content)) + 1
	if err := readAllWithLimit(msg, within); err != nil {
		t.Fatalf("limit %d: %v", within, err)
	}

	over := int64(len(inner))
	err = readAllWithLimit(msg, over)
	if !goerrors.Is(err, errors.ErrMessageTooLarge) {
		t.Fatalf("limit %d: expected ErrMessageTooLarge, got %v", over, err)
	}
}
