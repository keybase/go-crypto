package packet

import (
	"io"

	"github.com/keybase/go-crypto/openpgp/errors"
)

type limitReader struct {
	reader io.Reader
	budget *int64
}

func (l *limitReader) Read(p []byte) (n int, err error) {
	if *l.budget <= 0 {
		return 0, errors.ErrMessageTooLarge
	}

	if int64(len(p)) > *l.budget {
		p = p[:*l.budget]
	}

	n, err = l.reader.Read(p)
	*l.budget -= int64(n)

	if err == nil && *l.budget <= 0 {
		err = errors.ErrMessageTooLarge
	}

	return n, err
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (c *countingReader) Read(p []byte) (n int, err error) {
	n, err = c.reader.Read(p)
	c.count += int64(n)
	return n, err
}

type limitCompressedReader struct {
	body     io.Reader
	counting *countingReader

	budget        *int64
	countInflated int64
	charged       int64
}

func (l *limitCompressedReader) Read(p []byte) (n int, err error) {
	if *l.budget <= 0 {
		return 0, errors.ErrMessageTooLarge
	}

	if int64(len(p)) > *l.budget {
		p = p[:*l.budget]
	}

	n, err = l.body.Read(p)
	l.countInflated += int64(n)

	// If inflated amount exceeds the compressed amount (common case), charge
	// the difference into the budget (on top of what's already charged when
	// reading the compressed amount.)
	if l.countInflated > l.counting.count+l.charged {
		charge := l.countInflated - l.counting.count - l.charged
		*l.budget -= charge
		l.charged += charge
	}

	if err == nil && *l.budget <= 0 {
		err = errors.ErrMessageTooLarge
	}

	return n, err
}
