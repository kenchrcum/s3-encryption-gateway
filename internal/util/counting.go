// Package util provides shared io.Reader/io.Writer helpers used across the
// gateway. All types in this package are intentionally allocation-free on
// the hot path.
package util

import (
	"fmt"
	"io"
)

// CountingReader wraps an io.Reader and counts the total number of bytes read.
// It is safe for concurrent use if the underlying reader is, but the counter
// itself is not protected — callers should read N only after the source is
// exhausted or after synchronisation.
type CountingReader struct {
	R io.Reader
	N int64
}

// Read implements io.Reader.
func (c *CountingReader) Read(p []byte) (int, error) {
	n, err := c.R.Read(p)
	c.N += int64(n)
	return n, err
}

// LengthAssertingReader wraps an io.Reader and verifies that exactly Expected
// bytes are read before io.EOF is returned. If the stream ends short or long,
// it returns an error. This is used as belt-and-braces insurance around
// PutObject calls where a miscalculated ContentLength would cause a silent
// truncation or a backend 400.
//
// V0.6-PERF-1: introduced as part of the handleCopyObject streaming pipeline
// (Phase C) to catch ContentLength formula drift early.
type LengthAssertingReader struct {
	R        io.Reader
	Expected int64
	seen     int64
}

// Read implements io.Reader.
func (l *LengthAssertingReader) Read(p []byte) (int, error) {
	n, err := l.R.Read(p)
	l.seen += int64(n)
	if err == io.EOF {
		if l.seen != l.Expected {
			return n, fmt.Errorf(
				"stream length mismatch: expected %d bytes, got %d", l.Expected, l.seen)
		}
	}
	return n, err
}
