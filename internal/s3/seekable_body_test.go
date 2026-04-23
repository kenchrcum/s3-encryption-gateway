package s3

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSeekableBody_ReuseAcrossRetries verifies that Seek(0, SeekStart) + Read
// produces byte-identical output on a second pass — the AWS SDK SigV4 retry
// contract (V0.6-PERF-1 Phase D).
func TestSeekableBody_ReuseAcrossRetries(t *testing.T) {
	data := bytes.Repeat([]byte("hello"), 100)
	sb, err := NewSeekableBody(bytes.NewReader(data), int64(len(data))+1)
	require.NoError(t, err)
	assert.Equal(t, int64(len(data)), sb.Len)

	// First read.
	pass1, err := io.ReadAll(sb)
	require.NoError(t, err)
	assert.Equal(t, data, pass1)

	// Seek back to start (simulating SigV4 retry).
	_, err = sb.Seek(0, io.SeekStart)
	require.NoError(t, err)

	// Second read must be byte-identical.
	pass2, err := io.ReadAll(sb)
	require.NoError(t, err)
	assert.Equal(t, data, pass2)
}

// TestSeekableBody_CapEnforced verifies that sources exceeding maxBytes return
// ErrPartTooLarge before any bytes are written to the backend.
func TestSeekableBody_CapEnforced(t *testing.T) {
	maxBytes := int64(100)
	// Source has 101 bytes (one more than the cap).
	src := strings.NewReader(strings.Repeat("X", 101))
	_, err := NewSeekableBody(src, maxBytes)
	require.Error(t, err)
	var tooLarge *ErrPartTooLarge
	require.ErrorAs(t, err, &tooLarge)
	assert.Equal(t, int64(101), tooLarge.Got)
	assert.Equal(t, maxBytes, tooLarge.Cap)
}

// TestSeekableBody_ExactlyAtCap verifies that a source exactly at maxBytes succeeds.
func TestSeekableBody_ExactlyAtCap(t *testing.T) {
	maxBytes := int64(100)
	data := bytes.Repeat([]byte{0xAB}, int(maxBytes))
	sb, err := NewSeekableBody(bytes.NewReader(data), maxBytes)
	require.NoError(t, err)
	assert.Equal(t, maxBytes, sb.Len)
	got, err := io.ReadAll(sb)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

// TestSeekableBody_EmptySource verifies that an empty body is handled gracefully.
func TestSeekableBody_EmptySource(t *testing.T) {
	sb, err := NewSeekableBody(bytes.NewReader(nil), 64*1024*1024)
	require.NoError(t, err)
	assert.Equal(t, int64(0), sb.Len)
	got, err := io.ReadAll(sb)
	require.NoError(t, err)
	assert.Empty(t, got)
}
