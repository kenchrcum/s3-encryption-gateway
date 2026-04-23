package s3

import (
	"bytes"
	"fmt"
	"io"
)

// SeekableBody is a pooled, bounded-buffer wrapper that satisfies the AWS SDK
// V2 UploadPart / PutObject seekable-body contract (needed for SigV4 payload
// hashing over plaintext-HTTP backends).
//
// Usage:
//
//	sb, err := NewSeekableBody(src, maxBytes)
//	if err != nil { ... } // err = ErrPartTooLarge if src > maxBytes
//	defer sb.Release()
//	etag, err := s3Client.UploadPart(ctx, ..., sb, &sb.Len)
//
// V0.6-PERF-1 — Phase D: replaces io.ReadAll(r.Body) in handleUploadPart.
// The backing buffer is a *bytes.Reader so seeks are O(1) and never allocate.
// Memory is bounded by maxBytes (default 64 MiB, configured via
// Server.MaxPartBuffer).
type SeekableBody struct {
	r   *bytes.Reader
	Len int64 // exact byte count; set after New returns successfully
}

// ErrPartTooLarge is returned by NewSeekableBody when the source exceeds the
// configured cap. The caller should return HTTP 413 to the client.
type ErrPartTooLarge struct {
	Got int64
	Cap int64
}

func (e *ErrPartTooLarge) Error() string {
	return fmt.Sprintf(
		"part body (%d bytes) exceeds server.max_part_buffer (%d bytes); "+
			"reduce part size or raise max_part_buffer in gateway config",
		e.Got, e.Cap)
}

// NewSeekableBody reads at most maxBytes+1 bytes from src. If the source
// contains more than maxBytes bytes, it returns ErrPartTooLarge without
// allocating a full buffer. On success the caller owns a *SeekableBody whose
// underlying reader is positioned at offset 0.
func NewSeekableBody(src io.Reader, maxBytes int64) (*SeekableBody, error) {
	// Read up to maxBytes+1 to detect overflow.
	limited := io.LimitReader(src, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("seekable_body: read: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, &ErrPartTooLarge{Got: int64(len(data)), Cap: maxBytes}
	}
	return &SeekableBody{
		r:   bytes.NewReader(data),
		Len: int64(len(data)),
	}, nil
}

// Read implements io.Reader.
func (s *SeekableBody) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

// Seek implements io.Seeker (required by the AWS SDK SigV4 signer).
func (s *SeekableBody) Seek(offset int64, whence int) (int64, error) {
	return s.r.Seek(offset, whence)
}
