package api

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// AwsChunkedReader wraps an io.Reader and decodes AWS chunked encoding.
// Format: chunk-size;chunk-extensions(optional)\r\nchunk-data\r\n
type AwsChunkedReader struct {
	reader   *bufio.Reader
	left     int64 // bytes left in current chunk
	finished bool
	err      error
}

// NewAwsChunkedReader creates a new reader that decodes AWS chunked format.
func NewAwsChunkedReader(r io.Reader) *AwsChunkedReader {
	return &AwsChunkedReader{
		reader: bufio.NewReader(r),
	}
}

func (r *AwsChunkedReader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.finished {
		return 0, io.EOF
	}

	totalRead := 0

	for totalRead < len(p) {
		if r.left == 0 {
			// Read chunk header
			// Format: hex-chunk-size [; key=value] \r\n
			line, err := r.reader.ReadString('\n')
			if err != nil {
				r.err = err
				return totalRead, err
			}

			// Trim CRLF
			line = strings.TrimSpace(line)
			if line == "" {
				continue // Skip empty lines if any? (Should shouldn't happen in valid stream but being robust)
			}

			// Parse size (hex)
			parts := strings.SplitN(line, ";", 2)
			sizeStr := parts[0]

			size, err := strconv.ParseInt(sizeStr, 16, 64)
			if err != nil {
				r.err = fmt.Errorf("invalid chunk size: %w", err)
				return totalRead, r.err
			}

			if size == 0 {
				r.finished = true
				// We might have trailers here, but for now we consume until EOF or stop
				// The strict spec says we should consume trailers.
				// Let's just try to read until EOF or we can stop here if we don't care about trailers.
				// For this proxy usage, stopping is fine as we don't need to validate trailers.
				return totalRead, io.EOF
			}

			r.left = size
		}

		// Read chunk data
		toRead := int64(len(p) - totalRead)
		if toRead > r.left {
			toRead = r.left
		}

		n, err := r.reader.Read(p[totalRead : totalRead+int(toRead)])
		totalRead += n
		r.left -= int64(n)

		if err != nil {
			r.err = err
			return totalRead, err
		}

		if r.left == 0 {
			// Expect CRLF after chunk data
			// We can read 2 bytes
			_, err := r.reader.Discard(2) // \r\n
			if err != nil {
				r.err = err
				return totalRead, err
			}
		}

		// If we filled the buffer, return
		if totalRead == len(p) {
			return totalRead, nil
		}
	}

	return totalRead, nil
}
