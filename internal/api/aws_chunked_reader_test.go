package api

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAwsChunkedReader_Read(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "single chunk",
			input:    "5;chunk-signature=sig\r\nhello\r\n0;chunk-signature=end\r\n",
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "multiple chunks",
			input:    "5\r\nhello\r\n6\r\n world\r\n0\r\n",
			expected: "hello world",
			wantErr:  false,
		},
		{
			name:     "no extensions",
			input:    "d\r\nHello, world!\r\n0\r\n",
			expected: "Hello, world!",
			wantErr:  false,
		},
		{
			name:     "chunks with different sizes",
			input:    "2\r\nHi\r\n6\r\n there\r\n0\r\n",
			expected: "Hi there",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewAwsChunkedReader(strings.NewReader(tt.input))
			output, err := io.ReadAll(r)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, string(output))
			}
		})
	}
}

func TestAwsChunkedReader_LargeInput(t *testing.T) {
	// Construct a larger input with multiple chunks
	var buf bytes.Buffer
	expected := ""

	// Chunk 1
	buf.WriteString("A;sig=1\r\n0123456789\r\n")
	expected += "0123456789"

	// Chunk 2
	buf.WriteString("5;sig=2\r\nabcde\r\n")
	expected += "abcde"

	// Chunk 3 (longer)
	data := strings.Repeat("x", 100)
	buf.WriteString(strings.ToLower(string(strconv.FormatInt(int64(len(data)), 16))))
	buf.WriteString("\r\n")
	buf.WriteString(data)
	buf.WriteString("\r\n")
	expected += data

	// End
	buf.WriteString("0;sig=end\r\n")

	r := NewAwsChunkedReader(&buf)
	output, err := io.ReadAll(r)

	assert.NoError(t, err)
	assert.Equal(t, expected, string(output))
}

func TestAwsChunkedReader_InvalidFormat(t *testing.T) {
	input := "invalid-hex\r\nhello\r\n0\r\n"
	r := NewAwsChunkedReader(strings.NewReader(input))
	_, err := io.ReadAll(r)
	assert.Error(t, err)
}
