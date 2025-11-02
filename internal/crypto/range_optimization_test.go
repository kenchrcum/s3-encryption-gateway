package crypto

import (
	"testing"
)

func TestCalculateChunkRangeFromPlaintext(t *testing.T) {
	tests := []struct {
		name            string
		plaintextStart  int64
		plaintextEnd    int64
		chunkSize       int
		totalChunks     int
		expectedStartChunk int
		expectedEndChunk   int
		expectedStartOffset int
		expectedEndOffset   int
	}{
		{
			name:               "single chunk",
			plaintextStart:     100,
			plaintextEnd:       200,
			chunkSize:          1024,
			totalChunks:        10,
			expectedStartChunk: 0,
			expectedEndChunk:   0,
			expectedStartOffset: 100,
			expectedEndOffset:   200,
		},
		{
			name:               "span multiple chunks",
			plaintextStart:     1024,
			plaintextEnd:       3072,
			chunkSize:          1024,
			totalChunks:        10,
			expectedStartChunk: 1, // chunk 1 (bytes 1024-2047)
			expectedEndChunk:   3, // chunk 3 (bytes 3072-4095) - 3072 is start of chunk 3
			expectedStartOffset: 0,
			expectedEndOffset:   0,
		},
		{
			name:               "exact chunk boundary",
			plaintextStart:     2048,
			plaintextEnd:       4095,
			chunkSize:          1024,
			totalChunks:        10,
			expectedStartChunk: 2,
			expectedEndChunk:   3,
			expectedStartOffset: 0,
			expectedEndOffset:   1023,
		},
		{
			name:               "start at chunk boundary, end in middle",
			plaintextStart:     2048,
			plaintextEnd:       2500,
			chunkSize:          1024,
			totalChunks:        10,
			expectedStartChunk: 2,
			expectedEndChunk:   2,
			expectedStartOffset: 0,
			expectedEndOffset:   452,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startChunk, endChunk, startOffset, endOffset := calculateChunkRangeFromPlaintext(
				tt.plaintextStart,
				tt.plaintextEnd,
				tt.chunkSize,
				tt.totalChunks,
			)

			if startChunk != tt.expectedStartChunk {
				t.Errorf("startChunk = %d, expected %d", startChunk, tt.expectedStartChunk)
			}
			if endChunk != tt.expectedEndChunk {
				t.Errorf("endChunk = %d, expected %d", endChunk, tt.expectedEndChunk)
			}
			if startOffset != tt.expectedStartOffset {
				t.Errorf("startOffset = %d, expected %d", startOffset, tt.expectedStartOffset)
			}
			if endOffset != tt.expectedEndOffset {
				t.Errorf("endOffset = %d, expected %d", endOffset, tt.expectedEndOffset)
			}
		})
	}
}

func TestCalculateEncryptedByteRange(t *testing.T) {
	tests := []struct {
		name              string
		startChunk         int
		endChunk           int
		chunkSize          int
		expectedEncryptedStart int64
		expectedEncryptedEnd   int64
	}{
		{
			name:                  "single chunk",
			startChunk:            0,
			endChunk:              0,
			chunkSize:             65536, // 64KB
			expectedEncryptedStart: 0,
			expectedEncryptedEnd:   65551, // 65536 + 16 - 1
		},
		{
			name:                  "two chunks",
			startChunk:            0,
			endChunk:              1,
			chunkSize:             65536,
			expectedEncryptedStart: 0,
			expectedEncryptedEnd:   131103, // 2 * (65536 + 16) - 1
		},
		{
			name:                  "multiple chunks",
			startChunk:            2,
			endChunk:              5,
			chunkSize:             65536,
			expectedEncryptedStart: 131104, // 2 * (65536 + 16)
			expectedEncryptedEnd:   393311, // (5+1) * (65536 + 16) - 1 = 6 * 65552 - 1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptedStart, encryptedEnd := calculateEncryptedByteRange(
				tt.startChunk,
				tt.endChunk,
				tt.chunkSize,
			)

			if encryptedStart != tt.expectedEncryptedStart {
				t.Errorf("encryptedStart = %d, expected %d", encryptedStart, tt.expectedEncryptedStart)
			}
			if encryptedEnd != tt.expectedEncryptedEnd {
				t.Errorf("encryptedEnd = %d, expected %d", encryptedEnd, tt.expectedEncryptedEnd)
			}
		})
	}
}

func TestParseHTTPRangeHeader(t *testing.T) {
	tests := []struct {
		name          string
		rangeHeader   string
		totalSize     int64
		expectedStart int64
		expectedEnd   int64
		expectedErr   bool
	}{
		{
			name:          "valid range",
			rangeHeader:   "bytes=100-200",
			totalSize:     1000,
			expectedStart: 100,
			expectedEnd:   200,
			expectedErr:   false,
		},
		{
			name:          "open-ended range",
			rangeHeader:   "bytes=100-",
			totalSize:     1000,
			expectedStart: 100,
			expectedEnd:   999,
			expectedErr:   false,
		},
		{
			name:          "suffix range",
			rangeHeader:   "bytes=-100",
			totalSize:     1000,
			expectedStart: 900,
			expectedEnd:   999,
			expectedErr:   false,
		},
		{
			name:          "invalid format",
			rangeHeader:   "invalid",
			totalSize:     1000,
			expectedErr:   true,
		},
		{
			name:          "invalid range (out of bounds)",
			rangeHeader:   "bytes=5000-6000",
			totalSize:     1000,
			expectedErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := ParseHTTPRangeHeader(tt.rangeHeader, tt.totalSize)

			if tt.expectedErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if start != tt.expectedStart {
				t.Errorf("start = %d, expected %d", start, tt.expectedStart)
			}
			if end != tt.expectedEnd {
				t.Errorf("end = %d, expected %d", end, tt.expectedEnd)
			}
		})
	}
}

func TestGetPlaintextSizeFromMetadata(t *testing.T) {
	tests := []struct {
		name        string
		metadata    map[string]string
		expectedSize int64
		expectedErr bool
	}{
		{
			name: "chunked format",
			metadata: map[string]string{
				MetaChunkCount: "10",
				MetaChunkSize:  "65536",
			},
			expectedSize: 655360, // 10 * 65536
			expectedErr:  false,
		},
		{
			name: "legacy format",
			metadata: map[string]string{
				MetaOriginalSize: "123456",
			},
			expectedSize: 123456,
			expectedErr:  false,
		},
		{
			name: "no size info",
			metadata: map[string]string{
				MetaEncrypted: "true",
			},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := GetPlaintextSizeFromMetadata(tt.metadata)

			if tt.expectedErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if size != tt.expectedSize {
				t.Errorf("size = %d, expected %d", size, tt.expectedSize)
			}
		})
	}
}

func TestCalculateEncryptedRangeForPlaintextRange(t *testing.T) {
	metadata := map[string]string{
		MetaManifest: encodeBase64([]byte(`{"v":1,"cs":65536,"cc":10,"iv":"dGVzdC1iYXNlLWl2"}`)),
	}

	// Create a proper manifest for the test
	manifest := &ChunkManifest{
		Version:    1,
		ChunkSize:  65536,
		ChunkCount: 10,
		BaseIV:     "dGVzdC1iYXNlLWl2",
	}
	manifestEncoded, _ := encodeManifest(manifest)
	metadata[MetaManifest] = manifestEncoded

	encryptedStart, encryptedEnd, err := CalculateEncryptedRangeForPlaintextRange(metadata, 65536, 131071)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should span chunks 1-1 (bytes 65536-131071 are in chunk 1)
	// Encrypted: chunk 1 = bytes (1 * (65536+16)) to ((1+1) * (65536+16) - 1)
	// = 65552 to 131103
	expectedStart := int64(65552)  // chunk 1 start: 1 * 65552
	expectedEnd := int64(131103)   // chunk 1 end: 2 * 65552 - 1

	if encryptedStart != expectedStart {
		t.Errorf("encryptedStart = %d, expected %d", encryptedStart, expectedStart)
	}
	if encryptedEnd != expectedEnd {
		t.Errorf("encryptedEnd = %d, expected %d", encryptedEnd, expectedEnd)
	}
}
