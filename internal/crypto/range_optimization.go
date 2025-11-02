package crypto

import (
	"fmt"
	"strconv"
	"strings"
)

// calculateChunkRangeFromPlaintext calculates which chunks contain a given plaintext byte range.
// Returns: startChunk, endChunk (inclusive), startOffsetInStartChunk, endOffsetInEndChunk
func calculateChunkRangeFromPlaintext(plaintextStart, plaintextEnd int64, chunkSize int, totalChunks int) (startChunk, endChunk int, startOffset, endOffset int) {
	if chunkSize <= 0 || totalChunks <= 0 {
		return 0, 0, 0, 0
	}

	startChunk = int(plaintextStart / int64(chunkSize))
	endChunk = int(plaintextEnd / int64(chunkSize))

	// Clamp to valid range
	if startChunk >= totalChunks {
		startChunk = totalChunks - 1
	}
	if endChunk >= totalChunks {
		endChunk = totalChunks - 1
	}

	startOffset = int(plaintextStart % int64(chunkSize))
	endOffset = int(plaintextEnd % int64(chunkSize))

	return startChunk, endChunk, startOffset, endOffset
}

// calculateEncryptedByteRange calculates the byte range in encrypted data for given chunk indices.
// Each encrypted chunk = chunkSize + tagSize (16 bytes for GCM)
func calculateEncryptedByteRange(startChunk, endChunk int, chunkSize int) (encryptedStart, encryptedEnd int64) {
	if chunkSize <= 0 || startChunk < 0 || endChunk < startChunk {
		return 0, 0
	}

	encryptedChunkSize := int64(chunkSize + tagSize)
	encryptedStart = int64(startChunk) * encryptedChunkSize
	encryptedEnd = int64(endChunk+1) * encryptedChunkSize - 1

	return encryptedStart, encryptedEnd
}

// CalculateEncryptedRangeForPlaintextRange calculates the encrypted byte range needed to satisfy a plaintext range request.
// This is used to optimize range requests by fetching only necessary encrypted chunks from S3.
func CalculateEncryptedRangeForPlaintextRange(metadata map[string]string, plaintextStart, plaintextEnd int64) (encryptedStart, encryptedEnd int64, err error) {
	// Load manifest
	manifest, err := loadManifestFromMetadata(metadata)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to load manifest: %w", err)
	}

	// Calculate which chunks we need
	startChunk, endChunk, _, _ := calculateChunkRangeFromPlaintext(
		plaintextStart,
		plaintextEnd,
		manifest.ChunkSize,
		manifest.ChunkCount,
	)

	// Calculate encrypted byte range for those chunks
	encryptedStart, encryptedEnd = calculateEncryptedByteRange(startChunk, endChunk, manifest.ChunkSize)

	return encryptedStart, encryptedEnd, nil
}

// ParseHTTPRangeHeader parses an HTTP Range header and returns the plaintext byte range.
// Returns: start, end (inclusive), totalSize (if known), error
func ParseHTTPRangeHeader(rangeHeader string, totalSizeHint int64) (start, end int64, err error) {
	if len(rangeHeader) < 6 || rangeHeader[:6] != "bytes=" {
		return 0, 0, fmt.Errorf("invalid range header format")
	}

	rangeSpec := rangeHeader[6:]

	if rangeSpec[0] == '-' {
		// Suffix range: "-suffix" means last N bytes
		if totalSizeHint <= 0 {
			return 0, 0, fmt.Errorf("suffix range requires known total size")
		}
		var suffix int64
		if _, err := fmt.Sscanf(rangeSpec, "-%d", &suffix); err != nil {
			return 0, 0, fmt.Errorf("invalid suffix range: %w", err)
		}
		start = totalSizeHint - suffix
		if start < 0 {
			start = 0
		}
		end = totalSizeHint - 1
	} else {
		// Range: "start-end" or "start-"
		parts := strings.Split(rangeSpec, "-")
		if len(parts) != 2 {
			return 0, 0, fmt.Errorf("invalid range format")
		}

		if _, err := fmt.Sscanf(parts[0], "%d", &start); err != nil {
			return 0, 0, fmt.Errorf("invalid start: %w", err)
		}

		if parts[1] == "" {
			if totalSizeHint <= 0 {
				return 0, 0, fmt.Errorf("open-ended range requires known total size")
			}
			end = totalSizeHint - 1
		} else {
			if _, err := fmt.Sscanf(parts[1], "%d", &end); err != nil {
				return 0, 0, fmt.Errorf("invalid end: %w", err)
			}
		}
	}

	// Validate range
	if totalSizeHint > 0 {
		if start < 0 || start >= totalSizeHint || end < start || end >= totalSizeHint {
			return 0, 0, fmt.Errorf("range not satisfiable: %d-%d (size: %d)", start, end, totalSizeHint)
		}
	}

	return start, end, nil
}

// GetPlaintextSizeFromMetadata extracts the approximate plaintext size from chunked metadata.
func GetPlaintextSizeFromMetadata(metadata map[string]string) (int64, error) {
	chunkCountStr, ok1 := metadata[MetaChunkCount]
	chunkSizeStr, ok2 := metadata[MetaChunkSize]

	if !ok1 || !ok2 {
		// Try legacy format
		if sizeStr, ok := metadata[MetaOriginalSize]; ok {
			size, err := strconv.ParseInt(sizeStr, 10, 64)
			if err == nil {
				return size, nil
			}
		}
		return 0, fmt.Errorf("size information not found in metadata")
	}

	chunkCount, err1 := strconv.Atoi(chunkCountStr)
	chunkSize, err2 := strconv.Atoi(chunkSizeStr)

	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("invalid chunk count or size in metadata")
	}

	// Approximate: (chunkCount - 1) * chunkSize + chunkSize
	// Last chunk might be smaller, so this is an approximation
	size := int64((chunkCount - 1) * chunkSize + chunkSize)
	return size, nil
}
