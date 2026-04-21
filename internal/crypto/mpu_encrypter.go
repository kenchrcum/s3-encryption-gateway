package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"sync"
)

const mpuAEADTagSize = 16 // AES-GCM authentication tag size

// NewMPUPartEncryptReader creates a streaming encrypter for a single multipart
// upload part. It uses DeriveMultipartIV for each chunk so that IVs are
// deterministic across retries but unique across (upload, part, chunk) tuples.
//
// Returns the ciphertext reader and the exact byte length of the ciphertext.
// plainLen == 0 is allowed (empty part); the function reads body in full.
func NewMPUPartEncryptReader(
	ctx context.Context,
	body io.Reader,
	dek []byte,
	uploadIDHash [32]byte,
	ivPrefix [12]byte,
	partNumber int32,
	chunkSize int,
	plainLen int64,
) (io.Reader, int64, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	// Read the entire part body. Parts are ≥ 5 MiB (AWS minimum), so this
	// buffers at most one part at a time which is acceptable.
	plaintext, err := io.ReadAll(body)
	if err != nil {
		return nil, 0, fmt.Errorf("mpu_encrypter: read body: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, 0, fmt.Errorf("mpu_encrypter: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, fmt.Errorf("mpu_encrypter: create GCM: %w", err)
	}

	var (
		out        bytes.Buffer
		chunkIndex uint32
		offset     int
	)

	for offset < len(plaintext) {
		end := offset + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := plaintext[offset:end]
		iv := DeriveMultipartIV(dek, uploadIDHash, ivPrefix, uint32(partNumber), chunkIndex)
		cipherChunk := gcm.Seal(nil, iv[:], chunk, nil)
		out.Write(cipherChunk)
		offset = end
		chunkIndex++
	}

	encLen := int64(out.Len())
	return &out, encLen, nil
}

// newMPUPartEncryptReader is the unexported alias used from within the api package via the exported function.
// Both names delegate to the same implementation.
func newMPUPartEncryptReader(
	ctx context.Context,
	body io.Reader,
	dek []byte,
	uploadIDHash [32]byte,
	ivPrefix [12]byte,
	partNumber int32,
	chunkSize int,
	plainLen int64,
) (io.Reader, int64, error) {
	return NewMPUPartEncryptReader(ctx, body, dek, uploadIDHash, ivPrefix, partNumber, chunkSize, plainLen)
}

// mpuDecryptReader is a streaming io.Reader that decrypts an MPU-encrypted
// S3 object one AEAD chunk at a time. It never buffers more than one chunk
// (at most ChunkSize+tagSize bytes) of ciphertext in memory, regardless of
// object size.
//
// Ownership of the underlying source reader is retained by the caller — the
// caller is responsible for closing it after the mpuDecryptReader is exhausted
// or abandoned.
type mpuDecryptReader struct {
	src          io.Reader
	manifest     *MultipartManifest
	dek          []byte
	uploadIDHash [32]byte
	ivPrefix     [12]byte
	gcm          cipher.AEAD

	// read state
	partIdx  int
	chunkIdx int32

	// plaintext chunk buffer; nil when empty
	buf    []byte
	bufOff int

	done bool
	err  error

	// reusable ciphertext read buffer (capacity = ChunkSize + tagSize)
	encBuf []byte
}

// encBufPool reuses per-chunk ciphertext buffers to reduce GC pressure.
// Capacity is ChunkSize + tagSize (DefaultChunkSize + 16 = 65552 bytes).
var encBufPool = sync.Pool{New: func() any { return make([]byte, DefaultChunkSize+mpuAEADTagSize) }}

// NewMPUDecryptReader returns a streaming io.Reader that decrypts the
// ciphertext produced by NewMPUPartEncryptReader for each part in order.
// Memory overhead is O(ChunkSize) — one chunk at a time — regardless of
// object size.
//
// The caller retains ownership of src and must close it after the reader
// is fully consumed.
func NewMPUDecryptReader(
	src io.Reader,
	manifest *MultipartManifest,
	dek []byte,
	uploadIDHash [32]byte,
	ivPrefix [12]byte,
) (io.Reader, error) {
	if len(manifest.Parts) == 0 {
		return bytes.NewReader(nil), nil
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("mpu_encrypter: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mpu_encrypter: create GCM: %w", err)
	}
	return &mpuDecryptReader{
		src:          src,
		manifest:     manifest,
		dek:          dek,
		uploadIDHash: uploadIDHash,
		ivPrefix:     ivPrefix,
		gcm:          gcm,
		encBuf:       encBufPool.Get().([]byte),
	}, nil
}

// Read implements io.Reader. It decrypts one AEAD chunk per call to the
// underlying source, serving bytes from the chunk buffer until it's empty,
// then advancing to the next chunk.
func (r *mpuDecryptReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	for len(p) > 0 {
		// Serve from the plaintext buffer if available.
		if r.buf != nil && r.bufOff < len(r.buf) {
			n := copy(p, r.buf[r.bufOff:])
			r.bufOff += n
			if r.bufOff == len(r.buf) {
				r.buf = nil
				r.bufOff = 0
			}
			return n, nil
		}

		// Buffer exhausted — advance to next chunk.
		if r.done {
			r.returnEncBuf()
			return 0, io.EOF
		}
		if r.partIdx >= len(r.manifest.Parts) {
			r.done = true
			r.returnEncBuf()
			return 0, io.EOF
		}

		part := r.manifest.Parts[r.partIdx]
		if err := r.decryptNextChunk(part); err != nil {
			r.err = err
			r.returnEncBuf()
			return 0, err
		}
	}
	return len(p) - len(p), nil // unreachable but satisfies compiler
}

// decryptNextChunk reads the next encrypted chunk from src, authenticates it,
// and stores the plaintext in r.buf.
func (r *mpuDecryptReader) decryptNextChunk(part MPUPartRecord) error {
	isLastChunk := r.chunkIdx == part.ChunkCount-1

	var encSize int
	if isLastChunk {
		// Last chunk may be shorter than ChunkSize.
		lastPlainSize := part.PlainLen - int64(part.ChunkCount-1)*int64(r.manifest.ChunkSize)
		encSize = int(lastPlainSize) + mpuAEADTagSize
	} else {
		encSize = r.manifest.ChunkSize + mpuAEADTagSize
	}

	encChunk := r.encBuf[:encSize]
	if _, err := io.ReadFull(r.src, encChunk); err != nil {
		return fmt.Errorf("mpu_decrypt: part %d chunk %d: read: %w", part.PartNumber, r.chunkIdx, err)
	}

	iv := DeriveMultipartIV(r.dek, r.uploadIDHash, r.ivPrefix, uint32(part.PartNumber), uint32(r.chunkIdx))
	plain, err := r.gcm.Open(nil, iv[:], encChunk, nil)
	if err != nil {
		return fmt.Errorf("mpu_decrypt: part %d chunk %d auth failure: %w", part.PartNumber, r.chunkIdx, err)
	}

	r.buf = plain
	r.bufOff = 0

	// Advance position.
	r.chunkIdx++
	if r.chunkIdx >= part.ChunkCount {
		r.partIdx++
		r.chunkIdx = 0
	}
	if r.partIdx >= len(r.manifest.Parts) {
		r.done = true
	}
	return nil
}

func (r *mpuDecryptReader) returnEncBuf() {
	if r.encBuf != nil {
		encBufPool.Put(r.encBuf)
		r.encBuf = nil
	}
}

// DecryptMPUPartRange decrypts a consecutive run of chunks from a single MPU part.
// ciphertext must start at the first byte of chunk startChunkIdx — i.e. the caller
// must have requested the backend bytes starting from EncOffsetForPartChunk(part, startChunkIdx).
// All bytes in ciphertext are consumed (one or more chunks); authentication failure on
// any chunk returns an error with the chunk index, satisfying the tamper-detection requirement.
func DecryptMPUPartRange(
	ciphertext []byte,
	dek []byte,
	uploadIDHash [32]byte,
	ivPrefix [12]byte,
	partNumber int32,
	chunkSize int,
	startChunkIdx int32,
) ([]byte, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("mpu_encrypter: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mpu_encrypter: create GCM: %w", err)
	}

	encChunkSize := chunkSize + mpuAEADTagSize
	var (
		out        []byte
		offset     int
		chunkIndex = uint32(startChunkIdx)
	)

	for offset < len(ciphertext) {
		end := offset + encChunkSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		encChunk := ciphertext[offset:end]
		iv := DeriveMultipartIV(dek, uploadIDHash, ivPrefix, uint32(partNumber), chunkIndex)
		plain, err := gcm.Open(nil, iv[:], encChunk, nil)
		if err != nil {
			return nil, fmt.Errorf("mpu_encrypter: chunk %d auth failure in part %d: %w", chunkIndex, partNumber, err)
		}
		out = append(out, plain...)
		offset = end
		chunkIndex++
	}
	return out, nil
}

// DecryptMPUPart decrypts a single MPU part. It reconstructs per-chunk IVs
// using DeriveMultipartIV and decrypts each chunk independently.
// Returns the plaintext bytes or an error if any chunk fails authentication.
func DecryptMPUPart(
	ciphertext []byte,
	dek []byte,
	uploadIDHash [32]byte,
	ivPrefix [12]byte,
	partNumber int32,
	chunkSize int,
) ([]byte, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("mpu_encrypter: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mpu_encrypter: create GCM: %w", err)
	}

	encChunkSize := chunkSize + mpuAEADTagSize
	var (
		out        []byte
		chunkIndex uint32
		offset     int
	)

	for offset < len(ciphertext) {
		end := offset + encChunkSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		encChunk := ciphertext[offset:end]
		iv := DeriveMultipartIV(dek, uploadIDHash, ivPrefix, uint32(partNumber), chunkIndex)
		plain, err := gcm.Open(nil, iv[:], encChunk, nil)
		if err != nil {
			return nil, fmt.Errorf("mpu_encrypter: chunk %d auth failure in part %d: %w", chunkIndex, partNumber, err)
		}
		out = append(out, plain...)
		offset = end
		chunkIndex++
	}
	return out, nil
}
