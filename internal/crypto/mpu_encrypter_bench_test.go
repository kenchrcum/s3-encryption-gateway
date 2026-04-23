package crypto

// V0.6-PERF-1 Phase A: benchmarks for NewMPUPartEncryptReader streaming path.
// Run with: go test -bench=BenchmarkMPUEncryptReader -benchmem -benchtime=10s

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// BenchmarkMPUEncryptReader_5MiB benchmarks a 5 MiB part (common minimum S3 part size).
func BenchmarkMPUEncryptReader_5MiB(b *testing.B) {
	benchmarkMPUEncryptReader(b, 5*1024*1024)
}

// BenchmarkMPUEncryptReader_100MiB benchmarks a 100 MiB part.
func BenchmarkMPUEncryptReader_100MiB(b *testing.B) {
	benchmarkMPUEncryptReader(b, 100*1024*1024)
}

func benchmarkMPUEncryptReader(b *testing.B, plainLen int) {
	b.Helper()
	plain := bytes.Repeat([]byte{0xAB}, plainLen)
	b.SetBytes(int64(plainLen))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, _, err := NewMPUPartEncryptReader(context.Background(), bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(plainLen))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			b.Fatal(err)
		}
	}
}
