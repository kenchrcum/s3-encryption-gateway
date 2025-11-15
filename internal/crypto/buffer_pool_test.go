package crypto

import (
	"sync"
	"testing"
)

func TestBufferPool_GetPut4(t *testing.T) {
	pool := &BufferPool{
		pool4: &sync.Pool{
			New: func() interface{} { return make([]byte, 4) },
		},
	}

	// Test basic get/put cycle
	buf := pool.Get4()
	if len(buf) != 4 {
		t.Errorf("Expected buffer length 4, got %d", len(buf))
	}

	// Modify buffer
	buf[0] = 1
	buf[1] = 2
	buf[2] = 3
	buf[3] = 4

	pool.Put4(buf)

	// Get buffer again - should be zeroed (from Put operation)
	buf2 := pool.Get4()
	if buf2[0] != 0 || buf2[1] != 0 || buf2[2] != 0 || buf2[3] != 0 {
		t.Error("Buffer was not zeroed after Put")
	}

	pool.Put4(buf2)
}

func TestBufferPool_GetPut12(t *testing.T) {
	pool := &BufferPool{
		pool12: &sync.Pool{
			New: func() interface{} { return make([]byte, 12) },
		},
	}

	buf := pool.Get12()
	if len(buf) != 12 {
		t.Errorf("Expected buffer length 12, got %d", len(buf))
	}

	// Modify buffer
	for i := range buf {
		buf[i] = byte(i + 1)
	}

	pool.Put12(buf)

	// Get buffer again - should be zeroed
	buf2 := pool.Get12()
	for i, b := range buf2 {
		if b != 0 {
			t.Errorf("Buffer position %d was not zeroed, got %d", i, b)
		}
	}

	pool.Put12(buf2)
}

func TestBufferPool_GetPut32(t *testing.T) {
	pool := &BufferPool{
		pool32: &sync.Pool{
			New: func() interface{} { return make([]byte, 32) },
		},
	}

	buf := pool.Get32()
	if len(buf) != 32 {
		t.Errorf("Expected buffer length 32, got %d", len(buf))
	}

	pool.Put32(buf)
}

func TestBufferPool_GetPut64K(t *testing.T) {
	pool := &BufferPool{
		pool64K: &sync.Pool{
			New: func() interface{} { return make([]byte, 64*1024) },
		},
	}

	buf := pool.Get64K()
	if len(buf) != 64*1024 {
		t.Errorf("Expected buffer length 65536, got %d", len(buf))
	}

	pool.Put64K(buf)
}

func TestBufferPool_RejectWrongSize(t *testing.T) {
	pool := &BufferPool{
		pool4: &sync.Pool{
			New: func() interface{} { return make([]byte, 4) },
		},
	}

	// Try to put wrong size buffer
	wrongSize := make([]byte, 5)
	pool.Put4(wrongSize) // Should not panic, just not pool it

	// Next get should create new buffer
	buf := pool.Get4()
	if len(buf) != 4 {
		t.Errorf("Expected buffer length 4, got %d", len(buf))
	}
}

func TestBufferPool_RaceCondition(t *testing.T) {
	pool := &BufferPool{
		pool4: &sync.Pool{
			New: func() interface{} { return make([]byte, 4) },
		},
	}

	var wg sync.WaitGroup
	numGoroutines := 100
	numIterations := 1000

	// Run multiple goroutines that get/put buffers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				buf := pool.Get4()
				// Do some work
				buf[0] = 1
				pool.Put4(buf)
			}
		}()
	}

	wg.Wait()
}

func TestBufferPool_Metrics(t *testing.T) {
	pool := &BufferPool{
		pool4: &sync.Pool{
			New: func() interface{} { return make([]byte, 4) },
		},
	}

	// Reset metrics
	pool.Reset()

	// Perform some operations
	buf := pool.Get4()
	pool.Put4(buf)

	buf2 := pool.Get4()
	pool.Put4(buf2)

	// Check that metrics are being tracked (exact values depend on pool state)
	metrics := pool.GetMetrics()
	totalOps := metrics.Hits4 + metrics.Misses4
	if totalOps < 2 {
		t.Errorf("Expected at least 2 operations, got %d", totalOps)
	}

	// Test hit rate calculation doesn't panic
	_ = metrics.HitRate4()
	_ = metrics.HitRate12()
	_ = metrics.HitRate32()
	_ = metrics.HitRate64K()
}

func TestGetGlobalBufferPool(t *testing.T) {
	pool1 := GetGlobalBufferPool()
	pool2 := GetGlobalBufferPool()

	if pool1 != pool2 {
		t.Error("GetGlobalBufferPool should return the same instance")
	}
}
