package crypto

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBoundedQueue_BasicOperations(t *testing.T) {
	queue := NewBoundedQueue(100)
	defer queue.Close()

	// Test basic write/read
	data := []byte("hello world")
	n, err := queue.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	result := make([]byte, len(data))
	n, err = queue.Read(result)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to read %d bytes, read %d", len(data), n)
	}
	if string(result) != string(data) {
		t.Errorf("Expected %s, got %s", string(data), string(result))
	}
}

func TestBoundedQueue_Backpressure(t *testing.T) {
	queue := NewBoundedQueue(10) // Very small queue
	defer queue.Close()

	// Fill the queue
	data := []byte("0123456789") // 10 bytes, exactly queue size
	n, err := queue.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	// Try to write more - should block, but we'll test with timeout
	done := make(chan bool)
	go func() {
		extra := []byte("extra")
		n, err := queue.Write(extra)
		if err != nil {
			t.Errorf("Write should not fail: %v", err)
		}
		if n != len(extra) {
			t.Errorf("Expected to write %d bytes, wrote %d", len(extra), n)
		}
		done <- true
	}()

	// Read some data to free up space
	readBuf := make([]byte, 5)
	n, err = queue.Read(readBuf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 5 {
		t.Errorf("Expected to read 5 bytes, read %d", n)
	}

	// The write should now complete
	select {
	case <-done:
		// Good, write completed
	case <-time.After(100 * time.Millisecond):
		t.Error("Write should have completed after reading")
	}
}

func TestBoundedQueue_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	queue := NewBoundedQueueWithContext(ctx, 10)
	defer queue.Close()

	// Fill the queue
	data := []byte("0123456789")
	n, err := queue.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	// Try to write more - should block
	done := make(chan error, 1)
	go func() {
		extra := []byte("extra")
		_, err := queue.Write(extra)
		done <- err
	}()

	// Cancel context
	cancel()

	// Write should fail with context error
	select {
	case err := <-done:
		if err == nil {
			t.Error("Write should have failed with context cancellation")
		}
		if err != context.Canceled {
			t.Errorf("Expected context.Canceled, got %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Write should have failed immediately on context cancellation")
	}
}

func TestBoundedQueue_ConcurrentAccess(t *testing.T) {
	queue := NewBoundedQueue(1000)
	defer queue.Close()

	var wg sync.WaitGroup
	const numWorkers = 10
	const writesPerWorker = 100

	// Start multiple writers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < writesPerWorker; j++ {
				data := []byte{byte(workerID), byte(j)}
				_, err := queue.Write(data)
				if err != nil {
					t.Errorf("Write failed for worker %d: %v", workerID, err)
				}
			}
		}(i)
	}

	// Start multiple readers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2)
			for j := 0; j < writesPerWorker; j++ {
				_, err := queue.Read(buf)
				if err != nil {
					t.Errorf("Read failed: %v", err)
				}
			}
		}()
	}

	wg.Wait()
}

func TestBoundedQueue_Size(t *testing.T) {
	queue := NewBoundedQueue(100)
	defer queue.Close()

	if queue.Size() != 0 {
		t.Errorf("Expected initial size 0, got %d", queue.Size())
	}

	data := []byte("hello")
	n, err := queue.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	if queue.Size() != len(data) {
		t.Errorf("Expected size %d, got %d", len(data), queue.Size())
	}

	readBuf := make([]byte, len(data))
	n, err = queue.Read(readBuf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Expected to read %d bytes, read %d", len(data), n)
	}

	if queue.Size() != 0 {
		t.Errorf("Expected final size 0, got %d", queue.Size())
	}
}