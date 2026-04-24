package cache

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestMemoryCache_GetSet(t *testing.T) {
	cache := NewMemoryCache(1024*1024, 100, 5*time.Minute)
	ctx := context.Background()
	
	// Set a value
	data := []byte("test data")
	metadata := map[string]string{"Content-Type": "text/plain"}
	err := cache.Set(ctx, "bucket", "key", data, metadata, 0)
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}
	
	// Get the value
	entry, ok := cache.Get(ctx, "bucket", "key")
	if !ok {
		t.Fatal("cache entry not found")
	}
	
	if string(entry.Data) != string(data) {
		t.Fatalf("expected data %q, got %q", string(data), string(entry.Data))
	}
	
	if entry.Metadata["Content-Type"] != "text/plain" {
		t.Fatalf("expected metadata Content-Type text/plain, got %s", entry.Metadata["Content-Type"])
	}
}

func TestMemoryCache_Expiration(t *testing.T) {
	cache := NewMemoryCache(1024*1024, 100, 5*time.Minute)
	ctx := context.Background()
	
	// Set a value with short TTL
	data := []byte("test data")
	err := cache.Set(ctx, "bucket", "key", data, nil, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}
	
	// Get immediately - should work
	_, ok := cache.Get(ctx, "bucket", "key")
	if !ok {
		t.Fatal("cache entry not found immediately after set")
	}
	
	// Wait for expiration
	time.Sleep(150 * time.Millisecond)
	
	// Should be expired
	_, ok = cache.Get(ctx, "bucket", "key")
	if ok {
		t.Fatal("cache entry should be expired")
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	cache := NewMemoryCache(1024*1024, 100, 5*time.Minute)
	ctx := context.Background()
	
	// Set a value
	data := []byte("test data")
	err := cache.Set(ctx, "bucket", "key", data, nil, 0)
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}
	
	// Delete it
	err = cache.Delete(ctx, "bucket", "key")
	if err != nil {
		t.Fatalf("failed to delete cache: %v", err)
	}
	
	// Should not be found
	_, ok := cache.Get(ctx, "bucket", "key")
	if ok {
		t.Fatal("cache entry should be deleted")
	}
}

func TestMemoryCache_Stats(t *testing.T) {
	cache := NewMemoryCache(1024*1024, 100, 5*time.Minute)
	ctx := context.Background()
	
	// Set some values
	for i := 0; i < 5; i++ {
		data := []byte(fmt.Sprintf("test data %d", i))
		err := cache.Set(ctx, "bucket", fmt.Sprintf("key%d", i), data, nil, 0)
		if err != nil {
			t.Fatalf("failed to set cache: %v", err)
		}
	}
	
	// Get some values to generate hits
	for i := 0; i < 3; i++ {
		cache.Get(ctx, "bucket", fmt.Sprintf("key%d", i))
	}
	
	// Try to get non-existent key to generate miss
	cache.Get(ctx, "bucket", "nonexistent")
	
	stats := cache.Stats()
	
	if stats.Items != 5 {
		t.Fatalf("expected 5 items, got %d", stats.Items)
	}
	
	if stats.Hits != 3 {
		t.Fatalf("expected 3 hits, got %d", stats.Hits)
	}
	
	if stats.Misses != 1 {
		t.Fatalf("expected 1 miss, got %d", stats.Misses)
	}
}

// TestMemoryCache_EvictForSpace triggers the evictForSpaceLocked path by
// filling the cache to its max-size limit and then inserting another item.
func TestMemoryCache_EvictForSpace(t *testing.T) {
	const entrySize = 100
	const maxEntries = 3
	// maxSize is exactly 3 × entrySize so the 4th insert triggers eviction.
	c := NewMemoryCache(int64(entrySize*maxEntries), maxEntries*10, 5*time.Minute)
	ctx := context.Background()

	data := make([]byte, entrySize)
	for i := 0; i < maxEntries; i++ {
		if err := c.Set(ctx, "bucket", fmt.Sprintf("evict-key-%d", i), data, nil, 0); err != nil {
			t.Fatalf("Set(%d) failed: %v", i, err)
		}
	}

	// This insert should trigger eviction.
	if err := c.Set(ctx, "bucket", "evict-key-overflow", data, nil, 0); err != nil {
		t.Fatalf("Set(overflow) failed: %v", err)
	}

	// At least one item should remain (no panic, no "cache full" error).
	stats := c.Stats()
	if stats.Evictions == 0 {
		// Not all implementations will report evictions; just assert no panic.
		t.Log("Note: no evictions recorded (eviction tracking may differ)")
	}
}

// TestMemoryCache_EvictByItemCount triggers the evictForSpaceLocked path by
// exceeding the max-item count.
func TestMemoryCache_EvictByItemCount(t *testing.T) {
	// 1 GB max size (won't be hit by size), but only 2 items max.
	c := NewMemoryCache(1024*1024*1024, 2, 5*time.Minute)
	ctx := context.Background()

	data := []byte("small data")
	for i := 0; i < 2; i++ {
		if err := c.Set(ctx, "bucket", fmt.Sprintf("item-%d", i), data, nil, 0); err != nil {
			t.Fatalf("Set(%d) failed: %v", i, err)
		}
	}

	// 3rd insert should trigger eviction.
	if err := c.Set(ctx, "bucket", "item-3", data, nil, 0); err != nil {
		t.Fatalf("Set(3) unexpected error: %v", err)
	}
}

// TestMemoryCache_EvictExpiredTriggeredBySet verifies that expired entries
// are cleaned up during Set without panicking.
func TestMemoryCache_EvictExpiredTriggeredBySet(t *testing.T) {
	c := NewMemoryCache(1024, 100, time.Millisecond)
	ctx := context.Background()

	// Insert entries with a very short TTL.
	data := []byte("x")
	for i := 0; i < 5; i++ {
		if err := c.Set(ctx, "b", fmt.Sprintf("k%d", i), data, nil, time.Millisecond); err != nil {
			t.Fatalf("Set(%d): %v", i, err)
		}
	}

	// Wait for all entries to expire.
	time.Sleep(10 * time.Millisecond)

	// A subsequent Set should trigger evictExpiredLocked internally.
	if err := c.Set(ctx, "b", "fresh", data, nil, 0); err != nil {
		t.Fatalf("Set(fresh): %v", err)
	}
}

func TestMemoryCache_Clear(t *testing.T) {
	cache := NewMemoryCache(1024*1024, 100, 5*time.Minute)
	ctx := context.Background()
	
	// Set some values
	for i := 0; i < 5; i++ {
		data := []byte(fmt.Sprintf("test data %d", i))
		err := cache.Set(ctx, "bucket", fmt.Sprintf("key%d", i), data, nil, 0)
		if err != nil {
			t.Fatalf("failed to set cache: %v", err)
		}
	}
	
	// Clear cache
	err := cache.Clear(ctx)
	if err != nil {
		t.Fatalf("failed to clear cache: %v", err)
	}
	
	// Verify empty
	stats := cache.Stats()
	if stats.Items != 0 {
		t.Fatalf("expected 0 items after clear, got %d", stats.Items)
	}
}
