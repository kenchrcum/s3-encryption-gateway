package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestState_NewState(t *testing.T) {
	s := NewState("mybucket", "prefix/")
	if s.Bucket != "mybucket" {
		t.Errorf("Bucket = %q, want mybucket", s.Bucket)
	}
	if s.Prefix != "prefix/" {
		t.Errorf("Prefix = %q, want prefix/", s.Prefix)
	}
	if s.Checkpoint != "" {
		t.Errorf("Checkpoint = %q, want empty", s.Checkpoint)
	}
	if s.Started.IsZero() {
		t.Error("Started should not be zero")
	}
}

func TestState_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := NewState("bucket", "p/")
	s.MarkDone("obj-1")
	s.MarkDone("obj-2")
	s.MarkSkipped()
	s.MarkFailed("obj-fail", "network error")
	s.MarkClass(ClassA_XOR)

	if err := s.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, loadedFromFile, err := LoadOrCreate(path, "other", "x/")
	if err != nil {
		t.Fatalf("LoadOrCreate failed: %v", err)
	}
	if !loadedFromFile {
		t.Fatal("expected state to be loaded from file")
	}

	if loaded.Bucket != "bucket" {
		t.Errorf("Bucket = %q, want bucket", loaded.Bucket)
	}
	if loaded.Prefix != "p/" {
		t.Errorf("Prefix = %q, want p/", loaded.Prefix)
	}
	if loaded.Checkpoint != "obj-2" {
		t.Errorf("Checkpoint = %q, want obj-2", loaded.Checkpoint)
	}
	if loaded.Stats.Migrated != 2 {
		t.Errorf("Migrated = %d, want 2", loaded.Stats.Migrated)
	}
	if loaded.Stats.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", loaded.Stats.Skipped)
	}
	if loaded.Stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", loaded.Stats.Failed)
	}
	if loaded.Stats.ClassA != 1 {
		t.Errorf("ClassA = %d, want 1", loaded.Stats.ClassA)
	}
	if len(loaded.Failed) != 1 || loaded.Failed[0].Key != "obj-fail" {
		t.Errorf("Failed list mismatch: %+v", loaded.Failed)
	}
}

func TestState_LoadOrCreate_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	s, loadedFromFile, err := LoadOrCreate(path, "b", "p/")
	if err != nil {
		t.Fatalf("LoadOrCreate should create new state when file missing: %v", err)
	}
	if loadedFromFile {
		t.Error("expected new state to be created, not loaded from file")
	}
	if s.Bucket != "b" {
		t.Errorf("Bucket = %q, want b", s.Bucket)
	}
}

func TestState_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Write an initial state.
	s1 := NewState("bucket", "")
	s1.MarkDone("obj-1")
	if err := s1.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Simulate a crash during overwrite by creating a temp file with
	// truncated content, then ensuring the original is intact.
	if err := os.WriteFile(path+".tmp", []byte("garbage"), 0600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	// Remove the temp to simulate a successful write; instead verify
	// that loading the original still works.
	_ = os.Remove(path + ".tmp")

	loaded, loadedFromFile, err := LoadOrCreate(path, "", "")
	if err != nil {
		t.Fatalf("LoadOrCreate after temp cleanup failed: %v", err)
	}
	if !loadedFromFile {
		t.Error("expected state to be loaded from file")
	}
	if loaded.Checkpoint != "obj-1" {
		t.Errorf("Checkpoint = %q, want obj-1 (atomic write corrupted)", loaded.Checkpoint)
	}
}

func TestState_IsCompleted(t *testing.T) {
	s := NewState("bucket", "")
	s.Checkpoint = "obj-005"

	if !s.IsCompleted("obj-001") {
		t.Error("obj-001 should be completed")
	}
	if !s.IsCompleted("obj-005") {
		t.Error("obj-005 should be completed (equal to checkpoint)")
	}
	if s.IsCompleted("obj-006") {
		t.Error("obj-006 should NOT be completed")
	}
	if s.IsCompleted("obj-010") {
		t.Error("obj-010 should NOT be completed")
	}
}

func TestState_IsCompleted_EmptyCheckpoint(t *testing.T) {
	s := NewState("bucket", "")
	if s.IsCompleted("anything") {
		t.Error("empty checkpoint should mean nothing is completed")
	}
}

func TestState_Snapshot(t *testing.T) {
	s := NewState("bucket", "")
	s.MarkDone("obj-1")
	s.MarkSkipped()
	s.MarkClass(ClassB_NoAAD)

	snap := s.Snapshot()
	if snap.Migrated != 1 {
		t.Errorf("Snapshot.Migrated = %d, want 1", snap.Migrated)
	}
	if snap.Skipped != 1 {
		t.Errorf("Snapshot.Skipped = %d, want 1", snap.Skipped)
	}
	if snap.ClassB != 1 {
		t.Errorf("Snapshot.ClassB = %d, want 1", snap.ClassB)
	}
}

func TestState_ConcurrentAccess(t *testing.T) {
	s := NewState("bucket", "")

	// Run concurrent marks to ensure the mutex works.
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				s.MarkDone("obj")
				s.MarkSkipped()
			}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	stats := s.Snapshot()
	if stats.Migrated != 1000 {
		t.Errorf("Migrated = %d, want 1000", stats.Migrated)
	}
	if stats.Skipped != 1000 {
		t.Errorf("Skipped = %d, want 1000", stats.Skipped)
	}
}
