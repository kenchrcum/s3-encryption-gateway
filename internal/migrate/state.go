package migrate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Stats holds migration statistics.
type Stats struct {
	Total       int64 `json:"total"`
	Migrated    int64 `json:"migrated"`
	Scanned     int64 `json:"scanned"`    // objects successfully read/decrypted in dry-run
	Skipped     int64 `json:"skipped"`    // ClassModern / ClassPlaintext
	Failed      int64 `json:"failed"`
	ClassA      int64 `json:"class_a"`
	ClassB      int64 `json:"class_b"`
	ClassC_XOR  int64 `json:"class_c_xor"`
	ClassC_HKDF int64 `json:"class_c_hkdf"`
	ClassD      int64 `json:"class_d"`
}

// FailedObject records a single object that could not be migrated.
type FailedObject struct {
	Key   string `json:"key"`
	Error string `json:"error"`
}

// State holds the progress of a migration run.
type State struct {
	Bucket         string         `json:"bucket"`
	Prefix         string         `json:"prefix,omitempty"`
	Checkpoint     string         `json:"checkpoint,omitempty"` // last successfully processed key
	GatewayVersion string         `json:"gateway_version,omitempty"`
	DryRun         bool           `json:"dry_run"`              // true if this state file was produced by a dry-run
	Started        time.Time      `json:"started"`
	Updated        time.Time      `json:"updated"`
	Stats          Stats          `json:"stats"`
	Failed         []FailedObject `json:"failed,omitempty"`

	mu sync.RWMutex `json:"-"`
}

// NewState creates a new migration state for the given bucket and prefix.
func NewState(bucket, prefix string) *State {
	now := time.Now().UTC()
	return &State{
		Bucket:  bucket,
		Prefix:  prefix,
		Started: now,
		Updated: now,
	}
}

// LoadOrCreate loads a state from the given path or creates a new one if the
// file does not exist. The returned bool is true when an existing file was loaded.
func LoadOrCreate(path, bucket, prefix string) (*State, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewState(bucket, prefix), false, nil
		}
		return nil, false, fmt.Errorf("failed to read state file: %w", err)
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, false, fmt.Errorf("failed to parse state file: %w", err)
	}
	return &s, true, nil
}

// Save atomically writes the state to the given path using a temporary file
// and rename.
func (s *State) Save(path string) error {
	s.mu.RLock()
	data, err := json.MarshalIndent(s, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create state directory: %w", err)
		}
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary state file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename state file: %w", err)
	}

	return nil
}

// IsCompleted reports whether the given object key has already been processed
// (i.e. it is lexicographically <= the current checkpoint).
//
// S3 ListObjectsV2 returns keys in lexicographic order, so this check is
// sufficient for resume correctness.
func (s *State) IsCompleted(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Checkpoint != "" && key <= s.Checkpoint
}

// MarkDone records a successfully migrated object and updates the checkpoint.
func (s *State) MarkDone(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Checkpoint = key
	s.Stats.Migrated++
	s.Updated = time.Now().UTC()
}

// MarkScanned records a successfully read-decrypted object in dry-run mode
// and updates the checkpoint.
func (s *State) MarkScanned(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Checkpoint = key
	s.Stats.Scanned++
	s.Updated = time.Now().UTC()
}

// MarkSkipped increments the skipped counter.
func (s *State) MarkSkipped() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Stats.Skipped++
	s.Updated = time.Now().UTC()
}

// MarkClass increments the per-class counter.
func (s *State) MarkClass(c ObjectClass) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch c {
	case ClassA_XOR:
		s.Stats.ClassA++
	case ClassB_NoAAD:
		s.Stats.ClassB++
	case ClassC_Fallback_XOR:
		s.Stats.ClassC_XOR++
	case ClassC_Fallback_HKDF:
		s.Stats.ClassC_HKDF++
	case ClassD_LegacyKDF:
		s.Stats.ClassD++
	}
	s.Updated = time.Now().UTC()
}

// MarkFailed records a failed object.
func (s *State) MarkFailed(key string, errStr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Stats.Failed++
	s.Failed = append(s.Failed, FailedObject{Key: key, Error: errStr})
	s.Updated = time.Now().UTC()
}

// Snapshot returns a copy of the current stats for reporting without
// holding the lock.
func (s *State) Snapshot() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Stats
}
