package crypto

import (
	"sync"
	"testing"
	"time"
)

func TestRotationState_InitialPhase(t *testing.T) {
	rs := NewRotationState()
	if rs.Phase() != RotationIdle {
		t.Fatalf("expected idle, got %s", rs.Phase())
	}
}

func TestRotationState_FullLifecycle(t *testing.T) {
	rs := NewRotationState()
	plan := &RotationPlan{CurrentVersion: 1, TargetVersion: 2}

	// Start drain
	err := rs.StartDrain("rot-1", 1, 2, "memory", plan, 5*time.Second)
	if err != nil {
		t.Fatalf("StartDrain: %v", err)
	}
	if rs.Phase() != RotationDraining {
		t.Fatalf("expected draining, got %s", rs.Phase())
	}

	// Since no in-flight wraps, drain should complete quickly
	time.Sleep(200 * time.Millisecond)
	if rs.Phase() != RotationReadyToCutover {
		t.Fatalf("expected ready_for_cutover, got %s", rs.Phase())
	}

	// Commit
	err = rs.Commit(false)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if rs.Phase() != RotationCommitting {
		t.Fatalf("expected committing, got %s", rs.Phase())
	}

	rs.MarkCommitted()
	if rs.Phase() != RotationCommitted {
		t.Fatalf("expected committed, got %s", rs.Phase())
	}

	// Snapshot should return a defensive copy
	snap := rs.Snapshot()
	if snap.Phase != "committed" {
		t.Fatalf("snapshot phase expected committed, got %s", snap.Phase)
	}
	if snap.RotationID != "rot-1" {
		t.Fatalf("snapshot rotation_id expected rot-1, got %s", snap.RotationID)
	}

	// Reset
	rs.Reset()
	if rs.Phase() != RotationIdle {
		t.Fatalf("expected idle after reset, got %s", rs.Phase())
	}
}

func TestRotationState_Abort(t *testing.T) {
	rs := NewRotationState()
	plan := &RotationPlan{CurrentVersion: 1, TargetVersion: 2}

	err := rs.StartDrain("rot-2", 1, 2, "memory", plan, 5*time.Second)
	if err != nil {
		t.Fatalf("StartDrain: %v", err)
	}

	// Simulate in-flight wrap to prevent auto-drain
	rs.BeginWrap()

	// Abort should work from Draining
	err = rs.Abort()
	if err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if rs.Phase() != RotationAborted {
		t.Fatalf("expected aborted, got %s", rs.Phase())
	}

	rs.EndWrap()
}

func TestRotationState_DoubleStart_Conflict(t *testing.T) {
	rs := NewRotationState()
	plan := &RotationPlan{CurrentVersion: 1, TargetVersion: 2}

	err := rs.StartDrain("rot-1", 1, 2, "memory", plan, 5*time.Second)
	if err != nil {
		t.Fatalf("first StartDrain: %v", err)
	}

	// Second start should fail
	err = rs.StartDrain("rot-2", 1, 2, "memory", plan, 5*time.Second)
	if err == nil {
		t.Fatal("expected error on second StartDrain")
	}
}

func TestRotationState_CommitFromDraining_Force(t *testing.T) {
	rs := NewRotationState()
	plan := &RotationPlan{CurrentVersion: 1, TargetVersion: 2}

	err := rs.StartDrain("rot-3", 1, 2, "memory", plan, 30*time.Second)
	if err != nil {
		t.Fatalf("StartDrain: %v", err)
	}

	// Simulate in-flight wrap
	rs.BeginWrap()

	// Non-force commit should fail while in-flight > 0
	err = rs.Commit(false)
	if err == nil {
		t.Fatal("expected error on commit with in-flight wraps")
	}

	// Force commit should succeed
	err = rs.Commit(true)
	if err != nil {
		t.Fatalf("force Commit: %v", err)
	}

	rs.EndWrap()
}

func TestRotationState_GraceDeadlineElapsed(t *testing.T) {
	rs := NewRotationState()
	plan := &RotationPlan{CurrentVersion: 1, TargetVersion: 2}

	// Very short grace period
	err := rs.StartDrain("rot-4", 1, 2, "memory", plan, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("StartDrain: %v", err)
	}

	// Simulate in-flight wrap to block normal drain completion
	rs.BeginWrap()

	// Wait for grace period to elapse
	time.Sleep(300 * time.Millisecond)

	if rs.Phase() != RotationReadyToCutover {
		t.Fatalf("expected ready_for_cutover after grace deadline, got %s", rs.Phase())
	}

	rs.EndWrap()
}

func TestRotationState_ConcurrentBeginEndWrap(t *testing.T) {
	rs := NewRotationState()

	var wg sync.WaitGroup
	n := 100
	wg.Add(n * 2)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			rs.BeginWrap()
		}()
		go func() {
			defer wg.Done()
			rs.BeginWrap()
			rs.EndWrap()
		}()
	}
	wg.Wait()

	// We did n extra BeginWrap calls (without EndWrap)
	count := rs.InFlightWraps()
	if count != int64(n) {
		t.Fatalf("expected %d in-flight, got %d", n, count)
	}
}

func TestRotationState_SnapshotDefensiveCopy(t *testing.T) {
	rs := NewRotationState()
	plan := &RotationPlan{CurrentVersion: 1, TargetVersion: 2}
	rs.StartDrain("rot-5", 1, 2, "memory", plan, 5*time.Second)

	snap1 := rs.Snapshot()
	snap2 := rs.Snapshot()

	// Modifying snap1 should not affect snap2
	if snap1.Plan != nil {
		snap1.Plan.TargetVersion = 999
	}
	if snap2.Plan != nil && snap2.Plan.TargetVersion == 999 {
		t.Fatal("snapshot is not a defensive copy")
	}
}

func TestRotationPhase_String(t *testing.T) {
	tests := []struct {
		phase    RotationPhase
		expected string
	}{
		{RotationIdle, "idle"},
		{RotationDraining, "draining"},
		{RotationReadyToCutover, "ready_for_cutover"},
		{RotationCommitting, "committing"},
		{RotationCommitted, "committed"},
		{RotationAborted, "aborted"},
		{RotationPhase(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.phase.String(); got != tt.expected {
			t.Errorf("RotationPhase(%d).String() = %q, want %q", tt.phase, got, tt.expected)
		}
	}
}

func TestRotationState_MarkFailed(t *testing.T) {
	rs := NewRotationState()
	plan := &RotationPlan{CurrentVersion: 1, TargetVersion: 2}
	rs.StartDrain("rot-6", 1, 2, "memory", plan, 5*time.Second)
	time.Sleep(200 * time.Millisecond)

	rs.Commit(false)
	rs.MarkFailed(ErrRotationConflict)

	if rs.Phase() != RotationAborted {
		t.Fatalf("expected aborted, got %s", rs.Phase())
	}
	snap := rs.Snapshot()
	if snap.Error == "" {
		t.Fatal("expected error in snapshot")
	}
}
