package crypto

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// RotationPhase represents a stage in the key rotation state machine.
type RotationPhase int

const (
	RotationIdle           RotationPhase = iota // no rotation in progress
	RotationDraining                            // waiting for in-flight wraps to drain
	RotationReadyToCutover                      // in-flight count is zero; safe to commit
	RotationCommitting                          // PromoteActiveVersion in progress
	RotationCommitted                           // rotation complete
	RotationAborted                             // rotation aborted by operator
)

// String implements [fmt.Stringer] for JSON marshalling and logging.
func (p RotationPhase) String() string {
	switch p {
	case RotationIdle:
		return "idle"
	case RotationDraining:
		return "draining"
	case RotationReadyToCutover:
		return "ready_for_cutover"
	case RotationCommitting:
		return "committing"
	case RotationCommitted:
		return "committed"
	case RotationAborted:
		return "aborted"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}

// RotationSnapshot is a defensive copy of the rotation state, safe to marshal
// and return from the status endpoint without holding locks.
type RotationSnapshot struct {
	RotationID     string        `json:"rotation_id"`
	Phase          string        `json:"phase"`
	CurrentVersion int           `json:"current_version"`
	TargetVersion  int           `json:"target_version"`
	InFlightWraps  int64         `json:"in_flight_wraps"`
	StartedAt      time.Time     `json:"started_at,omitempty"`
	CompletedAt    time.Time     `json:"completed_at,omitempty"`
	GraceDeadline  time.Time     `json:"grace_deadline,omitempty"`
	Error          string        `json:"error,omitempty"`
	Provider       string        `json:"provider,omitempty"`
	Plan           *RotationPlan `json:"plan,omitempty"`
}

// RotationState manages the drain-and-cutover state machine for key rotation.
// The in-flight counter uses atomic operations for the zero-allocation fast path.
type RotationState struct {
	mu sync.Mutex

	phase          RotationPhase
	rotationID     string
	currentVersion int
	targetVersion  int
	provider       string
	plan           *RotationPlan
	startedAt      time.Time
	completedAt    time.Time
	graceDeadline  time.Time
	lastError      string

	inFlightWraps int64 // atomic

	// drainDone is closed when the drain goroutine completes or the
	// rotation is aborted.
	drainDone chan struct{}

	// stopDrain signals the drain goroutine to exit.
	stopDrain chan struct{}
}

// NewRotationState creates a new idle rotation state machine.
func NewRotationState() *RotationState {
	return &RotationState{
		phase: RotationIdle,
	}
}

// Phase returns the current rotation phase.
func (rs *RotationState) Phase() RotationPhase {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.phase
}

// BeginWrap increments the in-flight wrap counter. This is the hot-path
// call inserted around every WrapKey invocation. Uses atomic for zero
// allocations.
func (rs *RotationState) BeginWrap() {
	atomic.AddInt64(&rs.inFlightWraps, 1)
}

// EndWrap decrements the in-flight wrap counter.
func (rs *RotationState) EndWrap() {
	atomic.AddInt64(&rs.inFlightWraps, -1)
}

// InFlightWraps returns the current in-flight count.
func (rs *RotationState) InFlightWraps() int64 {
	return atomic.LoadInt64(&rs.inFlightWraps)
}

// StartDrain transitions from Idle to Draining. Returns an error if the
// state machine is not in the Idle state.
func (rs *RotationState) StartDrain(rotationID string, currentVersion, targetVersion int, provider string, plan *RotationPlan, gracePeriod time.Duration) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.phase != RotationIdle {
		return fmt.Errorf("%w: cannot start drain from phase %s", ErrRotationConflict, rs.phase)
	}

	rs.phase = RotationDraining
	rs.rotationID = rotationID
	rs.currentVersion = currentVersion
	rs.targetVersion = targetVersion
	rs.provider = provider
	rs.plan = plan
	rs.startedAt = time.Now()
	rs.completedAt = time.Time{}
	rs.lastError = ""

	if gracePeriod > 0 {
		rs.graceDeadline = rs.startedAt.Add(gracePeriod)
	}

	rs.drainDone = make(chan struct{})
	rs.stopDrain = make(chan struct{})

	// Launch drain poller
	go rs.drainPoller()

	return nil
}

// drainPoller polls the in-flight counter at 100ms intervals and transitions
// to ReadyToCutover when the count reaches zero or the grace deadline elapses.
func (rs *RotationState) drainPoller() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	defer close(rs.drainDone)

	for {
		select {
		case <-rs.stopDrain:
			return
		case <-ticker.C:
			count := atomic.LoadInt64(&rs.inFlightWraps)
			if count <= 0 {
				rs.mu.Lock()
				if rs.phase == RotationDraining {
					rs.phase = RotationReadyToCutover
				}
				rs.mu.Unlock()
				return
			}
			// Check grace deadline
			rs.mu.Lock()
			if !rs.graceDeadline.IsZero() && time.Now().After(rs.graceDeadline) {
				if rs.phase == RotationDraining {
					rs.phase = RotationReadyToCutover
				}
				rs.mu.Unlock()
				return
			}
			rs.mu.Unlock()
		}
	}
}

// Commit transitions from {Draining (if in_flight==0 or force), ReadyToCutover}
// to Committing. Returns an error if the state is invalid.
func (rs *RotationState) Commit(force bool) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	switch rs.phase {
	case RotationReadyToCutover:
		rs.phase = RotationCommitting
		return nil
	case RotationDraining:
		if force || atomic.LoadInt64(&rs.inFlightWraps) <= 0 {
			rs.phase = RotationCommitting
			// Stop the drain poller
			select {
			case <-rs.stopDrain:
			default:
				close(rs.stopDrain)
			}
			return nil
		}
		return fmt.Errorf("%w: cannot commit while in_flight_wraps > 0 (use force=true to override)", ErrRotationConflict)
	default:
		return fmt.Errorf("%w: cannot commit from phase %s", ErrRotationConflict, rs.phase)
	}
}

// MarkCommitted transitions from Committing to Committed.
func (rs *RotationState) MarkCommitted() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.phase = RotationCommitted
	rs.completedAt = time.Now()
}

// MarkFailed transitions from Committing to Aborted with an error.
func (rs *RotationState) MarkFailed(err error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.phase = RotationAborted
	rs.completedAt = time.Now()
	if err != nil {
		rs.lastError = err.Error()
	}
}

// Abort transitions from {Draining, ReadyToCutover} to Aborted.
func (rs *RotationState) Abort() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	switch rs.phase {
	case RotationDraining, RotationReadyToCutover:
		rs.phase = RotationAborted
		rs.completedAt = time.Now()
		// Stop drain poller if running
		if rs.stopDrain != nil {
			select {
			case <-rs.stopDrain:
			default:
				close(rs.stopDrain)
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: cannot abort from phase %s", ErrRotationConflict, rs.phase)
	}
}

// Reset transitions terminal states {Committed, Aborted} back to Idle.
func (rs *RotationState) Reset() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.phase = RotationIdle
	rs.rotationID = ""
	rs.currentVersion = 0
	rs.targetVersion = 0
	rs.provider = ""
	rs.plan = nil
	rs.startedAt = time.Time{}
	rs.completedAt = time.Time{}
	rs.graceDeadline = time.Time{}
	rs.lastError = ""
}

// Snapshot returns a defensive copy of the current state.
func (rs *RotationState) Snapshot() RotationSnapshot {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	snap := RotationSnapshot{
		RotationID:     rs.rotationID,
		Phase:          rs.phase.String(),
		CurrentVersion: rs.currentVersion,
		TargetVersion:  rs.targetVersion,
		InFlightWraps:  atomic.LoadInt64(&rs.inFlightWraps),
		StartedAt:      rs.startedAt,
		CompletedAt:    rs.completedAt,
		GraceDeadline:  rs.graceDeadline,
		Error:          rs.lastError,
		Provider:       rs.provider,
	}
	if rs.plan != nil {
		planCopy := *rs.plan
		snap.Plan = &planCopy
	}
	return snap
}
