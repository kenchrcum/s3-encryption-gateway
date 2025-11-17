package debug

import (
	"os"
	"sync"
)

var (
	enabled bool
	mu      sync.RWMutex
)

func init() {
	// Initialize from environment variables on package load
	// This ensures debug works even when not going through main.go (e.g., in tests)
	InitFromEnv()
}

// Enabled returns whether debug logging is enabled.
func Enabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return enabled
}

// SetEnabled sets whether debug logging is enabled.
func SetEnabled(value bool) {
	mu.Lock()
	defer mu.Unlock()
	enabled = value
}

// InitFromEnv initializes debug logging from environment variable or log level.
// If DEBUG=true is set, it enables debug logging.
// Otherwise, it checks if LOG_LEVEL=debug.
func InitFromEnv() {
	if os.Getenv("DEBUG") == "true" {
		SetEnabled(true)
		return
	}
	if os.Getenv("LOG_LEVEL") == "debug" {
		SetEnabled(true)
		return
	}
	SetEnabled(false)
}

// InitFromLogLevel initializes debug logging from a log level string.
// This will only set the flag if no environment variable is already set.
func InitFromLogLevel(logLevel string) {
	// Only override if environment variable is not set
	if os.Getenv("DEBUG") == "" && os.Getenv("LOG_LEVEL") == "" {
		SetEnabled(logLevel == "debug")
	}
}

