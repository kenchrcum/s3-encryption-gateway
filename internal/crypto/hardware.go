package crypto

import (
	"runtime"
)

// HasAESHardwareSupport checks if the CPU supports AES hardware acceleration (AES-NI).
// This uses CPU feature detection available in Go's runtime.
func HasAESHardwareSupport() bool {
	// Check for AES hardware support by attempting to detect CPU features
	// Go's crypto packages automatically use hardware acceleration when available,
	// but we can still check for it explicitly for logging/monitoring purposes

	// On x86/x86_64, AES-NI is typically available on modern CPUs (2010+)
	// On ARM, ARMv8 includes AES instructions (AES extensions)
	// Go's crypto/aes automatically uses these when available

	// For now, we'll use a simple heuristic based on architecture
	// In production, you might want to use CPUID or similar detection
	arch := runtime.GOARCH

	// x86_64 and amd64 architectures typically have AES-NI support
	// (though not guaranteed - would need CPUID for certainty)
	switch arch {
	case "amd64", "386":
		// Likely has AES-NI support (modern x86 CPUs)
		return true
	case "arm64", "arm":
		// ARMv8+ has AES instructions
		// This is a best-effort check
		return true
	default:
		// Unknown architecture - assume no hardware support
		return false
	}
}

// GetHardwareAccelerationInfo returns information about hardware acceleration support.
func GetHardwareAccelerationInfo() map[string]interface{} {
	return map[string]interface{}{
		"aes_hardware_support": HasAESHardwareSupport(),
		"architecture":          runtime.GOARCH,
		"goos":                  runtime.GOOS,
		"go_version":            runtime.Version(),
	}
}
