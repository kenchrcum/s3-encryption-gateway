package crypto

import (
	"runtime"
	"testing"
)

func TestHasAESHardwareSupport(t *testing.T) {
	// This test just verifies the function works and returns a boolean
	support := HasAESHardwareSupport()
	if support && runtime.GOARCH != "amd64" && runtime.GOARCH != "386" && runtime.GOARCH != "arm64" && runtime.GOARCH != "arm" {
		t.Errorf("HasAESHardwareSupport() returned true for unknown architecture: %s", runtime.GOARCH)
	}
}

func TestGetHardwareAccelerationInfo(t *testing.T) {
	info := GetHardwareAccelerationInfo()

	// Verify required fields
	requiredFields := []string{"aes_hardware_support", "architecture", "goos", "go_version"}
	for _, field := range requiredFields {
		if _, ok := info[field]; !ok {
			t.Errorf("GetHardwareAccelerationInfo() missing field: %s", field)
		}
	}

	// Verify architecture matches runtime
	if info["architecture"] != runtime.GOARCH {
		t.Errorf("GetHardwareAccelerationInfo() architecture mismatch: got %s, want %s", info["architecture"], runtime.GOARCH)
	}

	// Verify aes_hardware_support is boolean
	if _, ok := info["aes_hardware_support"].(bool); !ok {
		t.Errorf("GetHardwareAccelerationInfo() aes_hardware_support should be bool")
	}
}
