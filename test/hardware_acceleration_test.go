//go:build integration
// +build integration

package test

import (
	"strings"
	"testing"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHardwareAccelerationIntegration verifies the integration between
// config, crypto detection, and metrics reporting for hardware acceleration.
func TestHardwareAccelerationIntegration(t *testing.T) {
	// 1. Setup Configuration
	// Simulate default configuration where hardware acceleration is enabled
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			Hardware: config.HardwareConfig{
				EnableAESNI:    true,
				EnableARMv8AES: true,
			},
		},
	}

	// 2. Check Crypto Detection
	// We can't change the actual hardware, but we can verify the logic flows correctly
	hwInfo := crypto.GetHardwareAccelerationInfo(&cfg.Encryption.Hardware)

	require.Contains(t, hwInfo, "aes_hardware_support")
	require.Contains(t, hwInfo, "architecture")
	require.Contains(t, hwInfo, "hardware_acceleration_active")
	require.Contains(t, hwInfo, "aes_ni_enabled")
	require.Contains(t, hwInfo, "armv8_aes_enabled")

	// verify active status logic matches expected based on hardware support and config
	hasSupport := hwInfo["aes_hardware_support"].(bool)
	isActive := hwInfo["hardware_acceleration_active"].(bool)
	
	if hasSupport {
		// If hardware supports it and config enables it (default), it should be active
		assert.True(t, isActive, "Hardware acceleration should be active when supported and enabled")
	} else {
		assert.False(t, isActive, "Hardware acceleration should be inactive when not supported")
	}

	// 3. Setup Metrics
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)

	// 4. Simulate Main.go Logic for reporting to metrics
	if active, ok := hwInfo["hardware_acceleration_active"].(bool); ok {
		accelType := "unknown"
		arch := hwInfo["architecture"].(string)
		if strings.Contains(arch, "amd64") || strings.Contains(arch, "386") {
			accelType = "aes-ni"
		} else if strings.Contains(arch, "arm") {
			accelType = "armv8-aes"
		} else if strings.Contains(arch, "s390x") {
			accelType = "s390x-aes" // Added for completeness
		}
		
		m.SetHardwareAccelerationStatus(accelType, active)

		// 5. Verify Metrics Reporting
		// Check that the metric is recorded with correct value (1 for active, 0 for inactive)
		expectedVal := 0.0
		if active {
			expectedVal = 1.0
		}

		// We need to find the metric with the specific label
		// Since we don't know exact architecture of test runner, we check if ANY valid label has the value
		// But we know what we set above.
		
		val := testutil.ToFloat64(m.GetHardwareAccelerationEnabledMetric().WithLabelValues(accelType))
		assert.Equal(t, expectedVal, val, "Metric value should match active status")
	}
}

// TestHardwareAccelerationConfigDisable verifies that disabling via config works
func TestHardwareAccelerationConfigDisable(t *testing.T) {
	// Setup Configuration with acceleration DISABLED
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			Hardware: config.HardwareConfig{
				EnableAESNI:    false, // Disabled
				EnableARMv8AES: false, // Disabled
			},
		},
	}

	// Check Crypto Detection
	hwInfo := crypto.GetHardwareAccelerationInfo(&cfg.Encryption.Hardware)
	
	// If we are on x86/arm, active should be false regardless of support
	// (Unless architecture is s390x or others which we didn't flag-gate effectively in the test logic above, 
	// strictly speaking the code allows 'true' for unknown archs if supported, but let's assume standard test env)
	
	// Verify logic: IsHardwareAccelerationEnabled should return false if config is false for that arch
	// Note: We are testing the integration of the components here
	
	// If we have support, verify that disabling config makes it inactive
	if hwInfo["aes_hardware_support"].(bool) {
		arch := hwInfo["architecture"].(string)
		if strings.Contains(arch, "amd64") || strings.Contains(arch, "arm64") {
			assert.False(t, hwInfo["hardware_acceleration_active"].(bool), "Hardware acceleration should be inactive when disabled in config")
		}
	}
}

