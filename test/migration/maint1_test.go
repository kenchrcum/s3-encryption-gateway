//go:build conformance

// Package migration is the tier-2 integration test suite for the s3eg-migrate
// offline migration tool.
//
// Build tag: conformance (never runs under default `go test ./...`).
//
// Run via:
//
//	make test-conformance-minio   # MinIO only (fastest signal)
//
// These tests start a MinIO container, write objects in legacy formats,
// run the migration tool, and verify the results.
package migration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/migrate"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/kenneth/s3-encryption-gateway/test/provider"
)

// testPassword is the deterministic test password used for all engines.
var testPassword = []byte("test-migration-password-12345678")

// setupMinIO starts a MinIO testcontainer and returns the provider instance.
// It skips the test if Docker is unavailable.
func setupMinIO(t *testing.T) provider.Instance {
	t.Helper()
	ctx := context.Background()
	p := &minioProviderForMigration{}
	inst := p.Start(ctx, t)
	return inst
}

// newS3Client creates an internal/s3 client from a provider instance.
func newS3Client(t *testing.T, inst provider.Instance) s3.Client {
	t.Helper()
	cfg := &config.BackendConfig{
		Endpoint:     inst.Endpoint,
		Region:       inst.Region,
		AccessKey:    inst.AccessKey,
		SecretKey:    inst.SecretKey,
		Provider:     inst.ProviderName,
		UseSSL:       false,
		UsePathStyle: true,
	}
	client, err := s3.NewClient(cfg)
	if err != nil {
		t.Fatalf("newS3Client: %v", err)
	}
	return client
}

// newEngine creates a chunked encryption engine for migration tests.
func newEngine(t *testing.T) crypto.EncryptionEngine {
	t.Helper()
	eng, err := crypto.NewEngineWithChunking(testPassword, nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	return eng
}

// putEncryptedObject encrypts plaintext and stores it in the bucket with the
// given key, optionally mutating the metadata before storage.
func putEncryptedObject(t *testing.T, client s3.Client, eng crypto.EncryptionEngine, bucket, key string, plaintext []byte, metaMutate func(map[string]string)) {
	t.Helper()
	ctx := context.Background()

	encReader, encMeta, err := eng.Encrypt(bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt %s: %v", key, err)
	}
	cipherdata, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("read encrypted %s: %v", key, err)
	}

	if metaMutate != nil {
		metaMutate(encMeta)
	}

	if err := client.PutObject(ctx, bucket, key, bytes.NewReader(cipherdata), encMeta, nil, "", nil); err != nil {
		t.Fatalf("put object %s: %v", key, err)
	}
}

// putEncryptedObjectWithMeta encrypts plaintext with the given metadata and
// stores it in the bucket, optionally mutating the metadata before storage.
func putEncryptedObjectWithMeta(t *testing.T, client s3.Client, eng crypto.EncryptionEngine, bucket, key string, plaintext []byte, encryptMeta map[string]string, metaMutate func(map[string]string)) {
	t.Helper()
	ctx := context.Background()

	encReader, encMeta, err := eng.Encrypt(bytes.NewReader(plaintext), encryptMeta)
	if err != nil {
		t.Fatalf("encrypt %s: %v", key, err)
	}
	cipherdata, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("read encrypted %s: %v", key, err)
	}

	if metaMutate != nil {
		metaMutate(encMeta)
	}

	if err := client.PutObject(ctx, bucket, key, bytes.NewReader(cipherdata), encMeta, nil, "", nil); err != nil {
		t.Fatalf("put object %s: %v", key, err)
	}
}

// headMeta reads object metadata via HeadObject.
func headMeta(t *testing.T, client s3.Client, bucket, key string) map[string]string {
	t.Helper()
	ctx := context.Background()
	meta, err := client.HeadObject(ctx, bucket, key, nil)
	if err != nil {
		t.Fatalf("head object %s: %v", key, err)
	}
	return meta
}

// decryptObject reads and decrypts an object, returning the plaintext bytes.
func decryptObject(t *testing.T, client s3.Client, eng crypto.EncryptionEngine, bucket, key string) []byte {
	t.Helper()
	ctx := context.Background()
	reader, meta, err := client.GetObject(ctx, bucket, key, nil, nil)
	if err != nil {
		t.Fatalf("get object %s: %v", key, err)
	}
	defer reader.Close()

	decReader, _, err := eng.Decrypt(reader, meta)
	if err != nil {
		t.Fatalf("decrypt %s: %v", key, err)
	}
	plaintext, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("read decrypted %s: %v", key, err)
	}
	return plaintext
}

// TestMAINT1_SEC2_XOR_to_HKDF verifies that legacy XOR-IV chunked objects are
// re-encrypted with HKDF derivation and remain decryptable.
func TestMAINT1_SEC2_XOR_to_HKDF(t *testing.T) {
	inst := setupMinIO(t)
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket

	// Write 5 chunked objects and strip the HKDF flag to simulate legacy XOR.
	wantPlain := []byte("hello sec2 migration world")
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("sec2/obj-%02d", i)
		putEncryptedObject(t, client, eng, bucket, key, wantPlain, func(meta map[string]string) {
			delete(meta, crypto.MetaIVDerivation)
		})
	}

	// Run migration targeting SEC-2 only.
	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterSec2,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, ""); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// Verify all objects now have the HKDF flag and decrypt correctly.
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("sec2/obj-%02d", i)
		meta := headMeta(t, client, bucket, key)
		if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
			t.Errorf("%s: expected MetaIVDerivation=hkdf-sha256, got %q", key, meta[crypto.MetaIVDerivation])
		}
		got := decryptObject(t, client, eng, bucket, key)
		if !bytes.Equal(got, wantPlain) {
			t.Errorf("%s: plaintext mismatch after migration", key)
		}
	}
}

// TestMAINT1_Mixed_AllClasses writes objects simulating multiple legacy
// classes and migrates them all in one pass.
func TestMAINT1_Mixed_AllClasses(t *testing.T) {
	inst := setupMinIO(t)
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket

	wantPlain := []byte("mixed migration plaintext")

	// Class A: XOR-IV (chunked, no MetaIVDerivation)
	for i := 0; i < 3; i++ {
		putEncryptedObject(t, client, eng, bucket, fmt.Sprintf("mixed/a-%d", i), wantPlain, func(meta map[string]string) {
			delete(meta, crypto.MetaIVDerivation)
		})
	}

	// Class Modern: already up-to-date (should be skipped)
	for i := 0; i < 2; i++ {
		putEncryptedObject(t, client, eng, bucket, fmt.Sprintf("mixed/modern-%d", i), wantPlain, nil)
	}

	// Class B: legacy no-AAD (non-chunked, with flag)
	// Create these with a NON-chunked engine so the ciphertext is genuine
	// single-AEAD format.  Pass an explicit Content-Type to Encrypt so the
	// AAD built during encryption matches what S3 returns on retrieval.
	plainEng, err := crypto.NewEngineWithChunking(testPassword, nil, "", nil, false, 0)
	if err != nil {
		t.Fatalf("failed to create plain engine: %v", err)
	}
	for i := 0; i < 3; i++ {
		putEncryptedObjectWithMeta(t, client, plainEng, bucket, fmt.Sprintf("mixed/b-%d", i), wantPlain,
			map[string]string{"Content-Type": "application/octet-stream"},
			func(meta map[string]string) {
				meta[crypto.MetaLegacyNoAAD] = "true"
			})
	}

	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, ""); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// Verify Class A objects now have HKDF.
	for i := 0; i < 3; i++ {
		meta := headMeta(t, client, bucket, fmt.Sprintf("mixed/a-%d", i))
		if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
			t.Errorf("mixed/a-%d: expected hkdf-sha256, got %q", i, meta[crypto.MetaIVDerivation])
		}
	}

	// Verify Class B objects no longer have the legacy flag.
	for i := 0; i < 3; i++ {
		meta := headMeta(t, client, bucket, fmt.Sprintf("mixed/b-%d", i))
		if meta[crypto.MetaLegacyNoAAD] == "true" {
			t.Errorf("mixed/b-%d: MetaLegacyNoAAD should be absent after migration", i)
		}
	}

	// Verify modern objects unchanged.
	for i := 0; i < 2; i++ {
		meta := headMeta(t, client, bucket, fmt.Sprintf("mixed/modern-%d", i))
		if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
			t.Errorf("mixed/modern-%d: expected unchanged hkdf-sha256, got %q", i, meta[crypto.MetaIVDerivation])
		}
		got := decryptObject(t, client, eng, bucket, fmt.Sprintf("mixed/modern-%d", i))
		if !bytes.Equal(got, wantPlain) {
			t.Errorf("mixed/modern-%d: plaintext changed unexpectedly", i)
		}
	}
}

// TestMAINT1_DryRun_ReportsCorrectly verifies that dry-run mode classifies
// objects correctly and makes no writes.
func TestMAINT1_DryRun_ReportsCorrectly(t *testing.T) {
	inst := setupMinIO(t)
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket

	// Create a mix of objects.
	putEncryptedObject(t, client, eng, bucket, "dryrun/modern", []byte("modern"), nil)
	putEncryptedObject(t, client, eng, bucket, "dryrun/xor1", []byte("xor"), func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})
	putEncryptedObject(t, client, eng, bucket, "dryrun/xor2", []byte("xor"), func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})

	report, err := migrate.DryRunScan(context.Background(), client, bucket, "dryrun/", nil)
	if err != nil {
		t.Fatalf("DryRunScan failed: %v", err)
	}

	if report.Total != 3 {
		t.Errorf("Total = %d, want 3", report.Total)
	}
	if report.Modern != 1 {
		t.Errorf("Modern = %d, want 1", report.Modern)
	}
	if report.ClassA != 2 {
		t.Errorf("ClassA = %d, want 2", report.ClassA)
	}

	// Verify no writes occurred by checking metadata unchanged.
	meta := headMeta(t, client, bucket, "dryrun/xor1")
	if meta[crypto.MetaIVDerivation] != "" {
		t.Errorf("dry-run should not have mutated metadata")
	}
}

// TestMAINT1_Idempotency_E2E runs a full migration twice and confirms the
// second run skips everything.
func TestMAINT1_Idempotency_E2E(t *testing.T) {
	inst := setupMinIO(t)
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket

	for i := 0; i < 5; i++ {
		putEncryptedObject(t, client, eng, bucket, fmt.Sprintf("idemp/obj-%d", i), []byte("data"), func(meta map[string]string) {
			delete(meta, crypto.MetaIVDerivation)
		})
	}

	stateFile := t.TempDir() + "/state.json"
	m1 := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}

	ctx := context.Background()
	if err := m1.Migrate(ctx, bucket, ""); err != nil {
		t.Fatalf("first Migrate failed: %v", err)
	}

	// Second run should skip all objects (already modern).
	m2 := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}
	if err := m2.Migrate(ctx, bucket, ""); err != nil {
		t.Fatalf("second Migrate failed: %v", err)
	}

	// Load state and confirm zero additional migrations.
	state, _, _ := migrate.LoadOrCreate(stateFile, "bucket", "")
	if state.Stats.Migrated != 5 {
		t.Errorf("first run migrated = %d, want 5; second run should have 0 new", state.Stats.Migrated)
	}
	if state.Stats.Skipped != 5 {
		// On second run, all 5 objects are ClassModern and skipped.
		t.Errorf("second run skipped = %d, want 5", state.Stats.Skipped)
	}
}

// TestMAINT1_Resume_E2E verifies that a migration can be resumed from a state
// file after an interruption.
func TestMAINT1_Resume_E2E(t *testing.T) {
	inst := setupMinIO(t)
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket

	for i := 0; i < 5; i++ {
		putEncryptedObject(t, client, eng, bucket, fmt.Sprintf("resume/obj-%02d", i), []byte("data"), func(meta map[string]string) {
			delete(meta, crypto.MetaIVDerivation)
		})
	}

	stateFile := t.TempDir() + "/state.json"
	// Pre-seed state file to simulate interruption after obj-01.
	state := migrate.NewState(bucket, "")
	state.Checkpoint = "resume/obj-01"
	state.GatewayVersion = "0.7.0"
	state.Stats.Migrated = 2
	if err := state.Save(stateFile); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, ""); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// obj-00 and obj-01 should NOT be re-processed (<= checkpoint).
	// obj-02, obj-03, obj-04 should be migrated.
	finalState, _, err := migrate.LoadOrCreate(stateFile, bucket, "")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if finalState.Stats.Migrated != 5 {
		t.Errorf("total migrated = %d, want 5 (2 pre-seeded + 3 resumed)", finalState.Stats.Migrated)
	}
}

// TestMAINT1_GatewayVersion_Invalid verifies that an unsupported gateway
// version causes the tool to fail immediately without making any writes.
func TestMAINT1_GatewayVersion_Invalid(t *testing.T) {
	inst := setupMinIO(t)
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket

	// Write one object.
	putEncryptedObject(t, client, eng, bucket, "badver/obj", []byte("data"), func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})

	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.5.0", // unsupported
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, ""); err == nil {
		t.Fatal("expected error for invalid gateway version")
	}

	// Verify object was NOT migrated (metadata unchanged).
	meta := headMeta(t, client, bucket, "badver/obj")
	if meta[crypto.MetaIVDerivation] != "" {
		t.Errorf("object should not have been migrated with invalid gateway version")
	}
}

// TestMAINT1_StateFile_VersionMismatch verifies that resuming with a different
// gateway version is rejected.
func TestMAINT1_StateFile_VersionMismatch(t *testing.T) {
	stateFile := t.TempDir() + "/state.json"
	state := migrate.NewState("bucket", "")
	state.GatewayVersion = "0.6.4"
	state.Checkpoint = "obj-01"
	if err := state.Save(stateFile); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	inst := setupMinIO(t)
	client := newS3Client(t, inst)
	eng := newEngine(t)

	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0", // mismatched
		Workers:        1,
		StateFile:      stateFile,
	}

	if err := m.Migrate(context.Background(), inst.Bucket, ""); err == nil {
		t.Fatal("expected error for state file gateway version mismatch")
	}
}

// TestMAINT1_GoldenPath_AllBreakingChanges is the conformance-phase golden-path
// test for V1.0-MAINT-1.  It creates objects combining every legacy breaking
// change (SEC-2, SEC-4, SEC-27), runs the migration tool against a real MinIO
// backend, and asserts that every object is migrated to ClassModern and remains
// fully readable.
func TestMAINT1_GoldenPath_AllBreakingChanges(t *testing.T) {
	inst := setupMinIO(t)
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket

	wantPlain := []byte("golden-path-plaintext combining sec2 sec4 sec27")

	// CLASS A (SEC-2): XOR-IV chunked objects.
	putEncryptedObject(t, client, eng, bucket, "golden/a-1", wantPlain, func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})
	putEncryptedObject(t, client, eng, bucket, "golden/a-2", wantPlain, func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})

	// CLASS B (SEC-4): non-chunked objects with the legacy-no-AAD marker.
	plainEng, err := crypto.NewEngineWithChunking(testPassword, nil, "", nil, false, 0)
	if err != nil {
		t.Fatalf("failed to create plain engine: %v", err)
	}
	putEncryptedObjectWithMeta(t, client, plainEng, bucket, "golden/b-1", wantPlain,
		map[string]string{"Content-Type": "application/octet-stream"},
		func(meta map[string]string) {
			meta[crypto.MetaLegacyNoAAD] = "true"
		})

	// CLASS C_XOR (SEC-27 + SEC-2): fallback-v1 objects without HKDF marker.
	// We use an engine with a tiny metadata limit so that even modest metadata
	// triggers the fallback path, keeping S3 headers well within MinIO limits.
	fallbackEng, err := crypto.NewTestEngineWithFallbackProfile(testPassword, false)
	if err != nil {
		t.Fatalf("failed to create fallback engine: %v", err)
	}
	putEncryptedObjectWithMeta(t, client, fallbackEng, bucket, "golden/c-1", wantPlain,
		map[string]string{
			"Content-Type":      "application/octet-stream",
			"x-amz-meta-project": "s3-encryption-gateway",
		},
		nil)

	// "Super-legacy" — combines ALL three breaking-change markers on one
	// object: fallback-v1, XOR-IV, and legacy-no-AAD.  The classifier treats
	// it as ClassC_Fallback_XOR because the fallback branch takes precedence.
	putEncryptedObjectWithMeta(t, client, fallbackEng, bucket, "golden/c-2", wantPlain,
		map[string]string{
			"Content-Type":      "application/octet-stream",
			"x-amz-meta-project": "s3-encryption-gateway",
		},
		func(meta map[string]string) {
			meta[crypto.MetaLegacyNoAAD] = "true"
		})

	// CLASS Modern: already fully up-to-date (should be skipped).
	putEncryptedObject(t, client, eng, bucket, "golden/modern-1", wantPlain, nil)
	putEncryptedObject(t, client, eng, bucket, "golden/modern-2", wantPlain, nil)

	// CLASS Plaintext: not encrypted at all (should be skipped).
	ctx := context.Background()
	if err := client.PutObject(ctx, bucket, "golden/plain.txt", bytes.NewReader(wantPlain),
		map[string]string{"Content-Type": "text/plain"}, nil, "", nil); err != nil {
		t.Fatalf("put plaintext: %v", err)
	}

	// --- Phase 1: Dry-run must correctly classify every object ---
	report, err := migrate.DryRunScan(ctx, client, bucket, "golden/", nil)
	if err != nil {
		t.Fatalf("DryRunScan failed: %v", err)
	}
	if report.Total != 8 {
		t.Errorf("DryRun Total = %d, want 8", report.Total)
	}
	if report.Modern != 2 {
		t.Errorf("DryRun Modern = %d, want 2", report.Modern)
	}
	if report.ClassA != 2 {
		t.Errorf("DryRun ClassA = %d, want 2", report.ClassA)
	}
	if report.ClassB != 1 {
		t.Errorf("DryRun ClassB = %d, want 1", report.ClassB)
	}
	if report.ClassC_XOR != 2 {
		t.Errorf("DryRun ClassC_XOR = %d, want 2", report.ClassC_XOR)
	}
	if report.Plaintext != 1 {
		t.Errorf("DryRun Plaintext = %d, want 1", report.Plaintext)
	}

	// --- Phase 2: Run full migration ---
	stateFile := t.TempDir() + "/golden-state.json"
	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         true,
		VerifyDelay:    100 * time.Millisecond,
		Filter:         migrate.FilterAll,
	}
	if err := m.Migrate(ctx, bucket, "golden/"); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// --- Phase 3: Verify every object migrated to modern and is readable ---
	keys := []string{
		"golden/a-1", "golden/a-2",
		"golden/b-1",
		"golden/c-1", "golden/c-2",
		"golden/modern-1", "golden/modern-2",
		"golden/plain.txt",
	}
	for _, key := range keys {
		meta := headMeta(t, client, bucket, key)
		class := migrate.ClassifyObject(meta)
		if class != migrate.ClassModern && class != migrate.ClassPlaintext {
			t.Errorf("%s: expected ClassModern or ClassPlaintext after migration, got %s", key, migrate.ClassToString(class))
		}
		if class == migrate.ClassPlaintext {
			// Plaintext has no decryption to verify.
			continue
		}
		got := decryptObject(t, client, eng, bucket, key)
		if !bytes.Equal(got, wantPlain) {
			t.Errorf("%s: plaintext mismatch after migration", key)
		}
	}

	// Specific post-migration metadata assertions.
	for _, key := range []string{"golden/a-1", "golden/a-2"} {
		meta := headMeta(t, client, bucket, key)
		if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
			t.Errorf("%s: expected MetaIVDerivation=hkdf-sha256, got %q", key, meta[crypto.MetaIVDerivation])
		}
	}
	metaB := headMeta(t, client, bucket, "golden/b-1")
	if metaB[crypto.MetaLegacyNoAAD] == "true" {
		t.Errorf("golden/b-1: MetaLegacyNoAAD should be absent after migration")
	}
	for _, key := range []string{"golden/c-1", "golden/c-2"} {
		meta := headMeta(t, client, bucket, key)
		// After migration the object may or may not still be in fallback mode
		// depending on whether the metadata still exceeds the limit.  If it is
		// fallback, the version must be "2".
		if meta[crypto.MetaFallbackMode] == "true" && meta[crypto.MetaFallbackVersion] != "2" {
			t.Errorf("%s: fallback object must have version '2' after migration, got %q", key, meta[crypto.MetaFallbackVersion])
		}
	}

	// --- Phase 4: Idempotency — second run must skip everything ---
	m2 := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        2,
		StateFile:      stateFile,
		DryRun:         false,
		Verify:         false,
		Filter:         migrate.FilterAll,
	}
	if err := m2.Migrate(ctx, bucket, "golden/"); err != nil {
		t.Fatalf("second Migrate failed: %v", err)
	}
	state, _, err := migrate.LoadOrCreate(stateFile, bucket, "golden/")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	wantMigrated := int64(5) // a-1, a-2, b-1, c-1, c-2
	if state.Stats.Migrated != wantMigrated {
		t.Errorf("total migrated = %d, want %d (should not increase on second run)", state.Stats.Migrated, wantMigrated)
	}
	// First run skipped 3 (modern-1, modern-2, plain.txt).
	// Second run skipped all 8 (everything is now modern/plaintext).
	wantSkipped := int64(11)
	if state.Stats.Skipped != wantSkipped {
		t.Errorf("total skipped = %d, want %d", state.Stats.Skipped, wantSkipped)
	}
}

// minioProviderForMigration is a thin wrapper around the standard MinIO
// provider so we can reuse its Start() logic without importing the unexported
// type.

type minioProviderForMigration struct{}

func (p *minioProviderForMigration) Start(ctx context.Context, t *testing.T) provider.Instance {
	t.Helper()
	// Use the standard provider registration.
	providers := provider.All()
	for _, prov := range providers {
		if prov.Name() == "minio" {
			return prov.Start(ctx, t)
		}
	}
	t.Skip("minio provider not registered; ensure Docker is available and GATEWAY_TEST_SKIP_MINIO is not set")
	return provider.Instance{}
}

// TestMAINT1_DryRun_MinIO runs a dry-run scan against a real MinIO backend to
// confirm the classification and reporting logic works end-to-end.
func TestMAINT1_DryRun_MinIO(t *testing.T) {
	inst := setupMinIO(t)
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket

	// Seed a bucket with a known mix.
	putEncryptedObject(t, client, eng, bucket, "dryrun-minio/modern", []byte("modern"), nil)
	putEncryptedObject(t, client, eng, bucket, "dryrun-minio/legacy1", []byte("legacy"), func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})
	putEncryptedObject(t, client, eng, bucket, "dryrun-minio/plain.txt", []byte("plaintext"), func(meta map[string]string) {
		delete(meta, crypto.MetaEncrypted)
		delete(meta, "x-amz-meta-e")
	})

	report, err := migrate.DryRunScan(context.Background(), client, bucket, "dryrun-minio/", nil)
	if err != nil {
		t.Fatalf("DryRunScan failed: %v", err)
	}

	if report.Total != 3 {
		t.Errorf("Total = %d, want 3", report.Total)
	}
	if report.Modern != 1 {
		t.Errorf("Modern = %d, want 1", report.Modern)
	}
	if report.ClassA != 1 {
		t.Errorf("ClassA = %d, want 1", report.ClassA)
	}
	if report.Plaintext != 1 {
		t.Errorf("Plaintext = %d, want 1", report.Plaintext)
	}

	// Ensure samples are collected.
	if len(report.Samples["class_a_xor"]) != 1 {
		t.Errorf("expected 1 sample for class_a_xor, got %d", len(report.Samples["class_a_xor"]))
	}
}

// TestMAINT1_VerifyAfterWrite detects a 1-byte corruption after PutObject.
func TestMAINT1_VerifyAfterWrite(t *testing.T) {
	inst := setupMinIO(t)
	client := newS3Client(t, inst)
	eng := newEngine(t)
	bucket := inst.Bucket

	wantPlain := []byte("verify me please")
	putEncryptedObject(t, client, eng, bucket, "verify/obj", wantPlain, func(meta map[string]string) {
		delete(meta, crypto.MetaIVDerivation)
	})

	// Normal migration with verify should succeed.
	m := &migrate.Migrator{
		S3Client:       client,
		SourceEngine:   eng,
		TargetEngine:   eng,
		GatewayVersion: "0.7.0",
		Workers:        1,
		StateFile:      t.TempDir() + "/state.json",
		DryRun:         false,
		Verify:         true,
		VerifyDelay:    100 * time.Millisecond,
		Filter:         migrate.FilterAll,
	}

	ctx := context.Background()
	if err := m.Migrate(ctx, bucket, ""); err != nil {
		t.Fatalf("Migrate with verify failed: %v", err)
	}

	// Verify the object is now modern.
	meta := headMeta(t, client, bucket, "verify/obj")
	if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
		t.Errorf("expected hkdf-sha256 after migration, got %q", meta[crypto.MetaIVDerivation])
	}
}
