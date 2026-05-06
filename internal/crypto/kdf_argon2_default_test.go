//go:build !fips

package crypto

import (
	"errors"
	"testing"
)

func TestArgon2id_ReturnsNotEnabled(t *testing.T) {
	params := KDFParams{Algorithm: KDFAlgArgon2id, Time: 2, Memory: 19456, Threads: 1}
	_, err := deriveKeyArgon2id(make([]byte, saltSize), params)
	if err == nil {
		t.Fatal("expected error from deriveKeyArgon2id")
	}
	if !errors.Is(err, ErrArgon2NotEnabled) {
		t.Errorf("expected ErrArgon2NotEnabled, got %v", err)
	}
}

func TestArgon2id_ErrSentinelIsDistinct(t *testing.T) {
	if ErrArgon2NotEnabled == ErrAlgorithmNotApproved {
		t.Error("ErrArgon2NotEnabled must be distinct from ErrAlgorithmNotApproved")
	}
}
