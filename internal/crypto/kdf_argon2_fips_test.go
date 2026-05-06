//go:build fips

package crypto

import (
	"errors"
	"testing"
)

func TestArgon2id_Rejected_InFIPSBuild(t *testing.T) {
	params := KDFParams{Algorithm: KDFAlgArgon2id, Time: 2, Memory: 19456, Threads: 1}
	_, err := deriveKeyArgon2id(make([]byte, saltSize), params)
	if err == nil {
		t.Fatal("expected error from deriveKeyArgon2id in FIPS build")
	}
	if !errors.Is(err, ErrAlgorithmNotApproved) {
		t.Errorf("expected ErrAlgorithmNotApproved, got %v", err)
	}
}

func TestArgon2id_ParsedButNotDerived(t *testing.T) {
	params, err := ParseKDFParams("argon2id:2:19456:1")
	if err != nil {
		t.Fatalf("unexpected error parsing argon2id params: %v", err)
	}
	if params.Algorithm != KDFAlgArgon2id {
		t.Errorf("expected algorithm %q, got %q", KDFAlgArgon2id, params.Algorithm)
	}

	_, err = deriveKeyArgon2id(make([]byte, saltSize), params)
	if err == nil {
		t.Fatal("expected error from deriveKeyArgon2id in FIPS build")
	}
	if !errors.Is(err, ErrAlgorithmNotApproved) {
		t.Errorf("expected ErrAlgorithmNotApproved, got %v", err)
	}
}
