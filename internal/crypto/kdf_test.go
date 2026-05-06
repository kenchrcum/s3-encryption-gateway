package crypto

import (
	"fmt"
	"testing"
)

func TestFormatKDFParams_PBKDF2(t *testing.T) {
	p := KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: 100000}
	got := FormatKDFParams(p)
	want := "pbkdf2-sha256:100000"
	if got != want {
		t.Errorf("FormatKDFParams() = %q, want %q", got, want)
	}
}

func TestFormatKDFParams_600k(t *testing.T) {
	p := KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: 600000}
	got := FormatKDFParams(p)
	want := "pbkdf2-sha256:600000"
	if got != want {
		t.Errorf("FormatKDFParams() = %q, want %q", got, want)
	}
}

func TestParseKDFParams_Empty(t *testing.T) {
	p, err := ParseKDFParams("")
	if err != nil {
		t.Fatalf("ParseKDFParams(\"\") unexpected error: %v", err)
	}
	if p.Algorithm != KDFAlgPBKDF2SHA256 {
		t.Errorf("Algorithm = %q, want %q", p.Algorithm, KDFAlgPBKDF2SHA256)
	}
	if p.Iterations != 100000 {
		t.Errorf("Iterations = %d, want %d", p.Iterations, 100000)
	}
}

func TestParseKDFParams_100k(t *testing.T) {
	raw := "pbkdf2-sha256:100000"
	p, err := ParseKDFParams(raw)
	if err != nil {
		t.Fatalf("ParseKDFParams(%q) unexpected error: %v", raw, err)
	}
	if p.Algorithm != KDFAlgPBKDF2SHA256 {
		t.Errorf("Algorithm = %q, want %q", p.Algorithm, KDFAlgPBKDF2SHA256)
	}
	if p.Iterations != 100000 {
		t.Errorf("Iterations = %d, want %d", p.Iterations, 100000)
	}
	// Round-trip
	got := FormatKDFParams(p)
	if got != raw {
		t.Errorf("round-trip: FormatKDFParams() = %q, want %q", got, raw)
	}
}

func TestParseKDFParams_600k(t *testing.T) {
	raw := "pbkdf2-sha256:600000"
	p, err := ParseKDFParams(raw)
	if err != nil {
		t.Fatalf("ParseKDFParams(%q) unexpected error: %v", raw, err)
	}
	if p.Algorithm != KDFAlgPBKDF2SHA256 {
		t.Errorf("Algorithm = %q, want %q", p.Algorithm, KDFAlgPBKDF2SHA256)
	}
	if p.Iterations != 600000 {
		t.Errorf("Iterations = %d, want %d", p.Iterations, 600000)
	}
	got := FormatKDFParams(p)
	if got != raw {
		t.Errorf("round-trip: FormatKDFParams() = %q, want %q", got, raw)
	}
}

func TestParseKDFParams_ArbitraryValue(t *testing.T) {
	raw := "pbkdf2-sha256:750000"
	p, err := ParseKDFParams(raw)
	if err != nil {
		t.Fatalf("ParseKDFParams(%q) unexpected error: %v", raw, err)
	}
	if p.Algorithm != KDFAlgPBKDF2SHA256 {
		t.Errorf("Algorithm = %q, want %q", p.Algorithm, KDFAlgPBKDF2SHA256)
	}
	if p.Iterations != 750000 {
		t.Errorf("Iterations = %d, want %d", p.Iterations, 750000)
	}
	got := FormatKDFParams(p)
	if got != raw {
		t.Errorf("round-trip: FormatKDFParams() = %q, want %q", got, raw)
	}
}

func TestParseKDFParams_Invalid_NoColon(t *testing.T) {
	_, err := ParseKDFParams("pbkdf2-sha256")
	if err == nil {
		t.Fatal("expected error for missing colon")
	}
}

func TestParseKDFParams_Invalid_NegativeIter(t *testing.T) {
	_, err := ParseKDFParams("pbkdf2-sha256:-1")
	if err == nil {
		t.Fatal("expected error for negative iterations")
	}
}

func TestParseKDFParams_Invalid_ZeroIter(t *testing.T) {
	_, err := ParseKDFParams("pbkdf2-sha256:0")
	if err == nil {
		t.Fatal("expected error for zero iterations")
	}
}

func TestParseKDFParams_Invalid_UnknownAlg(t *testing.T) {
	_, err := ParseKDFParams("sha3:100000")
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

func TestParseKDFParams_Argon2id_WellFormed(t *testing.T) {
	raw := "argon2id:2:19456:1"
	p, err := ParseKDFParams(raw)
	if err != nil {
		t.Fatalf("ParseKDFParams(%q) unexpected error: %v", raw, err)
	}
	if p.Algorithm != KDFAlgArgon2id {
		t.Errorf("Algorithm = %q, want %q", p.Algorithm, KDFAlgArgon2id)
	}
	if p.Time != 2 {
		t.Errorf("Time = %d, want %d", p.Time, 2)
	}
	if p.Memory != 19456 {
		t.Errorf("Memory = %d, want %d", p.Memory, 19456)
	}
	if p.Threads != 1 {
		t.Errorf("Threads = %d, want %d", p.Threads, 1)
	}
}

func TestParseKDFParams_Argon2id_MissingFields(t *testing.T) {
	_, err := ParseKDFParams("argon2id:2")
	if err == nil {
		t.Fatal("expected error for missing fields")
	}
}

func TestParseKDFParams_Argon2id_ZeroMemory(t *testing.T) {
	_, err := ParseKDFParams("argon2id:2:0:1")
	if err == nil {
		t.Fatal("expected error for zero memory")
	}
}

func TestRoundTrip_PBKDF2_Various(t *testing.T) {
	tests := []int{100000, 200000, 600000, 1200000}
	for _, iterations := range tests {
		t.Run(fmt.Sprintf("%d", iterations), func(t *testing.T) {
			p := KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: iterations}
			raw := FormatKDFParams(p)
			got, err := ParseKDFParams(raw)
			if err != nil {
				t.Fatalf("ParseKDFParams(%q) error: %v", raw, err)
			}
			if got != p {
				t.Errorf("round-trip mismatch: got %+v, want %+v", got, p)
			}
		})
	}
}
