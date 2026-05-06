package crypto

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// KDFAlgorithm identifies the key derivation function.
type KDFAlgorithm string

const (
	KDFAlgPBKDF2SHA256 KDFAlgorithm = "pbkdf2-sha256"
	KDFAlgArgon2id     KDFAlgorithm = "argon2id" // non-FIPS only

	// Legacy sentinel: returned when MetaKDFParams is absent.
	// Treated as pbkdf2-sha256 with LegacyPBKDF2Iterations.
	LegacyPBKDF2Iterations  = 100000
	DefaultPBKDF2Iterations = 600000
	MinPBKDF2Iterations     = 100000
	// MaxPBKDF2Iterations is a hard upper bound used by envelope format
	// detection in PasswordKeyManager.UnwrapKey.  It prevents a mistaken
	// new-format attempt on an old-format envelope (whose first 4 bytes
	// are random salt) from hanging on a multi-billion-iteration PBKDF2
	// derivation.  2,000,000 is well above any sensible production value
	// while keeping a mistaken attempt under ~10 s even with -race.
	MaxPBKDF2Iterations = 2000000
)

// KDFParams holds the parsed parameters for a KDF stored in MetaKDFParams.
type KDFParams struct {
	Algorithm KDFAlgorithm
	// PBKDF2 fields
	Iterations int
	// argon2id fields (zero when not argon2id)
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// FormatKDFParams serialises KDFParams to the MetaKDFParams wire format.
func FormatKDFParams(p KDFParams) string {
	switch p.Algorithm {
	case KDFAlgPBKDF2SHA256:
		return fmt.Sprintf("%s:%d", KDFAlgPBKDF2SHA256, p.Iterations)
	case KDFAlgArgon2id:
		return fmt.Sprintf("%s:%d:%d:%d", KDFAlgArgon2id, p.Time, p.Memory, p.Threads)
	default:
		return ""
	}
}

// ParseKDFParams parses a MetaKDFParams value.
// Returns the LegacyPBKDF2Iterations PBKDF2 params when value is empty (absent).
func ParseKDFParams(value string) (KDFParams, error) {
	if value == "" {
		return KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: LegacyPBKDF2Iterations}, nil
	}

	parts := strings.Split(value, ":")
	if len(parts) < 2 {
		return KDFParams{}, errors.New("kdf params: invalid format, expected at least algorithm:parameter")
	}

	alg := KDFAlgorithm(parts[0])
	switch alg {
	case KDFAlgPBKDF2SHA256:
		if len(parts) != 2 {
			return KDFParams{}, fmt.Errorf("kdf params: pbkdf2-sha256 expects 2 colon-delimited parts, got %d", len(parts))
		}
		iter, err := strconv.Atoi(parts[1])
		if err != nil {
			return KDFParams{}, fmt.Errorf("kdf params: invalid iteration count: %w", err)
		}
		if iter < MinPBKDF2Iterations {
			return KDFParams{}, fmt.Errorf("kdf params: iteration count %d is below minimum %d", iter, MinPBKDF2Iterations)
		}
		return KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: iter}, nil
	case KDFAlgArgon2id:
		if len(parts) != 4 {
			return KDFParams{}, fmt.Errorf("kdf params: argon2id expects 4 colon-delimited parts, got %d", len(parts))
		}
		time, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return KDFParams{}, fmt.Errorf("kdf params: invalid argon2id time: %w", err)
		}
		memory, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			return KDFParams{}, fmt.Errorf("kdf params: invalid argon2id memory: %w", err)
		}
		if memory == 0 {
			return KDFParams{}, errors.New("kdf params: argon2id memory must be > 0")
		}
		threads, err := strconv.ParseUint(parts[3], 10, 8)
		if err != nil {
			return KDFParams{}, fmt.Errorf("kdf params: invalid argon2id threads: %w", err)
		}
		return KDFParams{
			Algorithm: KDFAlgArgon2id,
			Time:      uint32(time),
			Memory:    uint32(memory),
			Threads:   uint8(threads),
		}, nil
	default:
		return KDFParams{}, fmt.Errorf("kdf params: unsupported algorithm %q", alg)
	}
}

// DefaultKDFParams returns the KDFParams for newly-written objects
// using the configured iteration count.
func DefaultKDFParams(pbkdf2Iterations int) KDFParams {
	if pbkdf2Iterations < MinPBKDF2Iterations {
		pbkdf2Iterations = DefaultPBKDF2Iterations
	}
	return KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: pbkdf2Iterations}
}
