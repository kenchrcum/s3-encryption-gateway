package crypto

import (
	"testing"
)

func TestEncodeDecodeBase64(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "simple data",
			data: []byte("Hello, World!"),
		},
		{
			name: "binary data",
			data: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
		{
			name: "salt size",
			data: make([]byte, saltSize),
		},
		{
			name: "nonce size",
			data: make([]byte, nonceSize),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeBase64(tt.data)
			decoded, err := decodeBase64(encoded)
			if err != nil {
				t.Fatalf("decodeBase64() error: %v", err)
			}

			if len(decoded) != len(tt.data) {
				t.Errorf("decodeBase64() length mismatch: got %d, want %d", len(decoded), len(tt.data))
			}

			for i := range tt.data {
				if decoded[i] != tt.data[i] {
					t.Errorf("decodeBase64() data mismatch at index %d: got %x, want %x", i, decoded[i], tt.data[i])
					break
				}
			}
		})
	}
}

func TestDecodeBase64_Invalid(t *testing.T) {
	invalidStrings := []string{
		"not base64!",
		"invalid-base64",
		"@#$%^&*()",
	}

	for _, s := range invalidStrings {
		t.Run(s, func(t *testing.T) {
			_, err := decodeBase64(s)
			if err == nil {
				t.Errorf("decodeBase64() expected error for invalid string: %s", s)
			}
		})
	}
}
