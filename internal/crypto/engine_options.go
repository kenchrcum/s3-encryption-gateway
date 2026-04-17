package crypto

// Option is a functional option for configuring an engine at construction time.
// This pattern replaces the out-of-band SetKeyManager / SetKeyResolver mutators
// for new callers (see [NewEngineWithOpts]).
type Option func(*engine)

// WithKeyManager sets the KeyManager that will be used for envelope encryption.
// The provided KeyManager must not be nil. If nil is passed, the option is a no-op.
//
// Using this option is the preferred alternative to the deprecated [SetKeyManager].
func WithKeyManager(km KeyManager) Option {
	return func(e *engine) {
		if km != nil {
			e.kmsManager = km
		}
	}
}

// WithKeyResolver sets a key resolver used during decryption of objects that
// were encrypted with an older password (pbkdf2 mode only).
//
// Using this option is the preferred alternative to the deprecated [SetKeyResolver].
func WithKeyResolver(resolver func(version int) (string, bool)) Option {
	return func(e *engine) {
		if resolver != nil {
			e.keyResolver = resolver
		}
	}
}

// NewEngineWithOpts creates a new encryption engine with full options and zero or
// more functional Option values. This is the preferred constructor for new callers.
//
// Example:
//
//	eng, err := crypto.NewEngineWithOpts(password, nil,
//	    crypto.WithKeyManager(myKeyManager),
//	)
func NewEngineWithOpts(password string, compressionEngine CompressionEngine, opts ...Option) (EncryptionEngine, error) {
	eng, err := NewEngineWithChunkingAndProvider(password, compressionEngine, "", nil, false, DefaultChunkSize, "default")
	if err != nil {
		return nil, err
	}
	e := eng.(*engine)
	for _, o := range opts {
		o(e)
	}
	return e, nil
}
