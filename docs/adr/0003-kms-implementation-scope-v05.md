# ADR-0003: KMS Implementation Scope for v0.5

**Status**: Accepted  
**Date**: 2024  
**Deciders**: Development Team  
**Tags**: `kms`, `v0.5`, `architecture`, `decision`

## Context

The V0.5-KMS-1 task requires implementing external KMS integrations with AWS KMS and HashiCorp Vault Transit adapters. However, during implementation, we encountered practical constraints:

1. **AWS KMS**: Requires cloud provider access and AWS account setup for proper testing and validation. This creates barriers for:
   - Local development and testing
   - CI/CD pipeline setup (requires AWS credentials)
   - Open-source contributors without AWS access

2. **HashiCorp Vault Transit**: Requires Vault Enterprise license for the Transit engine, which is not available for:
   - Open-source development
   - Local testing without Enterprise license
   - CI/CD pipelines

3. **Cosmian KMIP**: Available as open-source with Docker-based testing, making it suitable for:
   - Local development
   - CI/CD integration
   - Open-source contribution
   - Full test coverage

## Decision

We will implement **only Cosmian KMIP** in v0.5, with the following approach:

1. **Complete the KeyManager interface** - This provides the foundation for all future KMS adapters
2. **Implement Cosmian KMIP adapter** - Fully functional with envelope encryption and dual-read window
3. **Defer AWS KMS and Vault Transit to v1.0** - These will be implemented when:
   - AWS KMS: Cloud provider access can be properly configured for testing
   - Vault Transit: Enterprise license is available or alternative testing approach is found

## Consequences

### Positive

- ✅ **Deliverable v0.5 milestone**: Core KMS functionality is complete with a working implementation
- ✅ **Testable**: Cosmian KMIP can be fully tested with Docker, enabling CI/CD integration
- ✅ **Open-source friendly**: No licensing or cloud provider barriers for contributors
- ✅ **Foundation established**: KeyManager interface enables future adapters
- ✅ **Production-ready for Cosmian users**: Users with Cosmian KMS can use the feature immediately

### Negative

- ⚠️ **Incomplete task scope**: V0.5-KMS-1 originally called for AWS KMS and Vault Transit
- ⚠️ **Limited provider support**: Only one KMS provider available in v0.5
- ⚠️ **Future work required**: AWS KMS and Vault Transit must be implemented in v1.0

### Mitigation

- **Clear documentation**: Updated `docs/KMS_COMPATIBILITY.md` to clearly state current support
- **Task tracking**: Moved AWS KMS and Vault Transit to v1.0 issues (V1.0-KMS-2, V1.0-KMS-3)
- **Interface design**: KeyManager interface is designed to easily accommodate future adapters
- **Code comments**: Added comments in code noting future KMS support

## Implementation Details

### Completed in v0.5

- ✅ KeyManager interface definition (`internal/crypto/keymanager.go`)
- ✅ Cosmian KMIP adapter (`internal/crypto/keymanager_cosmian.go`, `keymanager_cosmian_json.go`)
- ✅ Envelope encryption integration (`internal/crypto/engine.go`)
- ✅ Dual-read window for key rotation
- ✅ Configuration support (`internal/config/config.go`)
- ✅ Comprehensive tests (unit and integration)

### Deferred to v1.0

- 🔜 AWS KMS adapter (V1.0-KMS-2)
- 🔜 Vault Transit adapter (V1.0-KMS-3)
- 🔜 Health check endpoints for all KMS adapters (V1.0-KMS-1)

## References

- [V0.5-KMS-1](../issues/v0.5-issues.md#v05-kms-1-external-kms-integrations)
- [V1.0-KMS-2](../issues/v1.0-issues.md#v10-kms-2-aws-kms-adapter)
- [V1.0-KMS-3](../issues/v1.0-issues.md#v10-kms-3-hashicorp-vault-transit-adapter)
- [KMS Compatibility Guide](../KMS_COMPATIBILITY.md)

## Notes

This decision aligns with the project's pragmatic approach to delivering working software while maintaining quality and testability. The KeyManager interface design ensures that adding AWS KMS and Vault Transit in v1.0 will be straightforward and won't require breaking changes.

