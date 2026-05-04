#!/usr/bin/env python3
"""
generate-config-from-helmrelease.py

Generate a gateway config.yaml from a FluxCD HelmRelease (or helm values) YAML.

This script extracts the gateway configuration nested under `spec.values.config`
(HelmRelease) or top-level `config` (plain values file) and flattens it into
the native `config.yaml` format expected by the server and by `s3eg-migrate`.

Fields that use `valueFrom` (Secret/ConfigMap references) are emitted as
comments by default.  Use `--resolve-secrets --namespace <ns>` to fetch
secret values via kubectl when running locally with cluster access.

Usage:
    # From a HelmRelease manifest
    python3 scripts/generate-config-from-helmrelease.py helmrelease.yaml > config.yaml

    # Resolve Secret references via kubectl
    python3 scripts/generate-config-from-helmrelease.py helmrelease.yaml \
        --resolve-secrets --namespace s3-encryption-gateway > config.yaml

    # From a plain Helm values file (no spec.values wrapper)
    python3 scripts/generate-config-from-helmrelease.py values.yaml \
        --plain-values > config.yaml
"""

import argparse
import base64
import json
import subprocess
import sys
import textwrap
from typing import Any, Dict, Optional

try:
    import yaml
except ImportError:
    print("error: PyYAML is required.  pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Mapping: Helm values path (dotted, WITHOUT .value/.valueFrom suffix)
#          -> config.yaml key path (dotted)
# ---------------------------------------------------------------------------
# HelmRelease values place every scalar under `config.<section>.<key>` as a
# dict with either a `.value` string or `.valueFrom` ref.
#
# This table maps the *parent* dotted paths to the native YAML key used by
# internal/config/config.go.
# ---------------------------------------------------------------------------
CONFIG_MAP: Dict[str, str] = {
    "config.listenAddr": "listen_addr",
    "config.logLevel": "log_level",
    "config.proxiedBucket": "proxied_bucket",
    "config.policies": "policies",
    "config.backend.endpoint": "backend.endpoint",
    "config.backend.region": "backend.region",
    "config.backend.accessKey": "backend.access_key",
    "config.backend.secretKey": "backend.secret_key",
    "config.backend.provider": "backend.provider",
    "config.backend.useSSL": "backend.use_ssl",
    "config.backend.usePathStyle": "backend.use_path_style",
    "config.backend.useClientCredentials": "backend.use_client_credentials",
    "config.backend.filterMetadataKeys": "backend.filter_metadata_keys",
    "config.encryption.password": "encryption.password",
    "config.encryption.keyFile": "encryption.key_file",
    "config.encryption.preferredAlgorithm": "encryption.preferred_algorithm",
    "config.encryption.supportedAlgorithms": "encryption.supported_algorithms",
    "config.encryption.chunkedMode": "encryption.chunked_mode",
    "config.encryption.chunkSize": "encryption.chunk_size",
    "config.encryption.hardware.enableAESNI": "encryption.hardware.enable_aesni",
    "config.encryption.hardware.enableARMv8AES": "encryption.hardware.enable_armv8_aes",
    "config.encryption.keyManager.enabled": "encryption.key_manager.enabled",
    "config.encryption.keyManager.provider": "encryption.key_manager.provider",
    "config.encryption.keyManager.dualReadWindow": "encryption.key_manager.dual_read_window",
    "config.encryption.keyManager.memory.masterKeySource": "encryption.key_manager.memory.master_key_source",
    "config.encryption.keyManager.rotationPolicy.enabled": "encryption.key_manager.rotation_policy.enabled",
    "config.encryption.keyManager.rotationPolicy.graceWindow": "encryption.key_manager.rotation_policy.grace_window",
    "config.encryption.keyManager.cosmian.endpoint": "encryption.key_manager.cosmian.endpoint",
    "config.encryption.keyManager.cosmian.timeout": "encryption.key_manager.cosmian.timeout",
    "config.encryption.keyManager.cosmian.keys": "encryption.key_manager.cosmian.keys",
    "config.encryption.keyManager.cosmian.caCert": "encryption.key_manager.cosmian.ca_cert",
    "config.encryption.keyManager.cosmian.clientCert": "encryption.key_manager.cosmian.client_cert",
    "config.encryption.keyManager.cosmian.clientKey": "encryption.key_manager.cosmian.client_key",
    "config.encryption.keyManager.cosmian.insecureSkipVerify": "encryption.key_manager.cosmian.insecure_skip_verify",
    "config.compression.enabled": "compression.enabled",
    "config.compression.minSize": "compression.min_size",
    "config.compression.contentTypes": "compression.content_types",
    "config.compression.algorithm": "compression.algorithm",
    "config.compression.level": "compression.level",
    "config.server.readTimeout": "server.read_timeout",
    "config.server.writeTimeout": "server.write_timeout",
    "config.server.idleTimeout": "server.idle_timeout",
    "config.server.readHeaderTimeout": "server.read_header_timeout",
    "config.server.maxHeaderBytes": "server.max_header_bytes",
    "config.server.trustedProxies": "server.trusted_proxies",
    "config.server.disableMultipartUploads": "server.disable_multipart_uploads",
    "config.server.maxLegacyCopySourceBytes": "server.max_legacy_copy_source_bytes",
    "config.server.maxPartBuffer": "server.max_part_buffer",
    "config.tls.enabled": "tls.enabled",
    "config.tls.certFile": "tls.cert_file",
    "config.tls.keyFile": "tls.key_file",
    "config.rateLimit.enabled": "rate_limit.enabled",
    "config.rateLimit.limit": "rate_limit.limit",
    "config.rateLimit.window": "rate_limit.window",
    "config.cache.enabled": "cache.enabled",
    "config.cache.maxSize": "cache.max_size",
    "config.cache.maxItems": "cache.max_items",
    "config.cache.defaultTTL": "cache.default_ttl",
    "config.audit.enabled": "audit.enabled",
    "config.audit.maxEvents": "audit.max_events",
    "config.audit.redactMetadataKeys": "audit.redact_metadata_keys",
    "config.audit.sink.type": "audit.sink.type",
    "config.audit.sink.endpoint": "audit.sink.endpoint",
    "config.audit.sink.filePath": "audit.sink.file_path",
    "config.audit.sink.fileMode": "audit.sink.file_mode",
    "config.audit.sink.batchSize": "audit.sink.batch_size",
    "config.audit.sink.flushInterval": "audit.sink.flush_interval",
    "config.audit.sink.retryCount": "audit.sink.retry_count",
    "config.audit.sink.retryBackoff": "audit.sink.retry_backoff",
    "config.multipartState.valkey.addr": "multipart_state.valkey.addr",
    "config.multipartState.valkey.username": "multipart_state.valkey.username",
    "config.multipartState.valkey.passwordEnv": "multipart_state.valkey.password_env",
    "config.multipartState.valkey.db": "multipart_state.valkey.db",
    "config.multipartState.valkey.tls.enabled": "multipart_state.valkey.tls.enabled",
    "config.multipartState.valkey.tls.caFile": "multipart_state.valkey.tls.ca_file",
    "config.multipartState.valkey.tls.certFile": "multipart_state.valkey.tls.cert_file",
    "config.multipartState.valkey.tls.keyFile": "multipart_state.valkey.tls.key_file",
    "config.multipartState.valkey.tls.insecureSkipVerify": "multipart_state.valkey.tls.insecure_skip_verify",
    "config.multipartState.valkey.tls.minVersion": "multipart_state.valkey.tls.min_version",
    "config.multipartState.valkey.insecureAllowPlaintext": "multipart_state.valkey.insecure_allow_plaintext",
    "config.multipartState.valkey.ttlSeconds": "multipart_state.valkey.ttl_seconds",
    "config.multipartState.valkey.dialTimeout": "multipart_state.valkey.dial_timeout",
    "config.multipartState.valkey.readTimeout": "multipart_state.valkey.read_timeout",
    "config.multipartState.valkey.writeTimeout": "multipart_state.valkey.write_timeout",
    "config.multipartState.valkey.poolSize": "multipart_state.valkey.pool_size",
    "config.multipartState.valkey.minIdleConns": "multipart_state.valkey.min_idle_conns",
    "config.tracing.enabled": "tracing.enabled",
    "config.tracing.serviceName": "tracing.service_name",
    "config.tracing.serviceVersion": "tracing.service_version",
    "config.tracing.exporter": "tracing.exporter",
    "config.tracing.jaegerEndpoint": "tracing.jaeger_endpoint",
    "config.tracing.otlpEndpoint": "tracing.otlp_endpoint",
    "config.tracing.samplingRatio": "tracing.sampling_ratio",
    "config.tracing.redactSensitive": "tracing.redact_sensitive",
    "config.metrics.enableBucketLabel": "metrics.enable_bucket_label",
    "config.logging.accessLogFormat": "logging.access_log_format",
    "config.logging.redactHeaders": "logging.redact_headers",
    "config.auth.clockSkewTolerance": "auth.clock_skew_tolerance",
    "config.admin.enabled": "admin.enabled",
    "config.admin.address": "admin.address",
    "config.admin.maxHeaderBytes": "admin.max_header_bytes",
    "config.admin.tls.enabled": "admin.tls.enabled",
    "config.admin.tls.certFile": "admin.tls.cert_file",
    "config.admin.tls.keyFile": "admin.tls.key_file",
    "config.admin.auth.type": "admin.auth.type",
    "config.admin.auth.tokenFile": "admin.auth.token_file",
    "config.admin.auth.token": "admin.auth.token",
    "config.admin.rateLimit.requestsPerMinute": "admin.rate_limit.requests_per_minute",
    "config.admin.profiling.enabled": "admin.profiling.enabled",
    "config.admin.profiling.blockRate": "admin.profiling.block_rate",
    "config.admin.profiling.mutexFraction": "admin.profiling.mutex_fraction",
    "config.admin.profiling.maxConcurrentProfiles": "admin.profiling.max_concurrent_profiles",
    "config.admin.profiling.maxProfileSeconds": "admin.profiling.max_profile_seconds",
}

# Types that should be parsed as booleans or numbers rather than raw strings
BOOL_KEYS = {
    "backend.use_ssl",
    "backend.use_path_style",
    "backend.use_client_credentials",
    "encryption.chunked_mode",
    "encryption.hardware.enable_aesni",
    "encryption.hardware.enable_armv8_aes",
    "encryption.key_manager.enabled",
    "encryption.key_manager.rotation_policy.enabled",
    "encryption.key_manager.cosmian.insecure_skip_verify",
    "compression.enabled",
    "server.disable_multipart_uploads",
    "tls.enabled",
    "rate_limit.enabled",
    "cache.enabled",
    "audit.enabled",
    "multipart_state.valkey.tls.enabled",
    "multipart_state.valkey.insecure_allow_plaintext",
    "multipart_state.valkey.tls.insecure_skip_verify",
    "tracing.enabled",
    "tracing.redact_sensitive",
    "metrics.enable_bucket_label",
    "admin.enabled",
    "admin.tls.enabled",
    "admin.profiling.enabled",
}

INT_KEYS = {
    "backend.retry.max_attempts",
    "encryption.chunk_size",
    "encryption.key_manager.dual_read_window",
    "compression.level",
    "server.max_header_bytes",
    "rate_limit.limit",
    "cache.max_size",
    "cache.max_items",
    "audit.max_events",
    "audit.sink.batch_size",
    "audit.sink.retry_count",
    "multipart_state.valkey.db",
    "multipart_state.valkey.ttl_seconds",
    "multipart_state.valkey.pool_size",
    "multipart_state.valkey.min_idle_conns",
    "admin.max_header_bytes",
    "admin.rate_limit.requests_per_minute",
    "admin.profiling.block_rate",
    "admin.profiling.mutex_fraction",
    "admin.profiling.max_concurrent_profiles",
    "admin.profiling.max_profile_seconds",
}

FLOAT_KEYS = {
    "tracing.sampling_ratio",
}

# Comma-separated string fields that map to []string in Go.
# These are emitted as YAML lists (arrays) rather than scalar strings.
LIST_KEYS = {
    "backend.filter_metadata_keys",
    "encryption.supported_algorithms",
    "compression.content_types",
    "audit.redact_metadata_keys",
    "logging.redact_headers",
    "server.trusted_proxies",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(d: dict, path: str) -> Any:
    """Walk a dotted path through nested dicts."""
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _resolve_ref(ref: dict, namespace: Optional[str]) -> Optional[str]:
    """Try to resolve a valueFrom reference via kubectl."""
    if not namespace:
        return None

    kind = None
    name = None
    key = None

    if "secretKeyRef" in ref:
        kind = "secret"
        skr = ref["secretKeyRef"]
        name = skr.get("name")
        key = skr.get("key")
    elif "configMapKeyRef" in ref:
        kind = "configmap"
        cmr = ref["configMapKeyRef"]
        name = cmr.get("name")
        key = cmr.get("key")
    else:
        return None

    if not name or not key:
        return None

    cmd = [
        "kubectl", "get", kind, name,
        "-n", namespace,
        "-o", f"jsonpath={{.data['{key}']}}",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, check=False
        )
        if result.returncode != 0:
            return None
        val = result.stdout
        if kind == "secret" and val:
            try:
                val = base64.b64decode(val).decode("utf-8")
            except Exception:
                pass
        return val
    except Exception:
        return None


def _coerce(cfg_key: str, raw: str) -> Any:
    """Cast string values to the correct YAML scalar type."""
    if cfg_key in BOOL_KEYS:
        return raw.lower() in ("true", "1", "yes", "on")
    if cfg_key in INT_KEYS:
        try:
            return int(raw)
        except ValueError:
            return raw
    if cfg_key in FLOAT_KEYS:
        try:
            return float(raw)
        except ValueError:
            return raw
    if cfg_key in LIST_KEYS:
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        return parts if parts else []
    # Durations and strings pass through as-is
    return raw


def _deep_set(root: dict, dotted: str, value: Any, comment: Optional[str] = None):
    """Set a nested dict path, optionally attaching a comment key."""
    parts = dotted.split(".")
    cur = root
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value
    if comment:
        cur[f"__comment_{parts[-1]}"] = comment


def _build_config_tree(values: dict, resolve: bool, namespace: Optional[str]) -> dict:
    """Traverse the HelmRelease values and build the native config tree."""
    tree: dict = {}
    unresolved: list[tuple[str, dict]] = []

    # 1. Walk the flat mapping table (parent paths)
    for helm_path, cfg_key in CONFIG_MAP.items():
        node = _get(values, helm_path)
        if node is None:
            continue

        # Sometimes Helm values has a plain scalar instead of {value: "..."}
        # (e.g. if someone hand-edited values).  Accept it.
        if isinstance(node, str):
            _deep_set(tree, cfg_key, _coerce(cfg_key, node))
            continue

        if not isinstance(node, dict):
            continue

        if "value" in node and node["value"] != "":
            _deep_set(tree, cfg_key, _coerce(cfg_key, str(node["value"])))
        elif "valueFrom" in node:
            ref = node["valueFrom"]
            resolved = None
            if resolve:
                resolved = _resolve_ref(ref, namespace)
            if resolved is not None:
                _deep_set(tree, cfg_key, _coerce(cfg_key, resolved))
            else:
                unresolved.append((cfg_key, ref))
        elif node.get("value") == "":
            # Explicitly empty inline value — skip (use Go defaults)
            pass

    # 2. Handle top-level policies array if present
    policies = _get(values, "policies")
    if isinstance(policies, list) and policies:
        # The chart auto-mounts them and sets POLICIES env var.
        # For local use we can't replicate the ConfigMap, so emit a comment.
        _deep_set(
            tree,
            "policies",
            "/etc/s3-gateway/policies/*.yaml",
            comment=(
                "Policies are rendered as a ConfigMap by the Helm chart. "
                "For local use, copy the policy YAML files from the chart values "
                "and mount them at this path, or omit this key."
            ),
        )

    # 3. Emit comments for everything we couldn't resolve
    for cfg_key, ref in unresolved:
        ref_json = json.dumps(ref, separators=(",", ":"))
        _deep_set(
            tree,
            cfg_key,
            "",
            comment=f"Unresolved valueFrom: {ref_json}",
        )

    return tree


# ---------------------------------------------------------------------------
# YAML emission with inline comments
# ---------------------------------------------------------------------------

class CommentedEmitter:
    """Very small YAML emitter that preserves our __comment_ keys as comments."""

    def __init__(self, indent: int = 2):
        self.indent = indent

    def emit(self, obj: Any, level: int = 0) -> str:
        lines: list[str] = []
        prefix = " " * (level * self.indent)

        if isinstance(obj, dict):
            # Separate real keys from comment meta-keys
            comments = {k[10:]: v for k, v in obj.items() if isinstance(k, str) and k.startswith("__comment_")}
            real = {k: v for k, v in obj.items() if not (isinstance(k, str) and k.startswith("__comment_"))}

            for k, v in real.items():
                if isinstance(v, (dict, list)) and v:
                    if k in comments:
                        lines.append(f"{prefix}# {comments[k]}")
                    lines.append(f"{prefix}{k}:")
                    lines.append(self.emit(v, level + 1))
                elif isinstance(v, (dict, list)) and not v:
                    if k in comments:
                        lines.append(f"{prefix}# {comments[k]}")
                    lines.append(f"{prefix}{k}: []" if isinstance(v, list) else f"{prefix}{k}: {{}}")
                elif isinstance(v, bool):
                    if k in comments:
                        lines.append(f"{prefix}# {comments[k]}")
                    lines.append(f"{prefix}{k}: {str(v).lower()}")
                elif isinstance(v, (int, float)):
                    if k in comments:
                        lines.append(f"{prefix}# {comments[k]}")
                    lines.append(f"{prefix}{k}: {v}")
                elif v == "" and k in comments:
                    lines.append(f"{prefix}# {comments[k]}")
                    lines.append(f"{prefix}# {k}: \"\"")
                elif v == "":
                    lines.append(f"{prefix}{k}: \"\"")
                elif isinstance(v, str):
                    if k in comments:
                        lines.append(f"{prefix}# {comments[k]}")
                    # Quote strings that look like they need it
                    if any(c in v for c in ":#[]{}") or v.strip() != v:
                        lines.append(f'{prefix}{k}: "{v}"')
                    else:
                        lines.append(f"{prefix}{k}: {v}")
                else:
                    if k in comments:
                        lines.append(f"{prefix}# {comments[k]}")
                    lines.append(f"{prefix}{k}: {v}")

        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    sub = self.emit(item, level + 1)
                    first, rest = sub.split("\n", 1) if "\n" in sub else (sub, "")
                    lines.append(f"{prefix}- {first.lstrip()}")
                    if rest:
                        lines.append(rest)
                elif isinstance(item, str):
                    if any(c in item for c in ":#[]{}"):
                        lines.append(f'{prefix}- "{item}"')
                    else:
                        lines.append(f"{prefix}- {item}")
                else:
                    lines.append(f"{prefix}- {item}")
        else:
            lines.append(f"{prefix}{obj}")

        return "\n".join(lines)


def emit_yaml(tree: dict) -> str:
    """Emit a clean YAML string with inline comments for unresolved refs."""
    emitter = CommentedEmitter(indent=2)
    header = textwrap.dedent("""\
        # ---------------------------------------------------------------------------
        # Generated by generate-config-from-helmrelease.py
        #
        # NOTE: Fields that reference Secrets/ConfigMaps via valueFrom are emitted
        #       as comments.  Either fill them in manually, or re-run with:
        #         --resolve-secrets --namespace <ns>
        # ---------------------------------------------------------------------------
        """)
    return header + "\n" + emitter.emit(tree) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate gateway config.yaml from a FluxCD HelmRelease manifest or plain Helm values."
    )
    parser.add_argument("file", help="Path to the HelmRelease YAML or values YAML.")
    parser.add_argument(
        "--plain-values",
        action="store_true",
        help="Input is a plain Helm values file (not wrapped in spec.values).",
    )
    parser.add_argument(
        "--resolve-secrets",
        action="store_true",
        help="Try to resolve secretKeyRef / configMapKeyRef via kubectl.",
    )
    parser.add_argument(
        "--namespace",
        default="",
        help="Kubernetes namespace to use when resolving Secrets/ConfigMaps.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="-",
        help="Output file (default: stdout).",
    )
    args = parser.parse_args()

    with open(args.file, "r") as fh:
        doc = yaml.safe_load(fh)

    if args.plain_values:
        values = doc
    else:
        values = doc.get("spec", {}).get("values", {}) if isinstance(doc, dict) else {}

    if not isinstance(values, dict):
        print("error: could not extract values from input", file=sys.stderr)
        return 1

    tree = _build_config_tree(values, args.resolve_secrets, args.namespace or None)

    output = emit_yaml(tree)

    if args.output == "-":
        print(output)
    else:
        with open(args.output, "w") as fh:
            fh.write(output)
        print(f"config.yaml written to {args.output}", file=sys.stderr)

    # Warn if there are still unresolved refs
    def has_unresolved(d):
        if isinstance(d, dict):
            return any(str(k).startswith("__comment_") for k in d) or any(has_unresolved(v) for v in d.values())
        if isinstance(d, list):
            return any(has_unresolved(i) for i in d)
        return False

    if has_unresolved(tree):
        print(
            "\nwarning: some fields could not be resolved (see commented lines). "
            "Either fill them in manually or re-run with --resolve-secrets --namespace <ns>",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
