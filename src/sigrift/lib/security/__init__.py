"""Security module for network services.

Provides:
- Socket-based authentication with constant-time comparison
- Credential management (salted SHA-256, HMAC verification)
- Input validation (frequency, gain, sample rate, host, port, path)
- TLS context creation (TLS 1.2+, strong ciphers, mutual TLS)

Carried forward from gen2 security module (was already production-grade).
"""

from sigrift.lib.security.auth import authenticate_client, send_auth
from sigrift.lib.security.credentials import (
    generate_api_key,
    hash_credential,
    verify_credential,
)
from sigrift.lib.security.validation import (
    validate_frequency,
    validate_gain,
    validate_host,
    validate_path,
    validate_port,
    validate_sample_rate,
)
from sigrift.lib.security.tls import create_tls_context, generate_self_signed_cert

__all__ = [
    "authenticate_client",
    "send_auth",
    "generate_api_key",
    "hash_credential",
    "verify_credential",
    "validate_frequency",
    "validate_gain",
    "validate_sample_rate",
    "validate_host",
    "validate_port",
    "validate_path",
    "create_tls_context",
    "generate_self_signed_cert",
]
