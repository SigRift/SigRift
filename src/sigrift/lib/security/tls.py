"""TLS context creation for secure communications.

Provides TLS 1.2+ contexts with strong cipher suites and optional
mutual TLS (client certificate verification). Also includes a utility
for generating self-signed certificates for development/testing.
"""

from __future__ import annotations

import logging
import ssl
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Strong cipher suites (TLS 1.2 compatible, forward secrecy preferred)
_STRONG_CIPHERS = ":".join(
    [
        "ECDHE+AESGCM",
        "ECDHE+CHACHA20",
        "DHE+AESGCM",
        "DHE+CHACHA20",
        "ECDHE+AES256",
        "DHE+AES256",
        "!aNULL",
        "!eNULL",
        "!MD5",
        "!DSS",
        "!RC4",
        "!3DES",
    ]
)


def create_tls_context(
    cert_path: str | Path | None = None,
    key_path: str | Path | None = None,
    ca_path: str | Path | None = None,
    server: bool = True,
    mutual_tls: bool = False,
) -> ssl.SSLContext:
    """Create a TLS 1.2+ context with strong ciphers.

    Parameters
    ----------
    cert_path : str, Path, or None
        Path to the server/client certificate file (PEM format).
    key_path : str, Path, or None
        Path to the private key file (PEM format).
    ca_path : str, Path, or None
        Path to the CA certificate file for peer verification.
    server : bool
        If True, create a server-side context (``PROTOCOL_TLS_SERVER``).
        If False, create a client-side context (``PROTOCOL_TLS_CLIENT``).
    mutual_tls : bool
        If True and ``server=True``, require client certificates.
        Client contexts always verify the server certificate and hostname,
        using the provided CA or system trust store, regardless of this flag.

    Returns
    -------
    ssl.SSLContext
        Configured TLS context.

    Raises
    ------
    ValueError
        If only one of cert_path and key_path is provided.
    FileNotFoundError
        If cert_path, key_path, or ca_path are specified but don't exist.
    ssl.SSLError
        If the certificate or key files are invalid.
    """
    if (cert_path is None) != (key_path is None):
        raise ValueError("Certificate and private key must be provided together")

    # TLS 1.2 minimum
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)

    # Disable older protocols
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_TLSv1
    ctx.options |= ssl.OP_NO_TLSv1_1

    # Strong cipher suite
    ctx.set_ciphers(_STRONG_CIPHERS)

    # Load certificate and key
    if cert_path is not None:
        cert_path = Path(cert_path)
        key_path = Path(key_path)
        if not cert_path.exists():
            raise FileNotFoundError(f"Certificate not found: {cert_path}")
        if not key_path.exists():
            raise FileNotFoundError(f"Private key not found: {key_path}")
        ctx.load_cert_chain(str(cert_path), str(key_path))

    # Load CA certificate for peer verification
    if ca_path is not None:
        ca_path = Path(ca_path)
        if not ca_path.exists():
            raise FileNotFoundError(f"CA certificate not found: {ca_path}")
        ctx.load_verify_locations(str(ca_path))

    if server:
        if mutual_tls:
            # Server requires client certificates
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False  # Servers don't check hostnames
    else:
        # Sending a client certificate does not change how the server is trusted.
        if ca_path is None:
            try:
                ctx.load_default_certs()
            except Exception:
                logger.warning(
                    "Failed to load system CA certs — set ca_path to "
                    "provide a CA bundle for TLS verification."
                )
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True

    return ctx


def generate_self_signed_cert(
    cert_path: str | Path,
    key_path: str | Path,
    common_name: str = "mlrf-node",
    days: int = 365,
) -> None:
    """Generate a self-signed certificate for development/testing.

    Uses the ``openssl`` command-line tool to generate a private key and
    self-signed certificate. Requires OpenSSL to be installed.

    Parameters
    ----------
    cert_path : str or Path
        Output path for the certificate (PEM format).
    key_path : str or Path
        Output path for the private key (PEM format).
    common_name : str
        Certificate common name (CN).
    days : int
        Certificate validity period in days.

    Raises
    ------
    RuntimeError
        If certificate generation fails.
    FileNotFoundError
        If openssl is not available.
    """
    cert_path = Path(cert_path)
    key_path = Path(key_path)

    # Create parent directories if needed
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    subject = f"/CN={common_name}"

    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:4096",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        str(days),
        "-nodes",  # No passphrase on key
        "-subj",
        subject,
        "-sha256",
    ]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        logger.info(
            "Generated self-signed cert: %s (key: %s, CN=%s, days=%d)",
            cert_path,
            key_path,
            common_name,
            days,
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            "OpenSSL not found. Install openssl to generate certificates."
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Certificate generation failed: {exc.stderr}") from exc
