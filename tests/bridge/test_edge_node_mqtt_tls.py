"""edge/node.py must use TLS for MQTT when asked to (review finding D10).

``NodeConfig.mqtt_use_tls`` existed but nothing called ``tls_set`` and the
YAML loader never read it, so the MQTT username/password always crossed the
network in clear text. With ``mqtt_use_tls`` the client now gets a verifying
TLS context (CA from ``mqtt_ca_cert`` / MLRF_CA_CERT / MLRF_CA_BUNDLE, else
the system trust store) before it connects.
"""

from __future__ import annotations

import logging
import os
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import sigrift.edge.node as node


class FakeMQTTClient:
    instances: list["FakeMQTTClient"] = []

    def __init__(self, client_id: str = "") -> None:
        self.client_id = client_id
        self.calls: list[tuple[str, tuple]] = []
        FakeMQTTClient.instances.append(self)

    def tls_set_context(self, ctx: ssl.SSLContext) -> None:
        self.calls.append(("tls_set_context", (ctx,)))

    def tls_set(self, *args, **kwargs) -> None:
        self.calls.append(("tls_set", args))

    def username_pw_set(self, user, password=None) -> None:
        self.calls.append(("username_pw_set", (user, password)))

    def connect(self, host, port) -> None:
        self.calls.append(("connect", (host, port)))

    def loop_start(self) -> None:
        self.calls.append(("loop_start", ()))

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]

    def tls_context(self) -> ssl.SSLContext:
        return next(args[0] for name, args in self.calls if name == "tls_set_context")


@pytest.fixture(autouse=True)
def fake_paho(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeMQTTClient.instances.clear()
    monkeypatch.setattr(node, "HAS_MQTT", True)
    monkeypatch.setattr(
        node, "mqtt", SimpleNamespace(Client=FakeMQTTClient), raising=False
    )
    for var in ("MLRF_CA_CERT", "MLRF_CA_BUNDLE", "MLRF_INSECURE_TLS"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(scope="module")
def ca_pem(tmp_path_factory: pytest.TempPathFactory) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mqtt-test-ca")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path_factory.mktemp("mqtt-ca") / "ca.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(path)


def _ca_names(ctx: ssl.SSLContext) -> list[str]:
    return [
        value
        for cert in ctx.get_ca_certs()
        for rdn in cert["subject"]
        for key, value in rdn
        if key == "commonName"
    ]


def _config(**kw) -> node.NodeConfig:
    base = dict(
        node_id="n1",
        mqtt_broker="broker.example",
        mqtt_port=8883,
        mqtt_user="edge",
        mqtt_password="s3cret",
    )
    base.update(kw)
    return node.NodeConfig(**base)


def _assert_verifying(ctx: ssl.SSLContext) -> None:
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


class TestTLSApplied:
    def test_tls_context_installed_before_credentials_and_connect(self) -> None:
        client = node.create_mqtt_client(_config(mqtt_use_tls=True))
        assert client.names()[0] == "tls_set_context"
        _assert_verifying(client.tls_context())
        assert ("username_pw_set", ("edge", "s3cret")) in client.calls

    def test_edge_node_connects_over_tls(self) -> None:
        edge = node.EdgeNode(_config(mqtt_use_tls=True))
        assert edge.connect_mqtt()
        names = edge.mqtt_client.names()
        assert names.index("tls_set_context") < names.index("connect")
        assert ("connect", ("broker.example", 8883)) in edge.mqtt_client.calls

    def test_configured_ca_is_trusted(self, ca_pem: str) -> None:
        client = node.create_mqtt_client(
            _config(mqtt_use_tls=True, mqtt_ca_cert=ca_pem)
        )
        ctx = client.tls_context()
        _assert_verifying(ctx)
        assert "mqtt-test-ca" in _ca_names(ctx)

    def test_mlrf_ca_cert_env_is_used(self, ca_pem: str, monkeypatch) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", ca_pem)
        ctx = node.create_mqtt_client(_config(mqtt_use_tls=True)).tls_context()
        assert "mqtt-test-ca" in _ca_names(ctx)

    def test_missing_ca_path_still_verifies(self, tmp_path: Path) -> None:
        cfg = _config(mqtt_use_tls=True, mqtt_ca_cert=str(tmp_path / "nope.pem"))
        ctx = node.create_mqtt_client(cfg).tls_context()
        _assert_verifying(ctx)
        assert "mqtt-test-ca" not in _ca_names(ctx)

    def test_unloadable_ca_is_fatal(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pem"
        bad.write_text("not a certificate\n")
        with pytest.raises(node.MQTTTLSConfigError):
            node.create_mqtt_client(_config(mqtt_use_tls=True, mqtt_ca_cert=str(bad)))
        assert FakeMQTTClient.instances == []  # nothing was ever connected

    def test_insecure_opt_out_is_explicit(self, monkeypatch) -> None:
        monkeypatch.setenv("MLRF_INSECURE_TLS", "1")
        ctx = node.create_mqtt_client(_config(mqtt_use_tls=True)).tls_context()
        assert ctx.verify_mode == ssl.CERT_NONE


class TestSettledCAPolicy:
    """Same CA rules as the other edge agents (detection_reporter & co)."""

    def test_configured_ca_wins_over_insecure(self, ca_pem: str, monkeypatch) -> None:
        monkeypatch.setenv("MLRF_INSECURE_TLS", "1")
        ctx = node.create_mqtt_client(
            _config(mqtt_use_tls=True, mqtt_ca_cert=ca_pem)
        ).tls_context()
        _assert_verifying(ctx)
        assert "mqtt-test-ca" in _ca_names(ctx)

    def test_bad_ca_is_not_downgraded_by_insecure(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        bad = tmp_path / "bad.pem"
        bad.write_text("not a certificate\n")
        monkeypatch.setenv("MLRF_INSECURE_TLS", "1")
        with pytest.raises(node.MQTTTLSConfigError):
            node.build_mqtt_tls_context(
                _config(mqtt_use_tls=True, mqtt_ca_cert=str(bad))
            )

    def test_unstattable_path_is_not_treated_as_missing(
        self, tmp_path: Path, monkeypatch, caplog
    ) -> None:
        """EACCES on stat (parent dir not searchable) must not mean 'missing'.

        os.path.exists() is False there, which used to verify the broker
        against the system store as if no CA had been pinned.
        """
        hidden = str(tmp_path / "locked" / "ca.pem")
        real_stat = os.stat
        real_ctx = ssl.create_default_context

        def fake_stat(path, *args, **kwargs):
            if os.fspath(path) == hidden:
                raise PermissionError(13, "Permission denied", hidden)
            return real_stat(path, *args, **kwargs)

        def fake_ctx(*args, **kwargs) -> ssl.SSLContext:
            if kwargs.get("cafile") == hidden:
                raise PermissionError(13, "Permission denied", hidden)
            return real_ctx(*args, **kwargs)

        monkeypatch.setattr(os, "stat", fake_stat)
        monkeypatch.setattr(ssl, "create_default_context", fake_ctx)
        with caplog.at_level(logging.ERROR, logger=node.logger.name):
            with pytest.raises(node.MQTTTLSConfigError, match="Permission denied"):
                node.build_mqtt_tls_context(
                    _config(mqtt_use_tls=True, mqtt_ca_cert=hidden)
                )
        assert not any("does not exist" in r.getMessage() for r in caplog.records)

    def test_missing_path_falls_through_to_env(
        self, tmp_path: Path, ca_pem: str, monkeypatch
    ) -> None:
        monkeypatch.setenv("MLRF_CA_BUNDLE", ca_pem)
        ctx = node.build_mqtt_tls_context(
            _config(mqtt_use_tls=True, mqtt_ca_cert=str(tmp_path / "gone.pem"))
        )
        assert "mqtt-test-ca" in _ca_names(ctx)

    def test_empty_directory_is_fatal(self, tmp_path: Path) -> None:
        """Docker bind-mounts a missing host cert.pem as an empty directory.

        OpenSSL reads capath lazily, so without the probe this only failed
        at the first handshake instead of at startup.
        """
        stand_in = tmp_path / "cert.pem"
        stand_in.mkdir()
        with pytest.raises(node.MQTTTLSConfigError, match="empty directory"):
            node.build_mqtt_tls_context(
                _config(mqtt_use_tls=True, mqtt_ca_cert=str(stand_in))
            )

    def test_directory_without_hashed_certs_is_fatal(
        self, tmp_path: Path, ca_pem: str
    ) -> None:
        (tmp_path / "ca.pem").write_text(Path(ca_pem).read_text())
        with pytest.raises(node.MQTTTLSConfigError, match="openssl rehash"):
            node.build_mqtt_tls_context(
                _config(mqtt_use_tls=True, mqtt_ca_cert=str(tmp_path))
            )

    def test_directory_with_only_unloadable_hashed_entries_is_fatal(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "0123abcd.0").write_bytes(b"this is not a certificate\n")
        with pytest.raises(node.MQTTTLSConfigError, match="none of the 1"):
            node.build_mqtt_tls_context(
                _config(mqtt_use_tls=True, mqtt_ca_cert=str(tmp_path))
            )

    def test_hashed_directory_is_accepted(self, tmp_path: Path, ca_pem: str) -> None:
        (tmp_path / "00000000.0").write_bytes(b"junk sorted first\n")
        (tmp_path / "0123abcd.0").write_text(Path(ca_pem).read_text())
        ctx = node.build_mqtt_tls_context(
            _config(mqtt_use_tls=True, mqtt_ca_cert=str(tmp_path))
        )
        _assert_verifying(ctx)

    def test_main_exits_cleanly_on_empty_directory(
        self, tmp_path: Path, monkeypatch, caplog
    ) -> None:
        stand_in = tmp_path / "ca-dir"
        stand_in.mkdir()

        def no_run(self, status_interval=30.0):
            raise AssertionError("node ran with an unusable CA dir")

        monkeypatch.setattr(node.EdgeNode, "run", no_run)
        monkeypatch.setattr(
            "sys.argv",
            ["node.py", "--mqtt-tls", "--mqtt-ca-cert", str(stand_in)],
        )
        with caplog.at_level(logging.ERROR, logger=node.logger.name):
            assert node.main() == 1
        assert any(f"mqtt_ca_cert={stand_in}" in r.getMessage() for r in caplog.records)
        assert FakeMQTTClient.instances == []


class TestPlaintext:
    def test_no_tls_unless_requested(self) -> None:
        client = node.create_mqtt_client(_config(mqtt_broker="localhost"))
        assert "tls_set_context" not in client.names()

    def test_clear_text_credentials_to_remote_broker_warn(self, caplog) -> None:
        with caplog.at_level("WARNING", logger=node.logger.name):
            node.create_mqtt_client(_config())
        assert "clear text" in caplog.text
        assert "s3cret" not in caplog.text


class TestConfigLoading:
    def test_yaml_reads_tls_settings(self, tmp_path: Path, ca_pem: str) -> None:
        pytest.importorskip("yaml")
        cfg_path = tmp_path / "node.yaml"
        cfg_path.write_text(
            "node_id: n9\n"
            "mqtt_broker: broker.example\n"
            "mqtt_port: 8883\n"
            "mqtt_use_tls: true\n"
            f"mqtt_ca_cert: {ca_pem}\n"
        )
        cfg = node.load_config(str(cfg_path))
        assert cfg.mqtt_use_tls is True
        assert cfg.mqtt_ca_cert == ca_pem

    def test_cli_tls_flags(self, monkeypatch, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pem"
        bad.write_text("garbage")
        seen = {}

        def fake_run(self, status_interval=30.0):
            seen["config"] = self.config

        monkeypatch.setattr(node.EdgeNode, "run", fake_run)
        monkeypatch.setattr(
            "sys.argv",
            ["node.py", "--node-id", "n2", "--mqtt-broker", "b", "--mqtt-tls"],
        )
        assert node.main() == 0
        assert seen["config"].mqtt_use_tls is True
        assert seen["config"].mqtt_port == 8883

        monkeypatch.setattr(
            "sys.argv",
            ["node.py", "--mqtt-tls", "--mqtt-ca-cert", str(bad)],
        )
        assert node.main() == 1  # unusable CA: clear error, no plaintext fallback
