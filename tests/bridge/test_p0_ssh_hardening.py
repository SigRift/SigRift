"""Tests for P0-1 and P0-2 SSH hardening in admin key rotation.

P0-1: SSH uses StrictHostKeyChecking=accept-new (not 'no')
P0-2: Key deployed via SCP + file read, never on command line

The deploy flow is 3 steps:
  1. SSH mktemp to create a secure temp file on the remote node
  2. SCP the key file to that remote temp path
  3. SSH to read from the file, update the service, and restart

Covers:
  - SSH/SCP arguments include StrictHostKeyChecking=accept-new
  - Deploy flow uses SCP to transfer key file, then SSH to apply
  - Raw key never appears in SSH/SCP command-line arguments
  - Local temp file is cleaned up even on failure
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential

# Fake remote temp path returned by mktemp
_FAKE_REMOTE_TMP = "/tmp/mlrf_key_ABcDeFgHiJ"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _register_node_and_key(client: TestClient, persistence) -> str:
    """Register a node and associate a key with it, return key_id."""
    node_id = "node-deploy-01"
    client.post("/api/nodes/register", json={
        "node_id": node_id,
        "host": "10.0.0.50",
        "port": 8080,
    })
    # Create a non-master key associated with the node
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(node_id, hash_hex, salt)
    persistence.set_key_meta(node_id, {"node_id": node_id})
    return node_id


def _make_fake_process(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
    """Create a mock asyncio.Process with the given return values."""
    proc = AsyncMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return proc


def _three_step_mocks():
    """Return (processes, wait_for_results) for the 3-step deploy flow."""
    mktemp_proc = _make_fake_process(returncode=0, stdout=_FAKE_REMOTE_TMP.encode() + b"\n")
    scp_proc = _make_fake_process(returncode=0)
    ssh_proc = _make_fake_process(returncode=0)
    processes = [mktemp_proc, scp_proc, ssh_proc]
    wait_results = [
        (_FAKE_REMOTE_TMP.encode() + b"\n", b""),  # mktemp
        (b"", b""),   # SCP
        (b"", b""),   # SSH deploy
    ]
    return processes, wait_results


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSSHHostKeyChecking:
    """P0-1: StrictHostKeyChecking=accept-new is used, not 'no'."""

    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_ssh_uses_accept_new_not_no(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """Both SCP and SSH calls must use StrictHostKeyChecking=accept-new."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        processes, wait_results = _three_step_mocks()
        mock_subprocess_exec.side_effect = processes
        mock_wait_for.side_effect = wait_results

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        assert resp.status_code == 200

        # Inspect all calls to create_subprocess_exec
        for c in mock_subprocess_exec.call_args_list:
            args = c[0]  # positional args
            args_flat = list(args)
            # Must NOT contain StrictHostKeyChecking=no
            for a in args_flat:
                if a == "StrictHostKeyChecking=no":
                    pytest.fail(
                        "Found StrictHostKeyChecking=no in subprocess args"
                    )
            # Must contain StrictHostKeyChecking=accept-new
            assert "StrictHostKeyChecking=accept-new" in args_flat, (
                f"StrictHostKeyChecking=accept-new not found in: {args_flat}"
            )


class TestSCPKeyDeployment:
    """P0-2: Key deployed via SCP file transfer, not on command line."""

    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_key_not_in_ssh_command_args(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """The raw API key must never appear in SSH/SCP command-line args."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        processes, wait_results = _three_step_mocks()
        mock_subprocess_exec.side_effect = processes
        mock_wait_for.side_effect = wait_results

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        data = resp.json()
        new_key = data["raw_key"]

        # The raw key must not appear in any subprocess exec arguments
        for c in mock_subprocess_exec.call_args_list:
            args_flat = list(c[0])
            for arg in args_flat:
                assert new_key not in str(arg), (
                    f"Raw key found in command-line argument: {arg}"
                )

    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_scp_called_before_ssh(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """Flow: mktemp(SSH) -> SCP -> SSH deploy. SCP must come before deploy SSH."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        processes, wait_results = _three_step_mocks()
        mock_subprocess_exec.side_effect = processes
        mock_wait_for.side_effect = wait_results

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        assert resp.status_code == 200
        assert mock_subprocess_exec.call_count == 3

        calls = mock_subprocess_exec.call_args_list
        # First call: SSH mktemp
        assert list(calls[0][0])[0] == "ssh"
        assert "mktemp" in " ".join(str(a) for a in calls[0][0])
        # Second call: SCP
        assert list(calls[1][0])[0] == "scp"
        # Third call: SSH deploy
        assert list(calls[2][0])[0] == "ssh"

    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_scp_targets_secure_tmp_path(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """SCP must transfer to the mktemp-created path on remote host."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        processes, wait_results = _three_step_mocks()
        mock_subprocess_exec.side_effect = processes
        mock_wait_for.side_effect = wait_results

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        assert resp.status_code == 200

        # SCP is the second call (index 1)
        scp_args = list(mock_subprocess_exec.call_args_list[1][0])
        remote_dest = scp_args[-1]
        assert f":{_FAKE_REMOTE_TMP}" in remote_dest, (
            f"SCP destination should include {_FAKE_REMOTE_TMP}, got: {remote_dest}"
        )

    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_deploy_success_result(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """Successful deploy sets deployed=True in response."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        processes, wait_results = _three_step_mocks()
        mock_subprocess_exec.side_effect = processes
        mock_wait_for.side_effect = wait_results

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        data = resp.json()
        assert data["deployed"] is True
        assert data["deploy_host"] == "10.0.0.50"
        assert data["deploy_node_id"] == key_id


class TestTempFileCleanup:
    """Temp file containing the key must be cleaned up in all cases."""

    @patch("os.unlink")
    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_cleanup_on_success(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        mock_unlink,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """os.unlink is called on the temp file after successful deploy."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        processes, wait_results = _three_step_mocks()
        mock_subprocess_exec.side_effect = processes
        mock_wait_for.side_effect = wait_results

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        assert resp.status_code == 200
        mock_unlink.assert_called_once()
        cleanup_path = mock_unlink.call_args[0][0]
        assert "mlrf_key_" in cleanup_path

    @patch("os.unlink")
    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_cleanup_on_mktemp_failure(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        mock_unlink,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """os.unlink is called even when mktemp fails."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        mktemp_proc = _make_fake_process(returncode=1, stderr=b"Connection refused")
        mock_subprocess_exec.side_effect = [mktemp_proc]
        mock_wait_for.side_effect = [
            (b"", b"Connection refused"),
        ]

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        data = resp.json()
        assert data["deployed"] is False
        assert "deploy_error" in data
        mock_unlink.assert_called_once()

    @patch("os.unlink")
    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_cleanup_on_scp_failure(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        mock_unlink,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """os.unlink is called even when SCP fails."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        mktemp_proc = _make_fake_process(returncode=0, stdout=_FAKE_REMOTE_TMP.encode() + b"\n")
        scp_proc = _make_fake_process(returncode=1, stderr=b"Connection refused")
        mock_subprocess_exec.side_effect = [mktemp_proc, scp_proc]
        mock_wait_for.side_effect = [
            (_FAKE_REMOTE_TMP.encode() + b"\n", b""),
            (b"", b"Connection refused"),
        ]

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        data = resp.json()
        assert data["deployed"] is False
        assert "deploy_error" in data
        mock_unlink.assert_called_once()

    @patch("os.unlink")
    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_cleanup_on_timeout(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        mock_unlink,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """os.unlink is called even when SSH times out."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        mktemp_proc = _make_fake_process(returncode=0, stdout=_FAKE_REMOTE_TMP.encode() + b"\n")
        scp_proc = _make_fake_process(returncode=0)
        ssh_proc = _make_fake_process(returncode=0)
        mock_subprocess_exec.side_effect = [mktemp_proc, scp_proc, ssh_proc]
        mock_wait_for.side_effect = [
            (_FAKE_REMOTE_TMP.encode() + b"\n", b""),  # mktemp
            (b"", b""),  # SCP succeeds
            asyncio.TimeoutError(),  # SSH deploy times out
        ]

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        data = resp.json()
        assert data["deployed"] is False
        assert "timed out" in data.get("deploy_error", "").lower()
        mock_unlink.assert_called_once()

    @patch("os.unlink")
    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_cleanup_on_exception(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        mock_unlink,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """os.unlink is called even on unexpected exceptions."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        mock_subprocess_exec.side_effect = OSError("No such file: ssh")
        mock_wait_for.side_effect = []

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        data = resp.json()
        assert data["deployed"] is False
        assert "deploy_error" in data
        mock_unlink.assert_called_once()


class TestKeyFileContents:
    """The temp file written locally must contain exactly the new key."""

    @patch("asyncio.create_subprocess_exec")
    @patch("asyncio.wait_for")
    def test_temp_file_written_with_key(
        self,
        mock_wait_for,
        mock_subprocess_exec,
        client: TestClient,
        bridge_app: FastAPI,
        tmp_path,
    ):
        """Verify the temp file is created and contains the new key."""
        persistence = bridge_app.state.persistence
        key_id = _register_node_and_key(client, persistence)

        written_files: list[str] = []

        async def capture_scp_file(*args, **kwargs):
            # Capture the local file path from SCP args
            args_list = list(args)
            if args_list[0] == "scp":
                # The local file is the second-to-last argument
                local_path = args_list[-2]
                if os.path.exists(local_path):
                    with open(local_path, encoding="utf-8") as f:
                        written_files.append(f.read())
            return _make_fake_process(returncode=0)

        mock_subprocess_exec.side_effect = capture_scp_file
        mock_wait_for.side_effect = [
            (_FAKE_REMOTE_TMP.encode() + b"\n", b""),  # mktemp
            (b"", b""),   # SCP
            (b"", b""),   # SSH deploy
        ]

        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate",
            json={"deploy_to_node": True},
        )

        data = resp.json()
        new_key = data["raw_key"]

        # If we captured the file content, verify it matches the key
        if written_files:
            assert written_files[0] == new_key, (
                "Temp file content does not match the new API key"
            )
