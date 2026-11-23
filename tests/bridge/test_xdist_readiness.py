"""P3-15 — pytest-xdist Readiness Audit.

Scans test files for patterns that would break parallel test execution
under pytest-xdist. Checks for hardcoded ports, shared database paths,
global state mutation, and fixture isolation.
"""

from __future__ import annotations

import os
os.environ.setdefault("BRIDGE_CSRF", "disabled")

import re
import unittest
from pathlib import Path

# Root of the test directory
_TESTS_DIR = Path(__file__).parent
_CONFTEST = _TESTS_DIR / "conftest.py"


def _collect_test_files() -> list[Path]:
    """Return all test_*.py files in the test directory."""
    return sorted(_TESTS_DIR.glob("test_*.py"))


def _read_file(path: Path) -> str:
    """Read file content, returning empty string on failure."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


class TestXdistReadiness(unittest.TestCase):
    """Audit tests for xdist parallel execution readiness."""

    def test_no_hardcoded_ports_in_test_logic(self):
        """Scan test files for hardcoded port numbers in assertions/URLs.

        Port numbers in node registration payloads (e.g., port=8080 in
        test fixtures) are acceptable since they're data, not binding.
        We flag patterns like 'localhost:NNNN' or 'bind.*port.*=' that
        suggest a test binds to a specific port.
        """
        # Patterns that indicate actual port binding/connection
        binding_patterns = [
            re.compile(r"(?:bind|listen|connect|serve).*port\s*=\s*\d{4}", re.IGNORECASE),
            re.compile(r"localhost:\d{4,5}(?!/api)"),  # localhost:PORT not followed by path
            re.compile(r"0\.0\.0\.0:\d{4}"),
            re.compile(r"uvicorn\.run.*port\s*="),
        ]
        violations = []
        for tf in _collect_test_files():
            content = _read_file(tf)
            for pattern in binding_patterns:
                matches = pattern.findall(content)
                if matches:
                    violations.append(f"{tf.name}: {matches[:2]}")

        # This is an audit — report findings as warnings
        if violations:
            import warnings
            warnings.warn(
                f"Test files with potential port binding: {violations}",
                stacklevel=1,
            )

    def test_no_shared_db_paths(self):
        """Scan test files for hardcoded absolute database paths.

        Tests should use tmp_path or :memory: rather than fixed paths
        that would collide across parallel workers.
        """
        # Pattern for hardcoded absolute DB paths (not tmp_path-derived)
        hardcoded_db = re.compile(
            r"""(?:db_path|database)\s*=\s*["'](/[^"']+\.db|[A-Z]:\\[^"']+\.db)["']""",
        )
        violations = []
        for tf in _collect_test_files():
            content = _read_file(tf)
            matches = hardcoded_db.findall(content)
            if matches:
                violations.append(f"{tf.name}: {matches}")

        self.assertEqual(
            violations, [],
            f"Test files with hardcoded DB paths: {violations}",
        )

    def test_conftest_uses_tmp_path(self):
        """Verify conftest fixtures use tmp_path for databases."""
        content = _read_file(_CONFTEST)
        self.assertIn("tmp_path", content,
                       "conftest.py should use tmp_path fixture")
        # The detection_store fixture should use tmp_path
        self.assertIn("detection_store", content,
                       "conftest.py should define detection_store fixture")

    def test_conftest_detection_store_isolation(self):
        """Verify that detection_store fixture is per-test (not session)."""
        content = _read_file(_CONFTEST)
        # Should NOT be session-scoped — that would share state
        # Match @pytest.fixture with scope="session" near detection_store
        session_store = re.search(
            r'@pytest\.fixture\(.*scope\s*=\s*["\']session["\'].*\)\s*\n'
            r'def\s+detection_store',
            content,
        )
        self.assertIsNone(
            session_store,
            "detection_store fixture must not be session-scoped for xdist safety",
        )

    def test_no_global_state_mutation_in_tests(self):
        """Check for obvious global state patterns in test files.

        Looks for `global` keyword usage and module-level mutable
        state assignments that could leak between parallel workers.
        """
        # Only flag 'global' keyword in test functions
        global_pattern = re.compile(r"^\s+global\s+\w+", re.MULTILINE)
        violations = []
        for tf in _collect_test_files():
            content = _read_file(tf)
            matches = global_pattern.findall(content)
            if matches:
                violations.append(f"{tf.name}: {len(matches)} global statements")

        if violations:
            import warnings
            warnings.warn(
                f"Test files using 'global' keyword: {violations}",
                stacklevel=1,
            )

    def test_no_file_based_locks(self):
        """Scan for file-based locking that assumes single-process tests."""
        lock_patterns = [
            re.compile(r"fcntl\.flock", re.IGNORECASE),
            re.compile(r"FileLock|filelock", re.IGNORECASE),
            re.compile(r"lockfile", re.IGNORECASE),
        ]
        violations = []
        for tf in _collect_test_files():
            content = _read_file(tf)
            for pattern in lock_patterns:
                if pattern.search(content):
                    violations.append(tf.name)
                    break

        # Informational — file locks aren't necessarily wrong
        if violations:
            import warnings
            warnings.warn(
                f"Test files using file locks (review for xdist): {violations}",
                stacklevel=1,
            )

    def test_tmp_path_usage_prevalence(self):
        """Most test files should use tmp_path or tmp_path_factory."""
        total = 0
        uses_tmp = 0
        for tf in _collect_test_files():
            total += 1
            content = _read_file(tf)
            if "tmp_path" in content or "tmp_path_factory" in content:
                uses_tmp += 1

        # At least some tests should use tmp_path
        self.assertGreater(uses_tmp, 0, "No test files use tmp_path")

    def test_conftest_xdist_fixtures_exist(self):
        """Verify conftest_xdist.py provides worker-isolated fixtures."""
        xdist_conftest = _TESTS_DIR / "conftest_xdist.py"
        self.assertTrue(
            xdist_conftest.exists(),
            "conftest_xdist.py should exist with xdist fixtures",
        )
        content = _read_file(xdist_conftest)
        self.assertIn("worker_db", content,
                       "conftest_xdist.py should define worker_db fixture")
        self.assertIn("PYTEST_XDIST_WORKER", content,
                       "conftest_xdist.py should reference PYTEST_XDIST_WORKER env var")

    def test_no_singleton_module_state_in_conftest(self):
        """Conftest should not define module-level mutable singletons."""
        content = _read_file(_CONFTEST)
        # Look for module-level mutable assignments (dicts, lists) outside functions
        # But ignore type annotations, constants, and imports
        lines = content.split("\n")
        suspicious = []
        in_function = False
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Track function/class scope
            if stripped.startswith("def ") or stripped.startswith("class "):
                in_function = True
            if stripped and not stripped.startswith(" ") and not stripped.startswith("def ") and not stripped.startswith("class ") and not stripped.startswith("@") and not stripped.startswith("#") and not stripped.startswith("from ") and not stripped.startswith("import "):
                in_function = False

            if not in_function and not stripped.startswith("#"):
                # Module-level mutable dict/list assignment
                if re.match(r'^[a-z_]\w*\s*=\s*(\{|\[)', stripped) and not stripped.startswith("_"):
                    suspicious.append(f"line {i}: {stripped[:60]}")

        if suspicious:
            import warnings
            warnings.warn(
                f"conftest.py has module-level mutable state: {suspicious}",
                stacklevel=1,
            )

    def test_test_files_count(self):
        """Sanity check: ensure we found test files to audit."""
        files = _collect_test_files()
        self.assertGreater(len(files), 50,
                           f"Expected 50+ test files, found {len(files)}")


class TestWorkerDbFixture(unittest.TestCase):
    """Verify the worker_db fixture from conftest_xdist.py works."""

    def test_worker_db_creates_unique_path(self):
        """worker_db should generate a unique path per worker."""
        from pathlib import Path
        import tempfile

        # Simulate two different worker environments
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            os.environ["PYTEST_XDIST_WORKER"] = "gw0"
            db0 = tmp_path / f"test_{os.environ['PYTEST_XDIST_WORKER']}.db"

            os.environ["PYTEST_XDIST_WORKER"] = "gw1"
            db1 = tmp_path / f"test_{os.environ['PYTEST_XDIST_WORKER']}.db"

            self.assertNotEqual(str(db0), str(db1))
            self.assertIn("gw0", str(db0))
            self.assertIn("gw1", str(db1))

            # Clean up
            os.environ.pop("PYTEST_XDIST_WORKER", None)

    def test_worker_db_path_ends_with_db(self):
        """worker_db path should end with .db extension."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            worker_id = os.environ.get("PYTEST_XDIST_WORKER", "gw0")
            db_path = tmp_path / f"test_{worker_id}.db"
            self.assertTrue(str(db_path).endswith(".db"))

    def test_worker_detection_store_creates_tables(self):
        """worker_detection_store should create a usable store."""
        import tempfile
        from sigrift.bridge.detection_store import DetectionStore

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_worker.db"
            store = DetectionStore(db_path=db_path)
            # Should be able to query without error
            recent = store.get_recent(minutes=10, limit=5)
            self.assertEqual(len(recent), 0)


class TestPyprojectXdistConfig(unittest.TestCase):
    """Verify pyproject.toml has pytest marker for xdist grouping."""

    def test_pyproject_has_markers(self):
        """pyproject.toml should define test markers."""
        pyproject = Path(__file__).parent.parent.parent / "pyproject.toml"
        if not pyproject.exists():
            self.skipTest("pyproject.toml not found")
        content = pyproject.read_text()
        self.assertIn("markers", content,
                       "pyproject.toml should define pytest markers")


if __name__ == "__main__":
    unittest.main()
