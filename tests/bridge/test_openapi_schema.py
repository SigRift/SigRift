"""P3-14 — OpenAPI Schema Validation Tests.

Validates the auto-generated FastAPI OpenAPI schema for completeness,
correctness, and adherence to conventions. Uses the create_test_app
factory to build the full app with all routers mounted.
"""

from __future__ import annotations

import os
os.environ.setdefault("BRIDGE_CSRF", "disabled")

import re
import unittest
import warnings
from pathlib import Path
from tempfile import TemporaryDirectory

from sigrift.bridge.app import create_test_app


def _build_schema() -> dict:
    """Build the OpenAPI schema from a test app instance."""
    with TemporaryDirectory() as tmp:
        app = create_test_app(tmp_path=Path(tmp))
        return app.openapi()


class TestOpenAPISchema(unittest.TestCase):
    """Validate the auto-generated OpenAPI schema for completeness."""

    schema: dict

    @classmethod
    def setUpClass(cls):
        cls.schema = _build_schema()

    # ------------------------------------------------------------------
    # Top-level structure
    # ------------------------------------------------------------------

    def test_schema_has_openapi_version(self):
        """Schema must declare an OpenAPI spec version."""
        self.assertIn("openapi", self.schema)
        self.assertTrue(self.schema["openapi"].startswith("3."))

    def test_schema_has_info(self):
        """Schema must have title and version in info block."""
        info = self.schema.get("info", {})
        self.assertIn("title", info)
        self.assertIn("version", info)
        self.assertTrue(len(info["title"]) > 0)
        self.assertTrue(len(info["version"]) > 0)

    def test_schema_has_paths(self):
        """Schema must contain a paths object."""
        self.assertIn("paths", self.schema)
        self.assertIsInstance(self.schema["paths"], dict)

    # ------------------------------------------------------------------
    # Endpoint coverage
    # ------------------------------------------------------------------

    def test_paths_count_minimum(self):
        """Verify minimum expected endpoint count (sanity check).

        The SigRift app has 40+ routers mounted, so we expect at least 30
        unique paths.
        """
        paths = self.schema.get("paths", {})
        self.assertGreaterEqual(
            len(paths), 30,
            f"Expected >=30 paths, got {len(paths)}",
        )

    def test_critical_paths_present(self):
        """Key API endpoints must appear in the schema."""
        paths = set(self.schema.get("paths", {}).keys())
        required = [
            "/api/health",
            "/api/detections/batch",
            "/api/nodes/register",
            "/api/auth/login",
        ]
        for route in required:
            self.assertIn(route, paths, f"Missing critical path: {route}")

    def test_all_paths_have_at_least_one_method(self):
        """Every path must define at least one HTTP method."""
        for path, item in self.schema.get("paths", {}).items():
            methods = {
                k for k in item.keys()
                if k in ("get", "post", "put", "patch", "delete", "head", "options")
            }
            self.assertTrue(
                len(methods) > 0,
                f"Path '{path}' has no HTTP methods defined",
            )

    # ------------------------------------------------------------------
    # Descriptions and summaries
    # ------------------------------------------------------------------

    def test_all_paths_have_description_or_summary(self):
        """Every endpoint should have a description or summary.

        Endpoints without descriptions emit a warning rather than
        failing, since some auto-generated endpoints lack docs.
        """
        missing = []
        for path, item in self.schema.get("paths", {}).items():
            for method in ("get", "post", "put", "patch", "delete"):
                op = item.get(method)
                if op is None:
                    continue
                has_desc = bool(op.get("description") or op.get("summary"))
                if not has_desc:
                    missing.append(f"{method.upper()} {path}")

        if missing:
            pct = 100 * len(missing) / max(1, self._total_operations())
            # Warn but only fail if more than 50% are undocumented
            if pct > 50:
                self.fail(
                    f"{len(missing)} of {self._total_operations()} endpoints "
                    f"({pct:.0f}%) lack description/summary: {missing[:5]}..."
                )
            else:
                warnings.warn(
                    f"{len(missing)} endpoints lack description/summary "
                    f"(e.g. {missing[:3]})",
                    stacklevel=1,
                )

    def _total_operations(self) -> int:
        count = 0
        for item in self.schema.get("paths", {}).values():
            for method in ("get", "post", "put", "patch", "delete"):
                if method in item:
                    count += 1
        return count

    # ------------------------------------------------------------------
    # Responses
    # ------------------------------------------------------------------

    def test_all_paths_have_responses(self):
        """Every endpoint should define at least one response."""
        missing = []
        for path, item in self.schema.get("paths", {}).items():
            for method in ("get", "post", "put", "patch", "delete"):
                op = item.get(method)
                if op is None:
                    continue
                responses = op.get("responses", {})
                if not responses:
                    missing.append(f"{method.upper()} {path}")

        self.assertEqual(
            missing, [],
            f"Endpoints without responses: {missing[:10]}",
        )

    def test_successful_response_codes(self):
        """Endpoints should have a 2xx response defined."""
        missing_2xx = []
        for path, item in self.schema.get("paths", {}).items():
            for method in ("get", "post", "put", "patch", "delete"):
                op = item.get(method)
                if op is None:
                    continue
                responses = op.get("responses", {})
                has_2xx = any(
                    str(code).startswith("2") for code in responses.keys()
                )
                if not has_2xx:
                    missing_2xx.append(f"{method.upper()} {path}")

        if missing_2xx:
            pct = 100 * len(missing_2xx) / max(1, self._total_operations())
            if pct > 30:
                self.fail(
                    f"{len(missing_2xx)} endpoints lack a 2xx response: "
                    f"{missing_2xx[:5]}..."
                )

    # ------------------------------------------------------------------
    # Request bodies
    # ------------------------------------------------------------------

    def test_post_endpoints_have_request_body(self):
        """POST/PUT endpoints should document their request body.

        Lenient: warns instead of failing for endpoints that may use
        query params or have implicit bodies.
        """
        missing = []
        for path, item in self.schema.get("paths", {}).items():
            for method in ("post", "put"):
                op = item.get(method)
                if op is None:
                    continue
                has_body = bool(op.get("requestBody"))
                has_params = bool(op.get("parameters"))
                if not has_body and not has_params:
                    missing.append(f"{method.upper()} {path}")

        if missing:
            warnings.warn(
                f"{len(missing)} POST/PUT endpoints lack requestBody: "
                f"{missing[:5]}",
                stacklevel=1,
            )

    # ------------------------------------------------------------------
    # Components / schemas
    # ------------------------------------------------------------------

    def test_no_empty_response_schemas(self):
        """Response objects should have content/schema or description defined.

        At minimum a response must have a 'description' field per OpenAPI 3.x.
        """
        empty = []
        for path, item in self.schema.get("paths", {}).items():
            for method in ("get", "post", "put", "patch", "delete"):
                op = item.get(method)
                if op is None:
                    continue
                for code, resp_obj in op.get("responses", {}).items():
                    if not isinstance(resp_obj, dict):
                        continue
                    has_desc = bool(resp_obj.get("description"))
                    has_content = bool(resp_obj.get("content"))
                    if not has_desc and not has_content:
                        empty.append(f"{method.upper()} {path} -> {code}")

        if empty:
            warnings.warn(
                f"{len(empty)} response objects lack description/content: "
                f"{empty[:5]}",
                stacklevel=1,
            )

    def test_schema_components_referenced(self):
        """All defined components should be referenced somewhere.

        Orphaned schemas are a code smell indicating dead-code models.
        """
        components = self.schema.get("components", {}).get("schemas", {})
        if not components:
            # No components is fine — FastAPI inlines schemas sometimes
            return

        schema_json = str(self.schema)
        unreferenced = []
        for name in components:
            ref_pattern = f"#/components/schemas/{name}"
            if ref_pattern not in schema_json:
                unreferenced.append(name)

        if unreferenced:
            warnings.warn(
                f"{len(unreferenced)} component schemas are unreferenced: "
                f"{unreferenced[:5]}",
                stacklevel=1,
            )

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------

    def test_security_schemes_defined(self):
        """API key auth scheme should be documented or security is used."""
        components = self.schema.get("components", {})
        security_schemes = components.get("securitySchemes", {})
        # If no security schemes, that's okay for now — emit a warning
        if not security_schemes:
            warnings.warn(
                "No securitySchemes defined in OpenAPI schema. "
                "Consider adding APIKeyHeader scheme.",
                stacklevel=1,
            )
        else:
            # If defined, verify at least one is apiKey or http bearer
            types = {s.get("type") for s in security_schemes.values()}
            self.assertTrue(
                types & {"apiKey", "http", "oauth2", "openIdConnect"},
                f"Unexpected security scheme types: {types}",
            )

    # ------------------------------------------------------------------
    # Path naming conventions
    # ------------------------------------------------------------------

    def test_paths_use_consistent_prefix(self):
        """API paths should start with /api/ or /metrics."""
        non_conforming = []
        for path in self.schema.get("paths", {}).keys():
            if not (path.startswith("/api/") or path.startswith("/metrics")):
                non_conforming.append(path)

        if non_conforming:
            warnings.warn(
                f"{len(non_conforming)} paths don't start with /api/: "
                f"{non_conforming[:5]}",
                stacklevel=1,
            )

    def test_paths_are_lowercase(self):
        """API path segments should be lowercase or kebab-case."""
        # Allow path parameters like {detection_id}
        violations = []
        for path in self.schema.get("paths", {}).keys():
            # Strip path params
            cleaned = re.sub(r"\{[^}]+\}", "", path)
            if cleaned != cleaned.lower():
                violations.append(path)

        self.assertEqual(
            violations, [],
            f"Paths with uppercase segments: {violations}",
        )

    def test_path_parameters_documented(self):
        """Path parameters like {detection_id} should have parameter defs."""
        missing = []
        for path, item in self.schema.get("paths", {}).items():
            # Find path params in the URL template
            url_params = set(re.findall(r"\{(\w+)\}", path))
            if not url_params:
                continue

            for method in ("get", "post", "put", "patch", "delete"):
                op = item.get(method)
                if op is None:
                    continue
                # Gather path-level and operation-level parameters
                all_params = list(item.get("parameters", []))
                all_params.extend(op.get("parameters", []))
                defined_path_params = {
                    p.get("name")
                    for p in all_params
                    if p.get("in") == "path"
                }
                undocumented = url_params - defined_path_params
                if undocumented:
                    missing.append(
                        f"{method.upper()} {path}: {undocumented}"
                    )

        if missing:
            warnings.warn(
                f"{len(missing)} operations have undocumented path params: "
                f"{missing[:5]}",
                stacklevel=1,
            )

    def test_tags_are_present(self):
        """Endpoints should be tagged for grouping in docs."""
        untagged = 0
        total = 0
        for path, item in self.schema.get("paths", {}).items():
            for method in ("get", "post", "put", "patch", "delete"):
                op = item.get(method)
                if op is None:
                    continue
                total += 1
                if not op.get("tags"):
                    untagged += 1

        # Allow up to 10% untagged
        pct = 100 * untagged / max(1, total)
        if pct > 10:
            self.fail(f"{untagged}/{total} ({pct:.0f}%) endpoints are untagged")


if __name__ == "__main__":
    unittest.main()
