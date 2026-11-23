"""Tests for log buffer and structured JSON logging."""

import json
import logging
import os
from unittest.mock import patch


from sigrift.bridge.log_buffer import JSONFormatter, LogBuffer, init_log_buffer


class TestLogBuffer:
    """Tests for the in-memory ring buffer log handler."""

    def test_buffer_captures_entries(self):
        buf = LogBuffer(max_entries=100)
        logger = logging.getLogger("test.buffer")
        logger.addHandler(buf)
        logger.setLevel(logging.DEBUG)
        try:
            logger.info("hello world")
            entries = buf.get_entries()
            assert len(entries) == 1
            assert entries[0]["message"] == "hello world"
            assert entries[0]["level"] == "INFO"
        finally:
            logger.removeHandler(buf)

    def test_buffer_respects_max_entries(self):
        buf = LogBuffer(max_entries=5)
        logger = logging.getLogger("test.max")
        logger.addHandler(buf)
        logger.setLevel(logging.DEBUG)
        try:
            for i in range(10):
                logger.info("msg %d", i)
            entries = buf.get_entries(limit=100)
            assert len(entries) == 5
            # Newest first
            assert "msg 9" in entries[0]["message"]
        finally:
            logger.removeHandler(buf)

    def test_buffer_filter_by_level(self):
        buf = LogBuffer(max_entries=100)
        logger = logging.getLogger("test.level")
        logger.addHandler(buf)
        logger.setLevel(logging.DEBUG)
        try:
            logger.debug("debug msg")
            logger.info("info msg")
            logger.warning("warn msg")
            entries = buf.get_entries(level="WARNING")
            assert len(entries) == 1
            assert entries[0]["level"] == "WARNING"
        finally:
            logger.removeHandler(buf)

    def test_buffer_filter_by_search(self):
        buf = LogBuffer(max_entries=100)
        logger = logging.getLogger("test.search")
        logger.addHandler(buf)
        logger.setLevel(logging.DEBUG)
        try:
            logger.info("alpha one")
            logger.info("beta two")
            logger.info("alpha three")
            entries = buf.get_entries(search="alpha")
            assert len(entries) == 2
        finally:
            logger.removeHandler(buf)

    def test_buffer_size(self):
        buf = LogBuffer(max_entries=100)
        assert buf.size() == 0
        logger = logging.getLogger("test.size")
        logger.addHandler(buf)
        logger.setLevel(logging.DEBUG)
        try:
            logger.info("one")
            logger.info("two")
            assert buf.size() == 2
        finally:
            logger.removeHandler(buf)


class TestJSONFormatter:
    """Tests for structured JSON log formatter."""

    def test_basic_json_output(self):
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test.json", level=logging.INFO, pathname="",
            lineno=0, msg="hello %s", args=("world",), exc_info=None,
        )
        output = fmt.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "hello world"
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "test.json"
        assert "timestamp" in parsed
        assert isinstance(parsed["timestamp"], str)

    def test_json_includes_exception(self):
        fmt = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            record = logging.LogRecord(
                name="test.exc", level=logging.ERROR, pathname="",
                lineno=0, msg="failed", args=(), exc_info=sys.exc_info(),
            )
        output = fmt.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert isinstance(parsed["exception"], str)
        assert "ValueError" in parsed["exception"]

    def test_json_includes_extra_fields(self):
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test.extra", level=logging.INFO, pathname="",
            lineno=0, msg="audit event", args=(), exc_info=None,
        )
        record.run_id = "gpu0/run1"
        record.node_id = "node-abc"
        record.action = "training_start"
        output = fmt.format(record)
        parsed = json.loads(output)
        assert parsed["run_id"] == "gpu0/run1"
        assert parsed["node_id"] == "node-abc"
        assert parsed["action"] == "training_start"

    def test_json_output_is_single_line(self):
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test.line", level=logging.INFO, pathname="",
            lineno=0, msg="multi\nline\nmessage", args=(), exc_info=None,
        )
        output = fmt.format(record)
        # JSON dumps should escape newlines
        assert "\n" not in output or output.count("\n") == 0

    def test_init_log_buffer_json_mode(self):
        """Verify BRIDGE_LOG_FORMAT=json configures JSON formatter."""
        with patch.dict(os.environ, {"BRIDGE_LOG_FORMAT": "json"}):
            # Save and restore root logger state
            root = logging.getLogger()
            original_handlers = root.handlers.copy()
            try:
                buf = init_log_buffer(max_entries=100)
                # Check that at least one stream handler has JSONFormatter
                json_handlers = [
                    h for h in root.handlers
                    if isinstance(h, logging.StreamHandler)
                    and not isinstance(h, LogBuffer)
                    and isinstance(h.formatter, JSONFormatter)
                ]
                assert len(json_handlers) >= 1
                assert all(isinstance(h.formatter, JSONFormatter) for h in json_handlers)
            finally:
                # Restore original handlers
                root.handlers = original_handlers

    def test_init_log_buffer_default_mode(self):
        """Without BRIDGE_LOG_FORMAT=json, no JSON formatter is installed by init_log_buffer."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_LOG_FORMAT", None)
            root = logging.getLogger()
            original_handlers = root.handlers.copy()
            try:
                buf = init_log_buffer(max_entries=100)
                # Only check handlers we added (LogBuffer), not pytest internals
                new_handlers = [h for h in root.handlers if h not in original_handlers]
                json_new = [
                    h for h in new_handlers
                    if isinstance(h.formatter, JSONFormatter)
                ]
                assert len(json_new) == 0
            finally:
                root.handlers = original_handlers

    def test_json_includes_module_function_line(self):
        """JSON formatter includes module, function, and line fields."""
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test.loc", level=logging.INFO, pathname="/app/test.py",
            lineno=42, msg="location test", args=(), exc_info=None,
        )
        record.module = "test"
        record.funcName = "do_something"
        output = fmt.format(record)
        parsed = json.loads(output)
        assert parsed["module"] == "test"
        assert parsed["function"] == "do_something"
        assert parsed["line"] == 42

    def test_json_includes_request_context_fields(self):
        """JSON formatter includes request context fields when present."""
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test.req", level=logging.INFO, pathname="",
            lineno=0, msg="GET /api/health 200 5.2ms", args=(), exc_info=None,
        )
        record.request_id = "abc123"
        record.method = "GET"
        record.path = "/api/health"
        record.status_code = 200
        record.duration_ms = 5.2
        output = fmt.format(record)
        parsed = json.loads(output)
        assert parsed["request_id"] == "abc123"
        assert parsed["method"] == "GET"
        assert parsed["path"] == "/api/health"
        assert parsed["status_code"] == 200
        assert parsed["duration_ms"] == 5.2

    def test_json_omits_absent_request_fields(self):
        """JSON formatter omits request context fields when not set."""
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test.noreq", level=logging.INFO, pathname="",
            lineno=0, msg="plain message", args=(), exc_info=None,
        )
        output = fmt.format(record)
        parsed = json.loads(output)
        assert "request_id" not in parsed
        assert "method" not in parsed
        assert "status_code" not in parsed
