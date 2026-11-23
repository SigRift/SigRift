"""Tests for OpenTelemetry instrumentation with NoOp fallback."""

from __future__ import annotations

import os
os.environ.setdefault("BRIDGE_CSRF", "disabled")

import pytest

from sigrift.bridge.instrumentation import (
    _NoOpSpan,
    _NoOpTracer,
    _OTEL_AVAILABLE,
    get_tracer,
    setup_tracing,
    trace_span,
)


class TestNoOpSpan:
    """Tests for _NoOpSpan substitute."""

    def test_set_attribute_noop(self):
        span = _NoOpSpan()
        span.set_attribute("key", "value")

    def test_set_status_noop(self):
        span = _NoOpSpan()
        span.set_status("ok")

    def test_record_exception_noop(self):
        span = _NoOpSpan()
        span.record_exception(ValueError("test"))

    def test_add_event_noop(self):
        span = _NoOpSpan()
        span.add_event("event_name", {"k": "v"})

    def test_context_manager(self):
        span = _NoOpSpan()
        with span as s:
            assert s is span


class TestNoOpTracer:
    """Tests for _NoOpTracer substitute."""

    def test_start_span_returns_noop(self):
        tracer = _NoOpTracer()
        span = tracer.start_span("test_op")
        assert isinstance(span, _NoOpSpan)

    def test_start_as_current_span_context(self):
        tracer = _NoOpTracer()
        with tracer.start_as_current_span("test_op") as span:
            assert isinstance(span, _NoOpSpan)
            span.set_attribute("foo", "bar")


class TestSetupTracing:
    """Tests for setup_tracing() graceful degradation."""

    def test_setup_no_error_without_otel(self):
        # Should not raise even if OTel packages are missing
        setup_tracing(service_name="test")

    def test_setup_with_custom_endpoint(self):
        setup_tracing(service_name="test", endpoint="http://example.com:4317")


class TestGetTracer:
    """Tests for get_tracer()."""

    def test_returns_usable_tracer(self):
        tracer = get_tracer("test_module")
        # Should be either a real OTel tracer or our NoOp
        assert hasattr(tracer, "start_span") or hasattr(tracer, "start_as_current_span")

    def test_noop_when_otel_unavailable(self):
        if not _OTEL_AVAILABLE:
            tracer = get_tracer("test_module")
            assert isinstance(tracer, _NoOpTracer)

    def test_tracer_start_span_works(self):
        tracer = get_tracer("test_module")
        span = tracer.start_span("some_op")
        span.set_attribute("k", 1)


class TestTraceSpan:
    """Tests for trace_span() context manager."""

    def test_basic_span(self):
        tracer = get_tracer("test")
        with trace_span(tracer, "my_op") as span:
            span.set_attribute("size", 42)

    def test_span_with_attributes(self):
        tracer = get_tracer("test")
        with trace_span(tracer, "op", attributes={"a": 1, "b": "two"}) as span:
            span.set_attribute("c", 3)

    def test_span_with_no_attributes(self):
        tracer = get_tracer("test")
        with trace_span(tracer, "op", attributes=None) as span:
            pass

    def test_noop_tracer_span(self):
        tracer = _NoOpTracer()
        with trace_span(tracer, "op", attributes={"x": 1}) as span:
            assert isinstance(span, _NoOpSpan)

    def test_nested_spans(self):
        tracer = get_tracer("test")
        with trace_span(tracer, "outer") as outer:
            outer.set_attribute("level", "outer")
            with trace_span(tracer, "inner") as inner:
                inner.set_attribute("level", "inner")

    def test_span_exception_passthrough(self):
        tracer = get_tracer("test")
        with pytest.raises(ValueError, match="boom"):
            with trace_span(tracer, "failing") as span:
                raise ValueError("boom")

    def test_multiple_sequential_spans(self):
        tracer = get_tracer("test")
        for i in range(5):
            with trace_span(tracer, f"op_{i}") as span:
                span.set_attribute("iter", i)
