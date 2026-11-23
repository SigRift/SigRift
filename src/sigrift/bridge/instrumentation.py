"""OpenTelemetry instrumentation for the SigRift bridge.

Provides distributed tracing with OTLP export. Gracefully degrades
to no-ops when opentelemetry packages are not installed.

Usage:
    from sigrift.bridge.instrumentation import get_tracer, trace_span

    tracer = get_tracer(__name__)
    with trace_span(tracer, "operation_name") as span:
        span.set_attribute("key", "value")
        # ... do work ...
"""

from __future__ import annotations

import contextlib
import logging
import os
from typing import Any, Generator

logger = logging.getLogger(__name__)

_OTEL_AVAILABLE = False
_provider_initialized = False

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _OTEL_AVAILABLE = True
except ImportError:
    pass


class _NoOpSpan:
    """Minimal span substitute when OTel is not available."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any) -> None:
        pass

    def record_exception(self, exc: BaseException) -> None:
        pass

    def add_event(self, name: str, attributes: dict | None = None) -> None:
        pass

    def __enter__(self) -> _NoOpSpan:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class _NoOpTracer:
    """Minimal tracer substitute when OTel is not available."""

    def start_span(self, name: str, **kwargs: Any) -> _NoOpSpan:
        return _NoOpSpan()

    def start_as_current_span(
        self, name: str, **kwargs: Any
    ) -> contextlib.AbstractContextManager:
        return contextlib.nullcontext(_NoOpSpan())


def setup_tracing(
    service_name: str = "sigrift-bridge",
    endpoint: str | None = None,
) -> None:
    """Initialize OTLP tracing. No-op if opentelemetry not installed.

    Parameters
    ----------
    service_name : str
        Service name reported in traces.
    endpoint : str or None
        OTLP collector endpoint. Falls back to ``OTEL_EXPORTER_OTLP_ENDPOINT``
        env var, then ``http://localhost:4317``.
    """
    global _provider_initialized

    if not _OTEL_AVAILABLE:
        logger.debug("OpenTelemetry not installed — tracing disabled")
        return

    if _provider_initialized:
        logger.debug("Tracing already initialized — skipping")
        return

    endpoint = endpoint or os.environ.get(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"
    )

    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _provider_initialized = True
        logger.info(
            "OpenTelemetry tracing initialized: service=%s endpoint=%s",
            service_name,
            endpoint,
        )
    except Exception as exc:
        logger.warning("Failed to initialize OpenTelemetry tracing: %s", exc)


def get_tracer(name: str) -> Any:
    """Get a tracer instance. Returns NoOpTracer if OTel not available."""
    if _OTEL_AVAILABLE:
        return trace.get_tracer(name)
    return _NoOpTracer()


@contextlib.contextmanager
def trace_span(
    tracer: Any,
    name: str,
    attributes: dict | None = None,
) -> Generator[Any, None, None]:
    """Context manager for creating a trace span.

    Parameters
    ----------
    tracer : Any
        A tracer instance from ``get_tracer()``.
    name : str
        Span name.
    attributes : dict or None
        Initial attributes to set on the span.
    """
    if isinstance(tracer, _NoOpTracer):
        span = _NoOpSpan()
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, v)
        yield span
        return

    # Real OTel tracer path
    with tracer.start_as_current_span(name) as span:
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, v)
        yield span
