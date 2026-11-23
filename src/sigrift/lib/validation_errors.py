"""A 422 for request bodies that hold non-finite numbers, not a 500.

Starlette parses JSON request bodies with :func:`json.loads`, which accepts
the bare ``NaN``, ``Infinity`` and ``-Infinity`` tokens.  FastAPI's default
validation handler echoes each rejected ``input`` (and the error ``ctx``)
in the 422 body, and a non-finite float cannot be JSON-encoded, so any
rejected body holding one (``{"key_id": NaN}``, an unknown field set to
``Infinity``, ...) failed with a 500 instead.  This handler sends the same
response as FastAPI's, with those floats spelled as their JSON text.

Installed by the Shiny dashboard and the Bridge on their apps.
"""

from __future__ import annotations

import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


def json_safe(value: Any) -> Any:
    """*value* with every non-finite float replaced by its JSON spelling.

    ``float("nan")`` becomes ``"NaN"``, the infinities ``"Infinity"`` and
    ``"-Infinity"``, inside dicts, lists and tuples too; all else is kept.
    """
    if isinstance(value, float) and not math.isfinite(value):
        return json.dumps(value)
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


async def request_validation_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """FastAPI's 422 for *exc*, made JSON-safe."""
    return JSONResponse(
        status_code=422,
        content={"detail": json_safe(jsonable_encoder(exc.errors()))},
    )


def install_validation_handler(app: FastAPI) -> None:
    """Answer request validation errors on *app* with a JSON-safe 422."""
    app.add_exception_handler(RequestValidationError, request_validation_handler)
