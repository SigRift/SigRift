"""Webhook management router for The Bridge admin panel.

Provides endpoints for webhook CRUD operations, testing, and delivery log viewing.
All endpoints require master key authentication.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import admin_rate_limit as _admin_rate_limit

# One SSRF policy for creation-time validation and delivery: only globally
# routable addresses (or BRIDGE_WEBHOOK_ALLOW_HOSTS entries), checked on the
# resolved addresses.  Re-exported names keep existing imports working.
from sigrift.bridge.notifications import (  # noqa: F401
    ALLOW_HOSTS_ENV,
    BLOCKED_PORTS,
    _is_port_allowed,
    _resolve_and_check_ip,
    settle_task,
)

logger = logging.getLogger(__name__)

router = APIRouter()


async def _commit_webhook(request: Request, webhook_id: str, **change):
    """Checked shared config write, before reporting an admin mutation success."""
    notifier = request.app.state.notifier
    async with notifier.configuration_lock:
        return await _commit_webhook_locked(request, webhook_id, **change)


async def _commit_webhook_locked(request: Request, webhook_id: str, **change):
    task = asyncio.create_task(
        asyncio.to_thread(
            request.app.state.persistence.change_webhook, webhook_id, **change
        )
    )
    try:
        (values, previous), cancelled = await settle_task(task)
    except KeyError:
        raise HTTPException(status_code=404, detail="Webhook not found")
    except Exception:
        logger.error("Webhook configuration commit failed")
        raise HTTPException(
            status_code=503, detail="Webhook configuration could not be saved"
        )
    request.app.state.notifier.load(values, preserve_metrics=True)
    if cancelled:
        raise asyncio.CancelledError
    return previous


async def _current_webhooks(notifier):
    try:
        return await notifier.configuration_snapshot()
    except Exception:
        raise HTTPException(
            status_code=503, detail="Webhook configuration is unavailable"
        )


async def _validate_webhook_url(url: str) -> str:
    """Validate and sanitize webhook URL, blocking SSRF targets.

    Name resolution runs in a worker thread (``getaddrinfo`` blocks).
    """
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400, detail="URL must start with http:// or https://"
        )
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid URL")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid URL: missing hostname")

    # Port validation
    if not _is_port_allowed(port):
        raise HTTPException(
            status_code=400,
            detail=f"Port {port} is not allowed for webhook URLs",
        )

    try:
        await asyncio.to_thread(_resolve_and_check_ip, parsed.hostname)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=(
                "Webhook URLs must not target private/internal networks "
                "(only globally routable addresses are allowed; an operator "
                f"can allow an internal host with {ALLOW_HOSTS_ENV})"
            ),
        )
    except (socket.gaierror, OSError, UnicodeError):
        raise HTTPException(status_code=400, detail="Cannot resolve hostname")
    return url


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateWebhookRequest(BaseModel):
    model_config = {"extra": "forbid"}
    url: str
    name: str = ""
    severity_filter: list[str] = Field(default_factory=lambda: ["critical", "warning"])


class UpdateWebhookRequest(BaseModel):
    model_config = {"extra": "forbid"}
    url: str | None = None
    name: str | None = None
    enabled: bool | None = None
    severity_filter: list[str] | None = None


# ---------------------------------------------------------------------------
# Webhook endpoints
# ---------------------------------------------------------------------------


@router.get("/webhooks")
async def list_webhooks(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """List all configured webhook endpoints."""
    notifier = getattr(request.app.state, "notifier", None)
    if notifier is None:
        return {"webhooks": [], "delivery_log": []}
    # Strip signing_secret from listed webhooks (never expose after creation)
    safe_webhooks = [
        {
            k: v
            for k, v in wh.items()
            if k not in {"signing_secret", "delivery_revision"}
        }
        for wh in await _current_webhooks(notifier)
    ]
    return {
        "webhooks": safe_webhooks,
        "delivery_log": notifier.delivery_log,
    }


@router.post("/webhooks", status_code=status.HTTP_201_CREATED)
async def create_webhook(
    request: Request,
    body: CreateWebhookRequest,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Add a new webhook endpoint for alert notifications."""
    import html as _html

    notifier = getattr(request.app.state, "notifier", None)
    if notifier is None:
        raise HTTPException(
            status_code=500, detail="Notification system not initialized"
        )

    # Validate URL (SSRF protection)
    url = await _validate_webhook_url(body.url)

    # Validate severity filter
    valid_severities = {"critical", "warning", "info"}
    for sev in body.severity_filter:
        if sev not in valid_severities:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {sev}")

    # Construct without changing the live manager before its checked commit.
    from sigrift.bridge.notifications import NotificationManager

    webhook = NotificationManager().add_webhook(
        url=url,
        name=_html.escape(body.name) if body.name else "",
        severity_filter=body.severity_filter,
    )

    await _commit_webhook(request, webhook["id"], create=webhook)

    # Audit
    store = request.app.state.detection_store
    store.log_audit(
        action="admin_create_webhook",
        target_id=webhook.get("id", ""),
        operator=_key_id,
        note=f"Created webhook '{webhook['name']}' \u2192 {url}",
    )

    # Include signing_secret in the creation response (one-time display).
    # It is stored in the webhook config but never returned again.
    signing_secret = webhook.get("signing_secret", "")
    return {
        "status": "created",
        "webhook": webhook,
        "signing_secret": signing_secret,
        "message": "Save this signing secret now -- it will not be shown again. "
        "Use it to verify the X-Bridge-Signature header on incoming payloads.",
    }


@router.put("/webhooks/{webhook_id}")
async def update_webhook(
    webhook_id: str,
    request: Request,
    body: UpdateWebhookRequest,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Update a webhook endpoint configuration."""
    import html as _html

    notifier = getattr(request.app.state, "notifier", None)
    if notifier is None:
        raise HTTPException(
            status_code=500, detail="Notification system not initialized"
        )

    updates: dict[str, Any] = {}
    if body.url is not None:
        updates["url"] = await _validate_webhook_url(body.url)
    if body.name is not None:
        updates["name"] = _html.escape(body.name)
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if body.severity_filter is not None:
        valid_severities = {"critical", "warning", "info"}
        for sev in body.severity_filter:
            if sev not in valid_severities:
                raise HTTPException(status_code=400, detail=f"Invalid severity: {sev}")
        updates["severity_filter"] = body.severity_filter

    old_webhook = await _commit_webhook(request, webhook_id, updates=updates)
    result = notifier.test_webhook(webhook_id)

    # Build audit diff
    changes: list[dict[str, Any]] = []
    if old_webhook:
        for uk, uv in updates.items():
            ov = old_webhook.get(uk)
            if ov != uv:
                changes.append({"key": uk, "old": ov, "new": uv})

    store = request.app.state.detection_store
    store.log_audit(
        action="admin_update_webhook",
        target_id=webhook_id,
        operator=_key_id,
        details={"changes": changes} if changes else None,
    )

    return {
        "status": "updated",
        "webhook": {
            key: value for key, value in result.items() if key != "delivery_revision"
        },
    }


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Delete a webhook endpoint."""
    notifier = getattr(request.app.state, "notifier", None)
    if notifier is None:
        raise HTTPException(
            status_code=500, detail="Notification system not initialized"
        )

    await _commit_webhook(request, webhook_id, delete=True)

    store = request.app.state.detection_store
    store.log_audit(
        action="admin_delete_webhook",
        target_id=str(webhook_id),
        operator=_key_id,
        note=f"Deleted webhook {webhook_id}",
    )

    return {"status": "deleted", "webhook_id": webhook_id}


@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(
    webhook_id: str,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Send a test notification to a specific webhook."""
    notifier = getattr(request.app.state, "notifier", None)
    if notifier is None:
        raise HTTPException(
            status_code=500, detail="Notification system not initialized"
        )

    webhook = next(
        (
            value
            for value in await _current_webhooks(notifier)
            if value["id"] == webhook_id
        ),
        None,
    )
    if webhook is None:
        raise HTTPException(status_code=404, detail=f"Webhook {webhook_id} not found")

    test_alert = {
        "alert_id": "test-" + webhook_id,
        "name": "test_notification",
        "severity": "info",
        "message": "Test notification from The Bridge",
        "node_id": None,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "acknowledged": False,
        "acknowledged_at": None,
    }

    try:
        delivered = await notifier._deliver(webhook, test_alert)
        return {
            "status": "delivered" if delivered else "failed",
            "webhook_id": webhook_id,
            "last_error": webhook.get("last_error"),
        }
    except Exception as exc:
        return {
            "status": "failed",
            "webhook_id": webhook_id,
            "error": str(exc)[:200],
        }


@router.get("/webhooks/retry-queue")
async def get_webhook_retry_queue(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Return the current webhook retry queue size and entries.

    ``dropped`` counts failed deliveries given up on (queue full or out of
    retry attempts): persisted tenant drops plus current-worker transient drops.
    """
    notifier = getattr(request.app.state, "notifier", None)
    if notifier is None:
        return {"queue_size": 0, "entries": [], "dropped": 0}
    queue, durable_dropped = await notifier.retry_snapshot()
    # Sanitize entries for JSON serialization (next_retry is monotonic, convert to relative)
    import time as _time

    now = _time.monotonic()
    entries = []
    for entry in queue:
        entries.append(
            {
                "webhook_id": entry["webhook_id"],
                "attempts": entry["attempts"],
                "last_error": entry["last_error"],
                "retry_in_seconds": max(0, round(entry["next_retry"] - now, 1)),
            }
        )
    return {
        "queue_size": len(queue),
        "entries": entries,
        "dropped": getattr(notifier, "retry_dropped", 0) + durable_dropped,
        "persistence_failures": getattr(notifier, "_retry_storage_failures", 0),
        "initial_dispatch": notifier.initial_dispatch,
    }
