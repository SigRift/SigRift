"""Sanitized, authenticated host checks; these are never capture leases."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ValidationError, model_validator

READINESS_FIELD = "_setup_readiness"
READINESS_SECONDS = 300
REASONS = {
    "ready": {"checked"},
    "missing": {"not_found", "selected_absent"},
    "blocked": {
        "driver_in_use",
        "permissions",
        "device_unavailable",
        "management_interface",
        "monitor_unsupported",
        "radio_blocked",
        "ambiguous",
    },
    "unknown": {
        "unsupported_host",
        "probe_failed",
        "selection_unavailable",
        "not_checked",
    },
}


class AdapterReadiness(BaseModel):
    model_config = {"extra": "forbid"}

    adapter: Literal["ready", "missing", "blocked", "unknown"]
    selection: Literal["selected", "not_selected", "unmanaged"]
    reason: Literal[
        "checked",
        "not_found",
        "selected_absent",
        "driver_in_use",
        "permissions",
        "device_unavailable",
        "management_interface",
        "monitor_unsupported",
        "radio_blocked",
        "ambiguous",
        "unsupported_host",
        "probe_failed",
        "selection_unavailable",
        "not_checked",
    ]

    @model_validator(mode="after")
    def consistent_reason(self):
        if self.reason not in REASONS[self.adapter]:
            raise ValueError("Readiness reason does not match adapter status")
        if self.reason == "selected_absent" and self.selection != "selected":
            raise ValueError("Only a saved selection can be missing")
        return self


class SetupReadinessRequest(BaseModel):
    model_config = {"extra": "forbid"}

    sdr: AdapterReadiness
    wifi: AdapterReadiness


def readiness_snapshot(value, now):
    """Keep valid last-check evidence after expiry without claiming it is current."""
    if not isinstance(value, dict):
        return None
    try:
        stamp = datetime.fromisoformat(value["checked_at"])
        if stamp.tzinfo is None:
            return None
        age = (now - stamp).total_seconds()
        if age < 0:
            return None
        report = SetupReadinessRequest.model_validate(
            {key: item for key, item in value.items() if key != "checked_at"}
        )
    except (KeyError, TypeError, ValueError, ValidationError):
        return None
    return report.model_dump() | {
        "checked_at": stamp.astimezone(timezone.utc).isoformat(),
        "fresh": age < READINESS_SECONDS,
        "expires_in_seconds": max(0, READINESS_SECONDS - age),
    }
