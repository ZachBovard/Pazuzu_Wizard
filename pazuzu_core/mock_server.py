"""
M0 in-memory Pazuzu Core mock server.

This server is intentionally hardware-free. It supports the phone-app setup
flow locally and resets all data whenever the process is restarted.

M0 does not contact OPNsense. It tells the client application which setup
Wi-Fi network and management address to use during discovery.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="Pazuzu Core M0 Mock Server",
    version="0.1.0",
)

# Allow the local mobile application to call the mock server during M0 testing.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Default OPNsense management access is available only after joining setup Wi-Fi.
SETUP_NETWORK = {
    "ssid": "HANBI-SETUP-M0",
    "security": "open",
    "subnet": "192.168.250.0/24",
    "gateway": "192.168.250.1",
    "opnsense_management_url": "https://192.168.250.1",
    "management_access": "available_only_after_joining_setup_wifi",
    "wan_required": False,
}

mock_state: dict[str, Any] = {
    "setup_state": "factory_new",
    "claim_token": None,
    "pairing_id": None,
    "owner_id": None,
    "owner_session_token": None,
    "baseline_change_id": None,
    "baseline_status": "not_started",
    "history": [],
    "pending_manifest": None,
    "active_manifest": None,
}


def timestamp() -> str:
    """Return a UTC timestamp suitable for API responses."""
    return datetime.now(timezone.utc).isoformat()


def record_event(event: str) -> None:
    """Store a lightweight record of the guided-flow progress."""
    mock_state["history"].append(
        {
            "event": event,
            "timestamp": timestamp(),
            "setup_state": mock_state["setup_state"],
        }
    )


async def request_body(request: Request) -> dict[str, Any]:
    """Read a JSON object, returning an empty object when no body is supplied."""
    try:
        body = await request.json()
    except Exception:
        return {}

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400,
            detail="Request body must be a JSON object.",
        )

    return body


def reset_mock_state() -> None:
    """Return all M0 state to its factory-new condition."""
    mock_state["setup_state"] = "factory_new"
    mock_state["claim_token"] = None
    mock_state["pairing_id"] = None
    mock_state["owner_id"] = None
    mock_state["owner_session_token"] = None
    mock_state["baseline_change_id"] = None
    mock_state["baseline_status"] = "not_started"
    mock_state["pending_manifest"] = None
    mock_state["active_manifest"] = None
    mock_state["history"] = []


def require_owner_session(
    authorization: str | None,
    x_pazuzu_session: str | None,
    x_pazuzu_totp: str | None,
) -> None:
    """Require mock owner-session and TOTP values for privileged actions."""
    bearer_token = None

    if authorization and authorization.lower().startswith("bearer "):
        bearer_token = authorization[7:]

    supplied_session = x_pazuzu_session or bearer_token

    if supplied_session != mock_state["owner_session_token"]:
        raise HTTPException(status_code=401, detail="Valid owner session required.")

    if not x_pazuzu_totp:
        raise HTTPException(status_code=401, detail="X-Pazuzu-TOTP header required.")


@app.get("/api/v1/status")
async def get_status() -> dict[str, Any]:
    """Return the mock appliance identity and current setup position."""
    return {
        "device_id": "pazuzu-m0-mock",
        "device_name": "Pazuzu Core M0 Mock",
        "software_version": "0.1.0-m0",
        "hardware_connected": False,
        "setup_state": mock_state["setup_state"],
        "baseline_status": mock_state["baseline_status"],
        "setup_network": SETUP_NETWORK,
        "timestamp": timestamp(),
    }


@app.get("/api/v1/setup/network")
async def get_setup_network() -> dict[str, Any]:
    """Return setup Wi-Fi and local-management details for the app."""
    return {
        "setup_state": mock_state["setup_state"],
        "setup_network": SETUP_NETWORK,
    }


@app.post("/api/v1/factory/reset")
def factory_reset() -> dict[str, Any]:
    """Reset all mock state without changing a real network."""
    reset_mock_state()

    return {
        "status": "factory_reset",
        "setup_state": "factory_new",
        "baseline_status": "not_started",
        "message": "Mock device has been returned to factory state.",
    }


@app.post("/api/v1/pairing/claim")
async def claim_pairing(request: Request) -> dict[str, Any]:
    """Claim a QR-derived pairing code and provide setup Wi-Fi instructions."""
    body = await request_body(request)
    pairing_code = body.get("pairing_code") or body.get("qr_code")

    if not pairing_code:
        raise HTTPException(status_code=400, detail="pairing_code is required.")

    mock_state["claim_token"] = str(uuid4())
    mock_state["setup_state"] = "hanbi_discovered"
    record_event("pairing_claimed")

    return {
        "claim_token": mock_state["claim_token"],
        "expires_in_seconds": 300,
        "device_id": "pazuzu-m0-mock",
        "setup_state": mock_state["setup_state"],
        "next_action": "join_setup_wifi",
        "setup_network": SETUP_NETWORK,
    }


@app.post("/api/v1/pairing/complete")
async def complete_pairing(request: Request) -> dict[str, Any]:
    """Complete pairing after the application presents its claim token."""
    body = await request_body(request)
    claim_token = body.get("claim_token") or body.get("pairing_token")

    if claim_token != mock_state["claim_token"]:
        raise HTTPException(status_code=401, detail="Invalid or expired claim token.")

    mock_state["pairing_id"] = str(uuid4())
    mock_state["setup_state"] = "pairing_established"
    record_event("pairing_completed")

    return {
        "pairing_id": mock_state["pairing_id"],
        "setup_state": mock_state["setup_state"],
    }


@app.post("/api/v1/owner/create")
async def create_owner(request: Request) -> dict[str, Any]:
    """Create the local owner identity for the M0 flow."""
    body = await request_body(request)
    owner_name = body.get("owner_name") or body.get("name")

    if not owner_name:
        raise HTTPException(status_code=400, detail="owner_name is required.")

    if not mock_state["pairing_id"]:
        raise HTTPException(status_code=409, detail="Pairing must be completed first.")

    mock_state["owner_id"] = str(uuid4())
    mock_state["setup_state"] = "owner_identity_created"
    record_event("owner_created")

    return {
        "owner_id": mock_state["owner_id"],
        "owner_name": owner_name,
        "verification_required": True,
        "setup_state": mock_state["setup_state"],
    }


@app.post("/api/v1/owner/verify")
async def verify_owner(request: Request) -> dict[str, Any]:
    """Verify the owner and issue mock credentials for privileged actions."""
    body = await request_body(request)

    if not mock_state["owner_id"]:
        raise HTTPException(status_code=409, detail="Owner identity must be created first.")

    if not body.get("verification_code"):
        raise HTTPException(status_code=400, detail="verification_code is required.")

    mock_state["owner_session_token"] = str(uuid4())
    mock_state["setup_state"] = "wan_preflight"
    record_event("owner_verified")

    return {
        "owner_id": mock_state["owner_id"],
        "owner_session_token": mock_state["owner_session_token"],
        "mock_totp_code": "000000",
        "setup_state": mock_state["setup_state"],
    }


@app.get("/api/v1/setup/state")
async def get_setup_state() -> dict[str, Any]:
    """Return all setup-flow state needed by the mock client."""
    return {
        "setup_state": mock_state["setup_state"],
        "baseline_status": mock_state["baseline_status"],
        "setup_network": SETUP_NETWORK,
        "pending_manifest": mock_state["pending_manifest"],
        "active_manifest": mock_state["active_manifest"],
        "history": mock_state["history"],
    }


@app.post("/api/v1/baseline/apply")
async def apply_baseline(
    request: Request,
    authorization: str | None = Header(default=None),
    x_pazuzu_session: str | None = Header(default=None),
    x_pazuzu_totp: str | None = Header(default=None),
) -> dict[str, Any]:
    """Start the reversible baseline safe-change flow."""
    require_owner_session(authorization, x_pazuzu_session, x_pazuzu_totp)

    manifest: dict[str, Any] = {
        "version": "alpha-0.1",
        "profile": "lab-default",
    }

    if request.headers.get("content-length") not in (None, "0"):
        payload = await request.json()

        if not isinstance(payload, dict):
            raise HTTPException(
                status_code=422,
                detail="Manifest payload must be an object.",
            )

        supplied_manifest = payload.get("manifest", payload)

        if not isinstance(supplied_manifest, dict):
            raise HTTPException(
                status_code=422,
                detail="Manifest must be an object.",
            )

        manifest = supplied_manifest

    mock_state["baseline_change_id"] = str(uuid4())
    mock_state["pending_manifest"] = manifest
    mock_state["active_manifest"] = None
    mock_state["baseline_status"] = "pending_confirmation"
    mock_state["setup_state"] = "baseline_apply_pending_confirmation"
    record_event("baseline_applied")

    return {
        "change_id": mock_state["baseline_change_id"],
        "status": mock_state["baseline_status"],
        "confirmation_deadline_seconds": 120,
        "setup_state": mock_state["setup_state"],
    }


@app.post("/api/v1/baseline/validate")
async def validate_baseline(
    authorization: str | None = Header(default=None),
    x_pazuzu_session: str | None = Header(default=None),
    x_pazuzu_totp: str | None = Header(default=None),
) -> dict[str, Any]:
    """Return a successful M0 validation result without changing real networks."""
    require_owner_session(authorization, x_pazuzu_session, x_pazuzu_totp)

    if not mock_state["baseline_change_id"]:
        raise HTTPException(status_code=409, detail="No baseline change is pending.")

    mock_state["setup_state"] = "baseline_validation"
    record_event("baseline_validated")

    return {
        "change_id": mock_state["baseline_change_id"],
        "validation_passed": True,
        "checks": [
            {
                "name": "setup_wifi_discovery",
                "passed": True,
                "management_address": "192.168.250.1",
            },
            {"name": "management_network", "passed": True},
            {"name": "dns_resolution", "passed": True},
            {"name": "management_vpn", "passed": True},
        ],
        "setup_state": mock_state["setup_state"],
    }


@app.post("/api/v1/baseline/confirm")
async def confirm_baseline(
    authorization: str | None = Header(default=None),
    x_pazuzu_session: str | None = Header(default=None),
    x_pazuzu_totp: str | None = Header(default=None),
) -> dict[str, Any]:
    """Commit the mock baseline after owner confirmation."""
    require_owner_session(authorization, x_pazuzu_session, x_pazuzu_totp)

    if not mock_state["baseline_change_id"] or not mock_state["pending_manifest"]:
        raise HTTPException(status_code=409, detail="No baseline change is pending.")

    mock_state["active_manifest"] = mock_state["pending_manifest"]
    mock_state["pending_manifest"] = None
    mock_state["baseline_status"] = "committed"
    mock_state["setup_state"] = "setup_complete"
    record_event("baseline_confirmed")

    return {
        "change_id": mock_state["baseline_change_id"],
        "status": mock_state["baseline_status"],
        "setup_state": mock_state["setup_state"],
    }


@app.post("/api/v1/baseline/rollback")
async def rollback_baseline(
    authorization: str | None = Header(default=None),
    x_pazuzu_session: str | None = Header(default=None),
    x_pazuzu_totp: str | None = Header(default=None),
) -> dict[str, Any]:
    """Roll back the temporary mock baseline state."""
    require_owner_session(authorization, x_pazuzu_session, x_pazuzu_totp)

    mock_state["baseline_status"] = "rolled_back"
    mock_state["setup_state"] = "baseline_preflight"
    record_event("baseline_rolled_back")

    return {
        "change_id": mock_state["baseline_change_id"],
        "status": mock_state["baseline_status"],
        "setup_state": mock_state["setup_state"],
    }
