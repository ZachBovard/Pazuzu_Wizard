"""Enrollment probe: can a root web login reach the API on this firewall?

READ ONLY. It signs in to the web page with the root password (typed at a
prompt, never stored, never printed), then makes three harmless GET requests
with that session and reports only status words. It creates nothing and
changes nothing. Its answers decide how the real enroll step is built.

    python -m pazuzu_core.enroll_probe
Needs OPNSENSE_BASE_URL (and OPNSENSE_TLS_VERIFY=false for a lab box).
"""

from __future__ import annotations

import getpass
import html
import re
import sys
from pathlib import Path

_HIDDEN = re.compile(r"<input[^>]*type=[\"']hidden[\"'][^>]*>", re.I)
_ATTR = re.compile(r"(\w[\w-]*)=[\"']([^\"']*)[\"']")
PROBES = (
    ("firmware status", "/api/core/firmware/status"),
    ("user list", "/api/auth/user/search"),
)


def hidden_fields(page: str) -> dict[str, str]:
    """The hidden form inputs of a page (the login form carries a CSRF pair)."""
    out: dict[str, str] = {}
    for tag in _HIDDEN.findall(page or ""):
        attrs = {k.lower(): html.unescape(v) for k, v in _ATTR.findall(tag)}
        if attrs.get("name"):
            out[attrs["name"]] = attrs.get("value", "")
    return out


def form_shape(payload) -> tuple[list[str], list[str]]:
    """Field names of the firewall's blank user form, and its permission ids."""
    user = payload.get("user") if isinstance(payload, dict) else None
    if not isinstance(user, dict):
        return [], []
    privs = user.get("priv")
    return sorted(user), sorted(privs) if isinstance(privs, dict) else []


def logged_in(page: str) -> bool:
    """A page that still asks for the password is a failed sign-in."""
    return bool(page) and "passwordfld" not in page


def describe(status: int, content_type: str) -> str:
    kind = "json" if "json" in (content_type or "").lower() else "not json"
    return f"HTTP {status}, {kind}"


def _cause(exc: BaseException) -> str:
    """Exception kinds only, innermost last: never a message, URL or secret."""
    names = []
    while exc is not None and len(names) < 5:
        names.append(type(exc).__name__)
        exc = exc.__cause__ or exc.__context__
    return " <- ".join(names)


def run(base_url: str, password: str, verify: bool | str, timeout: float = 10,
        pin: str | None = None):
    from pazuzu_core.enroll_safety import base_host_port, host_is_private, make_session

    if not host_is_private(base_host_port(base_url)[0]):
        return ["that address is not on a private network; nothing was sent"]
    import requests  # noqa: F401

    s = make_session(verify, pin)
    lines: list[str] = []
    step = "loading the login page"
    try:
        page = s.get(f"{base_url}/", timeout=timeout)
        form = hidden_fields(page.text)
        form.update({"usernamefld": "root", "passwordfld": password, "login": "1"})
        step = "sending the sign-in"
        after = s.post(f"{base_url}/", data=form, timeout=timeout)
        ok = logged_in(after.text)
        lines.append("web sign-in: " + ("worked" if ok else "did not work"))
        if not ok:
            lines.append(f"login page: {describe(page.status_code, page.headers.get('Content-Type', ''))}, "
                         f"{len(form) - 3} hidden field(s) found")
            lines.append(f"after sign-in: HTTP {after.status_code}, "
                         f"{'password box shown again' if 'passwordfld' in after.text else 'no password box'}, "
                         f"{'a wrong-password message' if 'wrong' in after.text.lower() else 'no wrong-password message'}")
            return lines
        for label, path in PROBES:
            step = f"reading {label}"
            try:
                r = s.get(f"{base_url}{path}", timeout=timeout)
            except requests.exceptions.ConnectionError:
                lines.append(f"{label}: first try dropped, trying once more")
                r = s.get(f"{base_url}{path}", timeout=timeout)
            lines.append(f"{label} with the session: "
                         + describe(r.status_code, r.headers.get("Content-Type", "")))
        step = "reading the blank user form"
        r = s.get(f"{base_url}/api/auth/user/get", timeout=timeout)
        fields, privs = form_shape(r.json() if "json" in r.headers.get("Content-Type", "") else None)
        lines.append("user form fields: " + (", ".join(fields) or "none found"))
        lines.append(f"permission ids offered: {len(privs)}")
        lines.append("all permission ids (diagnostics left out): "
                     + ", ".join(p for p in privs if "diagnostics" not in p))
    except Exception as exc:
        lines.append(f"stopped while {step}: {_cause(exc)}")
    return lines


def main(argv: list[str] | None = None) -> int:
    from pazuzu_core.opnsense_client import _base_url, _tls_setting

    from pazuzu_core.firewall_rule_audit_cli import _quiet_lab_tls_warnings

    from pazuzu_core.enroll_safety import trust_flow

    _quiet_lab_tls_warnings()
    base, verify, pin = _base_url(), _tls_setting(), None
    if verify is False and base.startswith("https://"):
        try:
            pin = trust_flow(base, Path.home() / ".pazuzu")
        except OSError as exc:
            print(f"could not reach the firewall ({type(exc).__name__})")
            return 1
        if pin is None:
            print("not trusted; nothing was sent")
            return 1
    password = getpass.getpass("Root password for this firewall: ")
    lines = run(base, password, verify, pin=pin)
    for line in lines:
        print(line)
    bad = any(l.startswith(("stopped", "web sign-in: did not")) for l in lines)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
