"""Does the read user's key really refuse changes? (a harmless, cleaned-up test)

With the saved pazuzu-read key it tries to add ONE alias named pz_write_test
(a single documentation address, never applied to the live rules). It then
looks at the firewall's own alias list to see whether the alias exists: that
is the truth, whatever the answer said. If it exists, the test removes it and
checks again. Lab box only. Prints words, never the key.

    python -m pazuzu_core.write_block_test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

NAME = "pz_write_test"
KEY_FILE = "OPNsense.internal_pazuzu-read_apikey.txt"


def load_key(path: Path) -> tuple[str, str] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    k = re.search(r"^key=(\S+)", text, re.M)
    s = re.search(r"^secret=(\S+)", text, re.M)
    return (k.group(1), s.group(1)) if k and s else None


def find(rows, name: str):
    for r in rows or []:
        if isinstance(r, dict) and r.get("name") == name:
            return r
    return None


def run(base_url: str, auth, verify, timeout: float = 10) -> list[str]:
    import requests

    s = requests.Session()
    s.trust_env = False  # never let a proxy variable carry the key
    s.auth = auth
    s.verify = verify
    s.headers["Connection"] = "close"

    def call(method, path, **kw):
        return s.request(method, f"{base_url}{path}", timeout=timeout, **kw)

    def listed():
        r = call("GET", "/api/firewall/alias/search_item")
        return find(r.json().get("rows"), NAME)

    out: list[str] = []
    step = "listing aliases"
    try:
        if listed():
            return [f"an alias named {NAME} is already there; nothing was changed"]
        step = "trying a write"
        r = call("POST", "/api/firewall/alias/add_item", json={"alias": {
            "name": NAME, "type": "host", "content": "192.0.2.1", "enabled": "1",
            "description": "write test, safe to delete"}})
        out.append(f"write attempt: HTTP {r.status_code}")
        step = "checking what happened"
        made = listed()
        if not made:
            out.append("RESULT: the firewall refused the change (nothing was created).")
            return out
        out.append("RESULT: the change WAS accepted, so this key can change things.")
        step = "cleaning up"
        uuid = made.get("uuid")
        if uuid:
            call("POST", f"/api/firewall/alias/del_item/{uuid}")
        out.append("cleanup: "
                   + ("removed" if not listed() else
                      f"FAILED, delete the alias {NAME} by hand"))
    except Exception as exc:
        out.append(f"stopped while {step}: {type(exc).__name__}")
    return out


def main(argv: list[str] | None = None) -> int:
    from pazuzu_core.firewall_rule_audit_cli import _quiet_lab_tls_warnings
    from pazuzu_core.opnsense_client import _base_url, _tls_setting

    _quiet_lab_tls_warnings()
    auth = load_key(Path.home() / ".pazuzu" / KEY_FILE)
    if auth is None:
        print("no saved key for pazuzu-read; run enrollment first")
        return 1
    lines = run(_base_url(), auth, _tls_setting())
    for line in lines:
        print(line)
    return 0 if any("refused" in l for l in lines) else 1


if __name__ == "__main__":
    sys.exit(main())
