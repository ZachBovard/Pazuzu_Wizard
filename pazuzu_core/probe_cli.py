"""Run the read-only probe against the firewall.

    python -m pazuzu_core.probe_cli

It uses the read account Pazuzu already made (its key stays in the key folder; nothing is typed
or pasted), sends GET requests only, and prints a table of names and numbers that is safe to
paste into a chat. The full report is saved to scan_results/probe_<version>.json.

    --role installer   use the test-only installer account instead (it can read every page, so
                       it shows what exists even where the read account is denied)
    --only ids,ddns    run just those probes (see pazuzu_core.probe.PROBES)
    --keys PATH        the key folder (default: ~/.pazuzu)

The address and TLS setting come from OPNSENSE_BASE_URL and OPNSENSE_TLS_VERIFY, the same as the
wizard. Nothing here can change the firewall: every request is a GET to a fixed path.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable

import requests

from pazuzu_core import enroll as en
from pazuzu_core import probe
from pazuzu_core.opnsense_client import _base_url, _tls_setting

TIMEOUT = 8.0


def make_fetch(base: str, auth: tuple[str, str], verify, session=None) -> Callable:
    """GET only, to a path on the fixed list, no redirects, no proxy or environment settings."""
    sess = session or requests.Session()
    sess.auth = auth
    sess.verify = verify
    sess.trust_env = False
    sess.max_redirects = 0
    return session_fetch(sess, base)


def session_fetch(sess, base: str) -> Callable:
    """The same GET-only fetch over a session that is already set up (key, certificate pin)."""
    base = base.rstrip("/")

    def fetch(path: str):
        if not probe.allowed_path(path) or not probe.verb_ok(path):
            raise ValueError("not a probe path")
        try:
            resp = sess.get(base + path, timeout=TIMEOUT, allow_redirects=False, stream=True)
            try:
                chunks, size = [], 0
                for chunk in resp.iter_content(65536):
                    size += len(chunk)
                    if size > probe.MAX_BYTES:
                        return resp.status_code, None, "answer too large"
                    chunks.append(chunk)
                return resp.status_code, b"".join(chunks).decode("utf-8", "replace"), None
            finally:
                resp.close()
        except requests.RequestException as exc:
            return None, None, type(exc).__name__

    return fetch


def load_key(key_dir: Path, role: en.Role) -> tuple[str, str]:
    path = en.key_path(key_dir, role)
    try:
        pair = en.parse_key(path.read_text(encoding="utf-8"))
    except OSError:
        pair = None
    if pair is None:
        raise SystemExit(f"There is no {role.name} key in {key_dir}. Run the wizard's sign-in step first.")
    return pair


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="probe_cli", description=__doc__.split("\n\n")[0])
    ap.add_argument("--keys", default=str(Path.home() / ".pazuzu"))
    ap.add_argument("--role", choices=("read", "installer"), default="read")
    ap.add_argument("--only", default="")
    ap.add_argument("--output-dir", default="scan_results")
    args = ap.parse_args(argv)

    try:
        base, verify = _base_url(), _tls_setting()
    except RuntimeError as exc:
        print(f"Set OPNSENSE_BASE_URL (and OPNSENSE_TLS_VERIFY) first: {exc}")
        return 2
    if verify is False:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        print("Note: TLS verification is disabled (lab only).")

    role = en.READ if args.role == "read" else en.INSTALLER
    auth = load_key(Path(args.keys), role)
    only = [x.strip() for x in args.only.split(",") if x.strip()] or None
    known = {i for i, _p, _w in probe.PROBES}
    if only and not set(only) <= known:
        print("Unknown probe name(s): " + ", ".join(sorted(set(only) - known)))
        return 2

    report = probe.run_probe(make_fetch(base, auth, verify), only=only)
    report["account"] = role.name
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = "probe_" + str(report.get("version") or "unknown").replace("/", "_") + (
        "_installer" if args.role == "installer" else "") + ".json"
    (out_dir / name).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\n".join(probe.table(report)))
    print(f"\nSaved to {out_dir / name}. Paste the table above; it holds names and numbers only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
