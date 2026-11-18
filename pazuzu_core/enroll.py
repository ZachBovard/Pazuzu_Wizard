"""First-run enrollment: make Pazuzu's own limited users and keys.

Signs in to the firewall's web page once with the root password (typed at a
prompt, kept in memory only, never written or printed), creates ONE user
named pazuzu-read with a short list of permissions, creates a key for it and
saves the key file locally. It then proves the key with the five reads the
product uses. It never changes anything else.

With --write it makes a second user, pazuzu-write, the same way, for the
steps that change rules and aliases. Creating that user (and any later change
to a user's permissions) is a change to the firewall, so it needs a passkey
touch on that exact plan. Only the first-run read user is made without one,
because no passkey exists yet at that point.

Honest limit: the firewall's permissions are per page, not read/write, so
the user could change what it can see. It also carries the firewall's
"read-only config" permission, but whether that stops API writes is not yet
tested; until it is, read-only is our code's promise, not the firewall's.
"""

from __future__ import annotations

import getpass
import json
import re
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from pazuzu_core.enroll_probe import hidden_fields, logged_in
from pazuzu_core.enroll_safety import (
    base_host_port, host_is_private, load_pin, make_session, save_pin,
    trust_flow, write_private,
)

USER_NAME = "pazuzu-read"
READ_PERMISSIONS = (
    "page-firewall-rules",
    "page-filter-api",
    "page-firewall-aliases",
    "page-interfaces",
    "page-status-interfaces",
    "page-system-status",
    "page-system-firmware-manualupdate",
    "page-system-advanced-network",   # interface settings read (to confirm)
    "user-config-readonly",           # asks the firewall to refuse changes (to confirm)
)
# The firewall's own pages behind what Finish getting to Happy reads and changes. Names read from 26.7's own ACL.xml
# files on production (30 Oct 2026): before these, every one of them was read with the installer account, so the board
# lost them the morning after (the installer closes itself after a day). A name this firewall does not list is left off.
SERVICE_PERMISSIONS = (
    "page-services-unbound",          # api/unbound/* (DNS over TLS, the VPN's DNS entry, block lists)
    "page-wireguard-config",          # api/wireguard/server|client|general|service/*
    "page-dhcp-kea-v4",               # api/kea/dhcpv4/*, leases4, service
    "page-system-cron",               # api/cron/* (the lists' nightly refresh)
    "page-services-ids",              # api/ids/* (packet inspection's rulesets)
    "page-filter-snat-api",           # api/firewall/source_nat/*
    "page-firewall-nat-portforward-edit",   # api/firewall/d_nat/* (port forwards, DNS and time redirects)
    "page-services-dyndns",           # api/dyndns/* (Reach home from outside; os-ddclient's ACL.xml), BUILD 461
)
READ_PERMISSIONS = READ_PERMISSIONS[:-1] + SERVICE_PERMISSIONS + READ_PERMISSIONS[-1:]
# Pages the Data screen reads through the firewall's own API. The names are made from the
# firewall's page titles (Lobby: Dashboard, Status: Services, Reporting: Traffic,
# Diagnostics: ARP Table) and are NOT proven on 26.7, so they are added in a second,
# separate request: if the firewall refuses a name, the account stays as it was and
# enrolling carries on.
DATA_PERMISSIONS = (
    "page-lobby-dashboard",
    "page-status-services",
    "page-reporting-traffic",
    "page-diagnostics-arptable",
)

# What the write user may do: the same pages as the read user (the firewall's
# permissions are per page, not read or write), without the "read-only config"
# flag that is there to hold the read user back, plus the two edit pages for
# the things we change: aliases and rules. Creating an alias was refused (403)
# without the first; the names come from the firewall's own list. Whether
# these are enough for every change we make is checked by the drill.
WRITE_USER_NAME = "pazuzu-write"
WRITE_EXTRA_PERMISSIONS = (
    "page-firewall-alias-edit",
    "page-firewall-rules-edit",
)
WRITE_PERMISSIONS = tuple(
    p for p in READ_PERMISSIONS if p != "user-config-readonly"
) + WRITE_EXTRA_PERMISSIONS


@dataclass(frozen=True)
class Role:
    name: str
    permissions: tuple[str, ...]
    descr: str
    needs_passkey: bool
    expires_days: int | None = None   # the firewall closes the account after this


READ = Role(USER_NAME, READ_PERMISSIONS,
            "Pazuzu read user (created by first-run enrollment)", False)
WRITE = Role(WRITE_USER_NAME, WRITE_PERMISSIONS,
             "Pazuzu write user (changes rules and aliases; created with a passkey)",
             True)

# The account that installs plugins. Installing needs the firewall's firmware
# pages, which no smaller list here covers, so for now it is allowed every page.
# That is wide on purpose and only for testing: it is made on request with a
# passkey, the firewall closes it after a day, and the page says to delete it.
INSTALLER_USER_NAME = "pazuzu-installer"
INSTALLER_PERMISSIONS = ("page-all",)
INSTALLER = Role(INSTALLER_USER_NAME, INSTALLER_PERMISSIONS,
                 "Pazuzu installer (TEST ONLY: every page; closes after a day; delete it after use)",
                 True, expires_days=1)

READ_PATHS = (
    ("firmware", "/api/core/firmware/status"),
    ("interfaces overview", "/api/interfaces/overview/interfaces_info/true"),
    ("interface settings", "/api/interfaces/settings/get"),
    ("aliases", "/api/firewall/alias/search_item"),
    ("rules", "/api/firewall/filter/search_rule"),
)
_CSRF = re.compile(r"X-CSRFToken[\"']\s*,\s*[\"']([^\"']+)[\"']")


def csrf_token(page: str) -> str | None:
    m = _CSRF.search(page or "")
    return m.group(1) if m else None


def parse_key(body) -> tuple[str, str] | None:
    """The key and secret from either a JSON answer or a key=/secret= file."""
    if isinstance(body, dict):
        key = body.get("apikey") or body.get("key")
        sec = body.get("apisecret") or body.get("secret")
        return (key, sec) if key and sec else None
    if isinstance(body, str):
        k = re.search(r"^key=(\S+)", body, re.M)
        s = re.search(r"^secret=(\S+)", body, re.M)
        return (k.group(1), s.group(1)) if k and s else None
    return None


def user_payload(role: Role = READ) -> dict:
    extra = {}
    if role.expires_days:
        import datetime
        day = datetime.date.today() + datetime.timedelta(days=role.expires_days)
        extra["expires"] = day.strftime("%m/%d/%Y")
    return {"user": {
        **extra,
        "name": role.name,
        "disabled": "0",
        "scrambled_password": "1",
        "password": secrets.token_urlsafe(32),  # never used to sign in
        "descr": role.descr,
        "priv": ",".join(role.permissions),
    }}


def key_path(key_dir: Path, role: Role = READ) -> Path:
    return key_dir / f"OPNsense.internal_{role.name}_apikey.txt"


def _approved(gate, kind: str, role: Role, extra: dict, lines: list[str]) -> bool:
    """A passkey touch on exactly this user change. No gate means no."""
    if gate is None:
        return False
    from pazuzu_core.passkey_gate import plan_digest
    plan = {"user": role.name, "permissions": list(role.permissions), **extra}
    return bool(gate(plan_digest(kind, plan), lines))


def shape(r) -> str:
    kind = (r.headers.get("Content-Type", "") or "").split(";")[0]
    keys = ""
    if "json" in kind:
        try:
            body = r.json()
            if isinstance(body, dict):
                keys = " keys: " + ", ".join(sorted(body))
                res = body.get("result")
                if isinstance(res, str) and len(res) < 20:
                    keys += f"; result: {res}"
        except ValueError:
            pass
    return f"HTTP {r.status_code}, {kind or 'no type'}{keys}"


def _offered_privileges(s, base_url: str, timeout: float = 10):
    """The permission names this firewall offers on its user form, or None when the answer is not in a shape we
    know (then nothing is trimmed and the firewall's own refusal, if any, is shown)."""
    try:
        priv = s.get(f"{base_url}/api/auth/user/get", timeout=timeout).json()["user"]["priv"]
    except Exception:
        return None
    return set(priv) if isinstance(priv, dict) and priv else None


# The names that are left off, not refused, when a firewall does not list them (older or newer versions differ).
TRIMMABLE = WRITE_EXTRA_PERMISSIONS + SERVICE_PERMISSIONS + DATA_PERMISSIONS


def trim_write_extras(role: Role, offered) -> tuple[Role, list[str]]:
    """Firewalls differ in the pages they list. The edit pages, the service pages and the data pages are left off when
    this firewall does not list them (only for the read and write accounts; the installer's page-all is never trimmed).
    The base pages and the read-only guard are never trimmed: a missing one is shown as the firewall's refusal."""
    if offered is None or role.name not in (USER_NAME, WRITE_USER_NAME):
        return role, []
    dropped = [p for p in TRIMMABLE if p in role.permissions and p not in offered]
    if not dropped:
        return role, []
    kept = tuple(p for p in role.permissions if p not in dropped)
    from dataclasses import replace
    return replace(role, permissions=kept), dropped


def _refusal(r) -> str:
    """What the firewall said when it did not make a user: the fields it objected to and its words for each. These
    are the firewall's own validation messages (the request's password is never echoed back), cut short."""
    try:
        body = r.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    parts = []
    val = body.get("validations")
    if isinstance(val, dict):
        parts += [f"{str(k)[:40]}: {str(v)[:160]}" for k, v in list(val.items())[:4]]
    for key in ("message", "errorMessage"):
        if isinstance(body.get(key), str):
            parts.append(body[key][:160])
    if not parts and isinstance(body.get("result"), str) and body["result"] != "saved":
        parts.append("result: " + body["result"][:40])
    return "; ".join(parts)


def _tls_reason(exc: BaseException) -> str:
    """A fixed phrase for common certificate failures. Never the error's own text."""

    text = ""
    seen = 0
    while exc is not None and seen < 6:
        text += " " + str(exc)
        exc = exc.__cause__ or exc.__context__
        seen += 1
    for needle, phrase in (
            ("CERTIFICATE_VERIFY_FAILED", "strict certificate checking is on and this firewall uses its own certificate"),
            ("ingerprints did not match", "the certificate is not the one you confirmed"),
            ("DH_KEY_TOO_SMALL", "the firewall offers an old, weak key exchange"),
            ("UNSUPPORTED_PROTOCOL", "no common TLS version"),
            ("WRONG_VERSION_NUMBER", "that port is not speaking HTTPS"),
            ("SSLV3_ALERT", "the firewall closed the secure connection"),
            ("EOF occurred", "the firewall closed the secure connection")):
        if needle in text:
            return phrase
    return ""


def enroll(base_url: str, password: str, verify, key_dir: Path,
           confirm: Callable[[tuple[str, ...]], bool], timeout: float = 10,
           pin: str | None = None, role: Role = READ, gate=None,
           username: str = "root"):
    out: list[str] = []
    if not host_is_private(base_host_port(base_url)[0]):
        return ["that address is not on a private network; nothing was sent"]
    path = key_path(key_dir, role)
    if path.exists():
        return ["a key file for this user already exists here; nothing was changed"]
    s = make_session(verify, pin)
    step = "loading the login page"
    try:
        page = s.get(f"{base_url}/", timeout=timeout)
        form = hidden_fields(page.text)
        form.update({"usernamefld": username, "passwordfld": password, "login": "1"})
        step = "signing in"
        after = s.post(f"{base_url}/", data=form, timeout=timeout)
        if not logged_in(after.text):
            return ["web sign-in did not work; nothing was changed"]
        token = csrf_token(after.text)
        if token is None:
            home = s.get(f"{base_url}/index.php", timeout=timeout)
            token = csrf_token(home.text)
        if token is None:
            return ["signed in, but no change token was found on the page; "
                    "nothing was changed"]
        role, left_off = trim_write_extras(role, _offered_privileges(s, base_url, timeout)
                                           if role.name in (USER_NAME, WRITE_USER_NAME) else None)
        if left_off:
            out.append("this firewall does not list these permissions, so they are left off: " + ", ".join(left_off))
        step = "checking for an existing user"
        rows = s.get(f"{base_url}/api/auth/user/search", timeout=timeout).json().get("rows", [])
        exists = any(r.get("name") == role.name for r in rows if isinstance(r, dict))
        if not confirm(role.permissions, exists):
            return ["cancelled; nothing was changed"]
        if role.needs_passkey and not _approved(
                gate, "enroll-user", role, {"exists": exists},
                [f"{'Add a key to' if exists else 'Create'} the firewall user {role.name}",
                 "Permissions: " + ", ".join(role.permissions),
                 "Its key is saved only on this device"]):
            return ["not approved with a passkey; nothing was changed"]
        hdr = {"X-CSRFToken": token, "X-Requested-With": "XMLHttpRequest"}
        uuid = None
        if exists:
            out.append("user already there; adding a key to it")
        else:
            step = "creating the user"
            r = s.post(f"{base_url}/api/auth/user/add", json=user_payload(role),
                       headers=hdr, timeout=timeout)
            out.append(f"create user: {shape(r)}")
            try:
                uuid = r.json().get("uuid")
            except ValueError:
                pass
            if not uuid:
                said = _refusal(r)
                if said:
                    out.append("the firewall refused the user: " + said)
        if not uuid:
            rows = s.get(f"{base_url}/api/auth/user/search", timeout=timeout).json().get("rows", [])
            uuid = next((x.get("uuid") for x in rows
                         if isinstance(x, dict) and x.get("name") == role.name), None)
        if not uuid:
            out.append("the user was not found afterwards; stopping")
            return out
        step = "creating the key"
        body = None
        for who in (role.name, uuid):  # this endpoint may want the name or the id
            r = s.post(f"{base_url}/api/auth/user/add_api_key/{who}", headers=hdr,
                       timeout=timeout)
            out.append(f"create key ({'by name' if who == role.name else 'by id'}): {shape(r)}")
            try:
                body = r.json()
            except ValueError:
                body = r.text
            if parse_key(body):
                break
        pair = parse_key(body)
        if pair is None:
            out.append("the key answer was not understood; stopping")
            return out
        access = write_private(path, f"key={pair[0]}\nsecret={pair[1]}\n")
        out.append("key file saved")
        out.append(f"key file access: {access}")
        if role is READ:
            out += widen_for_data(s, base_url, uuid, role, hdr, timeout)
        if exists:
            out += renew_expiry(s, base_url, uuid, role, hdr, timeout)
        out += check_key(base_url, pair, verify, timeout, pin)
    except Exception as exc:
        why = _tls_reason(exc)
        out.append(f"stopped while {step}: {type(exc).__name__}" + (f" ({why})" if why else ""))
    return out


def renew_expiry(s, base_url: str, uuid: str, role: Role, hdr: dict, timeout: float = 10) -> list[str]:
    """A user that closes itself after a day (the installer) may be there already with its closing date past. A key
    added to it would be refused with 401 for good, so its date is moved on, and switched back on if it was off."""
    if not role.expires_days:
        return []
    import datetime
    day = (datetime.date.today() + datetime.timedelta(days=role.expires_days)).strftime("%m/%d/%Y")
    try:
        r = s.post(f"{base_url}/api/auth/user/set/{uuid}", json={"user": {"expires": day, "disabled": "0"}},
                   headers=hdr, timeout=timeout)
        saved = isinstance(r.json(), dict) and r.json().get("result") == "saved"
    except Exception:
        saved = False
    return [f"closing date moved to {day}" if saved else
            "the firewall did not accept a new closing date; if this account had already closed, delete it on the "
            "firewall (System, Access, Users) and make it again"]


def widen_for_data(s, base_url: str, uuid: str, role: Role, hdr: dict,
                   timeout: float = 10) -> list[str]:
    """Let the look-only user read the pages the Data screen needs. Best effort: the
    plain list was already saved, so a refusal leaves the user exactly as it was."""

    try:
        r = s.post(f"{base_url}/api/auth/user/set/{uuid}",
                   json={"user": {"priv": ",".join(role.permissions + DATA_PERMISSIONS)}},
                   headers=hdr, timeout=timeout)
        saved = isinstance(r.json(), dict) and r.json().get("result") == "saved"
    except Exception:
        saved = False
    return ["data pages: allowed" if saved else
            "data pages: the firewall did not accept them; the Data screen may say it cannot read"]


def sync_permissions(session, base_url: str, roles=None, timeout: float = 10) -> list[str]:
    """Bring the look-only and change accounts up to the current page lists, with a key that may change users (the
    installer's). The firewall's users API, the same calls a person makes on System, Access, Users. An account that is
    not on this firewall is skipped; a page this firewall does not list is left off. Lines say what happened."""
    roles = roles or (READ, WRITE)
    base = base_url.rstrip("/")
    try:
        rows = session.get(f"{base}/api/auth/user/search", timeout=timeout).json().get("rows", [])
    except Exception as exc:
        return [f"the accounts' pages were not brought up to date: the user list could not be read ({type(exc).__name__})"]
    offered = _offered_privileges(session, base, timeout)
    out = []
    for role in roles:
        uuid = next((x.get("uuid") for x in rows if isinstance(x, dict) and x.get("name") == role.name), None)
        if not uuid:
            out.append(f"{role.name}: not on this firewall, nothing to bring up to date")
            continue
        kept, left_off = trim_write_extras(role, offered)
        perms = kept.permissions        # plus the data pages (Status: Services lets the change account start a service)
        perms += tuple(p for p in DATA_PERMISSIONS if p not in perms and (offered is None or p in offered))
        try:
            r = session.post(f"{base}/api/auth/user/set/{uuid}", json={"user": {"priv": ",".join(perms)}},
                             timeout=timeout)
            saved = isinstance(r.json(), dict) and r.json().get("result") == "saved"
        except Exception:
            saved = False
        out.append(f"{role.name}: pages brought up to date" if saved else
                   f"{role.name}: the firewall did not take the new pages; the board may say it cannot read some lines")
        if saved and left_off:
            out.append(f"{role.name}: this firewall does not list " + ", ".join(left_off) + ", so they are left off")
    return out


def set_permissions(base_url: str, password: str, verify, key_dir: Path,
                    timeout: float = 10, pin: str | None = None,
                    role: Role = READ, gate=None, username: str = "root") -> list[str]:
    """Bring the existing user's permissions to the current list, then re-test.

    A change to the firewall, so it needs a passkey touch on that exact plan.
    """
    if not host_is_private(base_host_port(base_url)[0]):
        return ["that address is not on a private network; nothing was sent"]
    path = key_path(key_dir, role)
    if not path.exists():
        return ["no key file here; run enrollment first"]
    s = make_session(verify, pin)
    step = "signing in"
    try:
        page = s.get(f"{base_url}/", timeout=timeout)
        form = hidden_fields(page.text)
        form.update({"usernamefld": username, "passwordfld": password, "login": "1"})
        after = s.post(f"{base_url}/", data=form, timeout=timeout)
        if not logged_in(after.text):
            return ["web sign-in did not work; nothing was changed"]
        token = csrf_token(after.text) or csrf_token(
            s.get(f"{base_url}/index.php", timeout=timeout).text)
        if token is None:
            return ["no change token found; nothing was changed"]
        step = "finding the user"
        rows = s.get(f"{base_url}/api/auth/user/search", timeout=timeout).json().get("rows", [])
        uuid = next((x.get("uuid") for x in rows if isinstance(x, dict)
                     and x.get("name") == role.name), None)
        if not uuid:
            return [f"no user named {role.name}; nothing was changed"]
        role, left_off = trim_write_extras(role, _offered_privileges(s, base_url, timeout))
        if role.name == USER_NAME:          # the look-only account keeps the data pages it was widened with
            from dataclasses import replace
            role = replace(role, permissions=role.permissions + tuple(
                p for p in DATA_PERMISSIONS if p not in role.permissions and p not in left_off))
        if not _approved(gate, "set-user-permissions", role, {},
                         [f"Set the permissions of the firewall user {role.name}",
                          "Permissions: " + ", ".join(role.permissions)]):
            return ["not approved with a passkey; nothing was changed"]
        step = "setting permissions"
        r = s.post(f"{base_url}/api/auth/user/set/{uuid}",
                   json={"user": {"priv": ",".join(role.permissions)}},
                   headers={"X-CSRFToken": token, "X-Requested-With": "XMLHttpRequest"},
                   timeout=timeout)
        out = [f"set permissions: {shape(r)}"]
        if left_off:
            out.append("this firewall does not list these permissions, so they are left off: " + ", ".join(left_off))
        k = re.search(r"^key=(\S+)", path.read_text(encoding="utf-8"), re.M)
        sec = re.search(r"^secret=(\S+)", path.read_text(encoding="utf-8"), re.M)
        if k and sec:
            out += check_key(base_url, (k.group(1), sec.group(1)), verify, timeout, pin)
        return out
    except Exception as exc:
        return [f"stopped while {step}: {type(exc).__name__}"]


def check_key(base_url: str, pair: tuple[str, str], verify, timeout: float = 10,
              pin: str | None = None):
    out = []
    s = make_session(verify, pin)  # ignores proxy settings; pin if given
    s.auth = pair
    for label, p in READ_PATHS:
        try:
            r = s.get(f"{base_url}{p}", timeout=timeout)
            out.append(f"read {label} with the new key: {shape(r)}")
        except Exception as exc:
            out.append(f"read {label} with the new key: {type(exc).__name__}")
    return out


def passkey_step(key_dir: Path, say=print, ask=input, serve=None) -> bool:
    """Right after enrollment: set up the passkey that approves every change.

    True when a passkey is registered by the end (now or already). The
    firewall enrollment stands either way; without a passkey nothing can be
    changed, and the printed command finishes the job later.
    """
    from pazuzu_core import passkey as pk
    from pazuzu_core import passkey_server as ps

    later = "python -m pazuzu_core.passkey_server register"
    if not pk.HAVE_CRYPTO:
        say("Passkeys need the 'cryptography' package: pip install cryptography")
        say(f"Then run: {later}")
        return False
    try:
        if pk.load_credentials(Path(key_dir) / pk.CREDENTIALS_FILE):
            say("A passkey is already registered on this device.")
            return True
        say("Next: your passkey. It approves every change to the firewall.")
        say("If you lose it, you reset the firewall and set up again.")
        if ask("Press Enter to set it up now, or type skip: ").strip().lower() == "skip":
            say(f"Skipped. When you are ready, run: {later}")
            return False
        done = (serve or ps.serve_until)("register", Path(key_dir), say=say)
    except (pk.PasskeyError, OSError) as exc:
        say(f"The passkey step could not run: {exc}")
        say(f"When you are ready, run: {later}")
        return False
    say("Passkey registered." if done else
        f"No passkey yet. When you are ready, run: {later}")
    return bool(done)


def main(argv: list[str] | None = None) -> int:
    from pazuzu_core.firewall_rule_audit_cli import _quiet_lab_tls_warnings
    from pazuzu_core.opnsense_client import _base_url, _tls_setting

    _quiet_lab_tls_warnings()
    base, verify = _base_url(), _tls_setting()
    key_dir = Path.home() / ".pazuzu"
    if not host_is_private(base_host_port(base)[0]):
        print("that address is not on a private network; nothing was sent")
        return 1
    pin = None
    if verify is False and base.startswith("https://"):
        try:
            pin = trust_flow(base, key_dir)
        except OSError as exc:
            print(f"could not reach the firewall ({type(exc).__name__})")
            return 1
        if pin is None:
            print("not trusted; nothing was sent")
            return 1
    args = argv if argv is not None else sys.argv[1:]
    role = WRITE if "--write" in args else READ
    changing_permissions = "--permissions" in args
    gate = None
    if role.needs_passkey or changing_permissions:
        # These are changes to the firewall: a passkey must already exist.
        # Checked before the root password is asked for.
        from pazuzu_core import passkey as pk
        from pazuzu_core.passkey_gate import NO_PASSKEY, default_gate
        try:
            have = bool(pk.load_credentials(key_dir / pk.CREDENTIALS_FILE))
        except pk.PasskeyError as exc:
            print(f"The passkey file could not be read: {exc}")
            return 1
        if not have:
            print(NO_PASSKEY)
            return 1
        gate = default_gate(key_dir)
    password = getpass.getpass("Root password for this firewall: ")
    if changing_permissions:
        for line in set_permissions(base, password, verify, key_dir, pin=pin,
                                    role=role, gate=gate):
            print(line)
        return 0

    def confirm(perms, exists=False):
        if exists:
            print(f"The user {role.name} already exists. This will only add a key to it.")
            return input("Type yes to continue: ").strip().lower() == "yes"
        print(f"This will create one user, {role.name}, with these permissions:")
        for p in perms:
            print("  -", p)
        return input("Type yes to continue: ").strip().lower() == "yes"

    lines = enroll(base, password, verify, key_dir, confirm, pin=pin,
                   role=role, gate=gate)
    for line in lines:
        print(line)
    saved = any(l == "key file saved" for l in lines)
    if saved and pin and load_pin(key_dir) != pin:
        save_pin(key_dir, pin)
    if saved and role is READ:
        passkey_step(key_dir)
    return 0 if saved else 1


if __name__ == "__main__":
    sys.exit(main())
