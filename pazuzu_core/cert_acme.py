"""A certificate for the home's name (the dynamic DNS name), from Let's Encrypt, renewed by the firewall itself.

It is done with the firewall's own ACME plugin (os-acme-client), set the way the baseline wants:

  - A DuckDNS name (the one the setup page offers) is proved through DNS (DNS-01): the plugin puts a short text record
    at DuckDNS with the same token the name itself uses, Let's Encrypt reads it, and the record is removed. Nothing is
    opened on the internet side at all, so it works behind another router too, and alongside a port forward of the
    person's own (BUILD 430: a WordPress box on the DMZ had port 80 and 443 forwarded, so a check over port 80 would
    have landed on WordPress). The firewall never gives a token back once saved, so the sheet asks for it once more.
  - Any other name is proved over HTTP (HTTP-01). The plugin opens port 80 on the internet side ONLY while Let's
    Encrypt checks, with a temporary forward to its own small web server, and closes it again straight after. That
    cannot work while port 80 or 443 is forwarded to a box of the person's own, and the sheet says so.
  - Renewal is automatic, on the firewall's own scheduler (every 60 days, as the plugin does by default).

What is made, each with a name starting "Pazuzu" so it is found again and never confused with the person's own: an
account at Let's Encrypt, the HTTP-01 check, and the certificate. The plugin's settings are switched on (and the
renewal job added). Each step can be taken back. The request itself (Let's Encrypt checking the name) is not a step:
it is asked for after, and waited on, and what it says is said plainly.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Callable

from pazuzu_core import write_engine as we
from pazuzu_core.passkey_gate import plan_digest
from pazuzu_core.wifi_backup import Plan, Step
from pazuzu_core.zone_vlans import ZoneVlans

PLUGIN = "os-acme-client"
A = "/api/acmeclient"
ACCOUNT_NAME = "Pazuzu"
CHECK_NAME = "Pazuzu HTTP-01"
CHECK_DNS_NAME = "Pazuzu DNS-01 (DuckDNS)"
DESCRIPTION = "Pazuzu: the home's name, proved over port 80 only while it renews"
DNS_DESCRIPTION = "Pazuzu: the home's name, proved through DuckDNS with its own token"
DUCK = ".duckdns.org"
CHECK_GD_NAME = "Pazuzu DNS-01 (GoDaddy)"
GD_DESCRIPTION = "Pazuzu: the home's name, proved through GoDaddy's DNS with its API key"
ACTION_NAME = "Pazuzu: restart the admin page"    # BUILD 471: a renewed certificate is loaded by the page at once
WAIT = 240.0                # seconds to wait for Let's Encrypt
STATUS = {"100": "waiting", "200": "issued", "250": "waiting", "300": "set up wrongly", "400": "refused",
          "500": "stopped with an error"}
_NAME = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_TOKEN = re.compile(r"^[A-Za-z0-9-]{16,80}$")                 # a DuckDNS token is a UUID-shaped string


def clean_name(name: Any) -> str:
    n = str(name or "").strip().lower().rstrip(".")
    if not _NAME.match(n):
        raise we.WriteError("The home's name is not set up yet (Dynamic DNS first), so there is no name to get a "
                            "certificate for. Nothing was changed.")
    return n


def method_for(name: str, service: str = "") -> str:
    """"dns01" for a DuckDNS name (its token proves it, nothing opened), "dns01gd" for a name kept at GoDaddy (its API key
    proves it, nothing opened; BUILD 471), "http01" for any other."""
    if str(name or "").lower().rstrip(".").endswith(DUCK):
        return "dns01"
    if "godaddy" in str(service or "").lower():
        return "dns01gd"
    return "http01"


def port80_taken(forwards: Any) -> list[str]:
    """The person's forwards that would catch Let's Encrypt's HTTP check (port 80, or 443): their names, from
    forwards.forwards rows. Empty when the check over port 80 can reach the firewall."""
    out = []
    for f in forwards if isinstance(forwards, list) else []:
        ports = {p.strip() for p in str((f or {}).get("ports") or "").replace("-", ",").split(",")}
        if ports & {"80", "443", "http", "https"}:
            out.append(str(f.get("descr") or f.get("target") or "?"))
    return sorted(set(out))


def behind_another_router(wan_addr: str) -> bool:
    """True when the firewall's internet side has a private or shared address: Let's Encrypt cannot reach port 80 on
    it without a forward on the router in front, which this app cannot make."""
    try:
        ip = ipaddress.ip_address(str(wan_addr).split("/")[0])
    except ValueError:
        return False
    return ip.is_private or ip in ipaddress.ip_network("100.64.0.0/10")


def _row(rows: list, key: str, value: str) -> dict | None:
    hit = [r for r in rows if isinstance(r, dict) and str(r.get(key) or "").strip().lower() == value.lower()]
    return hit[0] if hit else None


def read(getter: Callable[[str], Any], name: str) -> dict:
    """What the firewall has for `name`, reads only: {"plugin", "cert": {uuid, status, words, renews, http01}|None}."""
    try:
        got = getter(A + "/settings/get")
    except Exception:
        return {"plugin": False, "cert": None}
    if not isinstance(got, dict) or "acmeclient" not in got:
        return {"plugin": False, "cert": None}
    try:
        rows = (getter(A + "/certificates/search?rowCount=-1&searchPhrase=") or {}).get("rows") or []
        checks = (getter(A + "/validations/search?rowCount=-1&searchPhrase=") or {}).get("rows") or []
    except Exception:
        return {"plugin": True, "cert": None}
    row = _row(rows, "name", name)
    if row is None:
        return {"plugin": True, "cert": None}
    settings = got["acmeclient"].get("settings") if isinstance(got["acmeclient"], dict) else {}
    on = lambda v: str(v if not isinstance(v, dict) else "") in ("1", "true", "True")
    check = next((c for c in checks if isinstance(c, dict) and str(c.get("uuid")) == str(row.get("validationMethod"))), None)
    code = str(row.get("statusCode") or "")
    method = str((check or {}).get("method") or "").lower()
    return {"plugin": True, "cert": {
        "uuid": str(row.get("uuid") or ""), "status": code, "words": STATUS.get(code, "not asked for yet"),
        "issued": code == "200", "enabled": on(row.get("enabled", "1")),
        "renews": on(row.get("autoRenewal", "1")) and on((settings or {}).get("autoRenewal")) and on((settings or {}).get("enabled")),
        "http01": check is None or "http" in method, "method": "dns01" if "dns" in method else "http01" if check else ""}}


class CertSetup(ZoneVlans):
    """The plan: plugin switched on with renewals, the account, the HTTP-01 check, the certificate. Then ask."""

    def plan(self, name: str, email: str = "", token: str = "", service: str = "", gd_key: str = "",  # type: ignore[override]
             gd_secret: str = "") -> Plan:
        name = clean_name(name)
        method = method_for(name, service)
        token = str(token or "").strip()
        gd_key, gd_secret = str(gd_key or "").strip(), str(gd_secret or "").strip()
        if method == "dns01" and not (token and _TOKEN.match(token)):
            raise we.WriteError("A DuckDNS name is proved with its token. Type the same token you gave for the name "
                                "(the firewall never gives it back). Nothing was changed.")
        if method == "dns01gd" and not (re.fullmatch(r"[A-Za-z0-9_]{8,80}", gd_key)
                                        and re.fullmatch(r"[A-Za-z0-9_]{8,80}", gd_secret)):
            raise we.WriteError("A GoDaddy name is proved with your GoDaddy API key and its secret (a Production key). "
                                "Type both; the firewall never gives them back. Nothing was changed.")
        try:
            self._form(A + "/settings/get")
        except we.WriteError:
            raise we.WriteError("The certificate plugin (os-acme-client) is not on the firewall yet. Install it first. "
                                "Nothing was changed.")
        accounts = self._rows(A + "/accounts/search")
        checks = self._rows(A + "/validations/search")
        certs = self._rows(A + "/certificates/search")
        check_name = {"dns01": CHECK_DNS_NAME, "dns01gd": CHECK_GD_NAME}.get(method, CHECK_NAME)
        acc, chk, crt = _row(accounts, "name", ACCOUNT_NAME), _row(checks, "name", check_name), _row(certs, "name", name)
        try:
            act, has_actions = _row(self._rows(A + "/actions/search"), "name", ACTION_NAME), True
        except we.WriteError:
            act, has_actions = None, False          # an older plugin with no automations: renewals then need a restart
        steps = [Step("acme-settings", self._do_settings)]
        lines = [f"A certificate for {name}, from Let's Encrypt, renewed by the firewall itself",
                 "Switch on the firewall's certificate plugin, with automatic renewal on its own scheduler"]
        facts: dict = {"name": name, "method": method, "account": str(acc.get("uuid")) if acc else "",
                       "check": str(chk.get("uuid")) if chk else "", "cert": str(crt.get("uuid")) if crt else "",
                       "action": str(act.get("uuid")) if act else ""}
        if not act and has_actions:
            lines.append("A renewal step that restarts the admin page, so a renewed certificate is used at once")
            steps.append(Step("acme-action", lambda: self._do_action(facts)))
        if not acc:
            lines.append("An account at Let's Encrypt, called Pazuzu" + (f" ({email})" if email else ""))
            steps.append(Step("acme-account", lambda: self._do_account(facts, email)))
        if chk and method == "dns01":
            # BUILD 471: a check already there takes the token just typed (a wrong one typed before could never be fixed)
            lines.append("Give the DuckDNS check the token you just typed")
            steps.append(Step("acme-check-token", lambda: self._do_check_update(
                facts, {"dns_service": "dns_duckdns", "dns_duckdns_token": token}, ("dns_duckdns_token",))))
        elif chk and method == "dns01gd":
            lines.append("Give the GoDaddy check the API key and secret you just typed")
            steps.append(Step("acme-check-key", lambda: self._do_check_update(
                facts, {"dns_service": "dns_gd", "dns_gd_key": gd_key, "dns_gd_secret": gd_secret},
                ("dns_gd_key", "dns_gd_secret"))))
        if not chk:
            if method == "dns01gd":
                lines.append("Prove the name through GoDaddy's DNS: a short text record put there with your API key while "
                             "Let's Encrypt checks, then removed. Nothing is opened on the internet side")
                steps.append(Step("acme-check", lambda: self._do_gd_check(facts, gd_key, gd_secret)))
            elif method == "dns01":
                lines.append("Prove the name through DuckDNS: a short text record put there with your token while Let's "
                             "Encrypt checks, then removed. Nothing is opened on the internet side")
                steps.append(Step("acme-check", lambda: self._do_dns_check(facts, token)))
            else:
                lines.append("Prove the name over HTTP: port 80 is opened on the internet side only while Let's Encrypt "
                             "checks, and closed straight after")
                steps.append(Step("acme-check", lambda: self._do_check(facts)))
        if not crt:
            lines.append(f"The certificate for {name}, renewed every 60 days")
            steps.append(Step("acme-cert", lambda: self._do_cert(facts)))
        else:
            # Always point the row at this kind's check and at the restart step (BUILD 471): a row made before either
            # existed, or for another kind of name, is brought in line. A no-op when it already is.
            lines.append("Point the certificate at that check and at the restart step")
            steps.append(Step("acme-cert-check", lambda: self._do_cert_check(facts)))   # after the check step: facts["check"] is set
        lines.append("Then ask Let's Encrypt for it and wait for the answer (up to four minutes)")
        lines.append("It uses the installer account, which can open every page")
        return Plan(steps, lines, plan_digest("acme-cert", {"name": name, "email": email, "method": method,
                                                            "typed": bool(token or gd_key),
                                                            "have": [bool(acc), bool(chk), bool(crt)]}), "", facts)

    # -- the steps
    def _do_settings(self) -> Callable[[], None]:
        _w, form = self._form(A + "/settings/get")
        s = form.get("settings") if isinstance(form.get("settings"), dict) else {}
        flat = lambda v: we._value_of(v) if we._option_labels(v) is not None else str(v or "")
        was = {k: flat(s.get(k)) for k in ("enabled", "autoRenewal")}
        res = self._call("post", A + "/settings/set", json={"acmeclient": {"settings": {"enabled": "1", "autoRenewal": "1"}}})
        if not (isinstance(res, dict) and str(res.get("result")) == "saved"):
            raise we.WriteError("The certificate plugin did not take its settings." + we._error_words(res))
        try:
            self._call("post", A + "/settings/fetch_cron_integration", json={})
        except we.WriteError:
            self.said.append("The renewal job could not be added just now; the plugin adds it when its settings are "
                             "saved on its own page.")
        self._reconfigure(A + "/service/reconfigure")

        def back() -> None:
            got = self._call("post", A + "/settings/set", json={"acmeclient": {"settings": was}})
            if not (isinstance(got, dict) and str(got.get("result")) == "saved"):
                raise we.WriteError("The certificate plugin would not put its settings back. Look at Services, ACME Client.")
            self._reconfigure(A + "/service/reconfigure")
        return back

    def _add(self, kind: str, changes: dict, what: str, optional=(), free=()) -> str:
        wrapper, form = self._form(f"{A}/{kind}s/get")
        res, _b = self._post_form(f"{A}/{kind}s/add", wrapper, form, changes, what, optional=optional, free=free)
        uuid = str(res.get("uuid", ""))
        if not we._UUID.match(uuid):
            raise we.WriteError(f"The firewall saved {what} but did not say which row it is. Look at Services, ACME Client.")
        return uuid

    def _del(self, kind: str, uuid: str, what: str) -> Callable[[], None]:
        def back() -> None:
            got = self._call("post", f"{A}/{kind}s/del/{uuid}", json={})
            if not (isinstance(got, dict) and str(got.get("result")) == "deleted"):
                raise we.WriteError(f"The firewall would not remove {what}. Look at Services, ACME Client.")
        return back

    def _do_account(self, facts: dict, email: str) -> Callable[[], None]:
        changes = {"name": ACCOUNT_NAME, "description": DESCRIPTION, "ca": "letsencrypt", "enabled": "1"}
        if email:
            changes["email"] = email
        uuid = self._add("account", changes, "the Let's Encrypt account", optional=("description", "enabled"))
        facts["account"] = uuid
        return self._del("account", uuid, "the Let's Encrypt account")

    def _do_check(self, facts: dict) -> Callable[[], None]:
        changes = {"name": CHECK_NAME, "description": DESCRIPTION, "method": "http01", "http_service": "opnsense",
                   "http_opn_autodiscovery": "1", "http_opn_interface": "wan", "enabled": "1"}
        uuid = self._add("validation", changes, "the HTTP-01 check",
                         optional=("description", "enabled", "http_opn_interface"))
        facts["check"] = uuid
        return self._del("validation", uuid, "the HTTP-01 check")

    def _do_dns_check(self, facts: dict, token: str) -> Callable[[], None]:
        changes = {"name": CHECK_DNS_NAME, "description": DNS_DESCRIPTION, "method": "dns01", "dns_service": "dns_duckdns",
                   "dns_duckdns_token": token, "enabled": "1"}
        uuid = self._add("validation", changes, "the DNS-01 check (DuckDNS)",
                         optional=("description", "enabled"), free=("dns_duckdns_token",))
        facts["check"] = uuid
        return self._del("validation", uuid, "the DNS-01 check")

    def _do_gd_check(self, facts: dict, key: str, secret: str) -> Callable[[], None]:
        changes = {"name": CHECK_GD_NAME, "description": GD_DESCRIPTION, "method": "dns01", "dns_service": "dns_gd",
                   "dns_gd_key": key, "dns_gd_secret": secret, "enabled": "1"}
        uuid = self._add("validation", changes, "the DNS-01 check (GoDaddy)",
                         optional=("description", "enabled"), free=("dns_gd_key", "dns_gd_secret"))
        facts["check"] = uuid
        return self._del("validation", uuid, "the DNS-01 check")

    def _do_check_update(self, facts: dict, changes: dict, free) -> Callable[[], None]:
        uuid = facts["check"]
        back = self._change(f"{A}/validations/get/{uuid}", f"{A}/validations/update/{uuid}", changes,
                            "the check", free=tuple(free))
        self._reconfigure(A + "/service/reconfigure")
        return back

    def _do_action(self, facts: dict) -> Callable[[], None]:
        uuid = self._add("action", {"name": ACTION_NAME, "description": "Pazuzu: the admin page loads a renewed "
                                    "certificate", "type": "configd_restart_gui", "enabled": "1"},
                         "the restart step", optional=("description", "enabled"))
        facts["action"] = uuid
        return self._del("action", uuid, "the restart step")

    def _do_cert_check(self, facts: dict) -> Callable[[], None]:
        """The certificate row already there, pointed at the check made for this kind of name, and at the restart step.
        The plugin's own page saves a row with update/ (BUILD 471: it had been sent to set/, which it does not have)."""
        changes = {"validationMethod": facts["check"], "description": _describe(facts)}   # BUILD 473: words follow the kind
        if facts.get("action"):
            changes["restartActions"] = facts["action"]
        back = self._change(f"{A}/certificates/get/{facts['cert']}", f"{A}/certificates/update/{facts['cert']}",
                            changes, "the certificate's check", free=("restartActions",), optional=("description",))
        self._reconfigure(A + "/service/reconfigure")
        return back

    def _do_cert(self, facts: dict) -> Callable[[], None]:
        changes = {"name": facts["name"], "description": _describe(facts), "account": facts["account"],
                   "validationMethod": facts["check"], "autoRenewal": "1", "keyLength": "key_ec256", "enabled": "1"}
        if facts.get("action"):
            changes["restartActions"] = facts["action"]
        uuid = self._add("certificate", changes, "the certificate",
                         optional=("description", "enabled", "keyLength", "restartActions"), free=("restartActions",))
        facts["cert"] = uuid
        self._reconfigure(A + "/service/reconfigure")
        return self._del("certificate", uuid, "the certificate")

    # -- after the steps: ask for it, and wait
    def request(self, facts: dict, sleep: Callable[[float], None] = time.sleep,
                clock: Callable[[], float] = time.monotonic, wait: float = WAIT,
                say: Callable[[str], None] = print) -> dict:
        uuid = facts.get("cert") or ""
        if not we._UUID.match(uuid):
            raise we.WriteError("There is no certificate row to ask for. Nothing more was done.")
        if facts.get("account"):
            try:
                self._call("post", f"{A}/accounts/register/{facts['account']}", json={})
            except we.WriteError:
                pass                                     # signing registers it too
        say("Asking Let's Encrypt. The firewall puts the proof at GoDaddy, then removes it." if facts.get("method") == "dns01gd"
            else "Asking Let's Encrypt. The firewall puts the proof at DuckDNS, then removes it." if facts.get("method") == "dns01"
            else "Asking Let's Encrypt. The firewall opens port 80 for its check, then closes it again.")
        # BUILD 473: the row keeps the last run's answer until this run ends (prod: a "refused" from 13:21 was read 5 s
        # after asking again at 13:37, while acme.sh still waited for DNS; the run then issued it). So the answer only
        # counts once the row says this run ended: its last-run time (or status) differs from before asking.
        before = _run_mark(next((r for r in self._rows(A + "/certificates/search") if str(r.get("uuid")) == uuid), None))
        self._call("post", f"{A}/certificates/sign/{uuid}", json={})
        end = clock() + wait
        sleep(5.0)
        while True:
            rows = self._rows(A + "/certificates/search")
            row = next((r for r in rows if str(r.get("uuid")) == uuid), None)
            code = str((row or {}).get("statusCode") or "")
            if row is not None and _run_mark(row) == before and code != "100":
                code = ""                                        # still the last run's answer: keep waiting
            if code == "200":
                say("Let's Encrypt issued it." + ("" if str(facts.get("method", "")).startswith("dns01") else " Port 80 is closed again."))
                refid = ""
                try:                                     # BUILD 471: where it sits in the firewall's store
                    _w, form = self._form(f"{A}/certificates/get/{uuid}")
                    refid = str(form.get("certRefId") or "").strip()
                except we.WriteError:
                    pass
                return {"issued": True, "status": code, "method": facts.get("method"), "refid": refid}
            if code in ("300", "400", "500"):
                return {"issued": False, "status": code, "why": STATUS[code], "method": facts.get("method")}
            if clock() >= end:
                return {"issued": False, "status": code or "", "why": "no answer yet", "method": facts.get("method")}
            say("Waiting for Let's Encrypt…")
            sleep(10.0)


def _describe(facts: dict) -> str:
    """The certificate row's words, by how the name is proved (every row had said port 80, even a DNS-proved one)."""
    return {"dns01": DNS_DESCRIPTION, "dns01gd": GD_DESCRIPTION}.get(str(facts.get("method") or ""), DESCRIPTION)


def _run_mark(row: Any) -> tuple:
    """What changes when a run ends: the status and the times of the last run and of the last issue."""
    row = row if isinstance(row, dict) else {}
    return tuple(str(row.get(k) or "") for k in ("statusCode", "statusLastUpdate", "lastUpdate"))


def outcome_words(name: str, got: dict) -> list[str]:
    if got.get("issued"):
        return [f"The certificate for {name} is issued. The firewall renews it by itself"
                + ("; nothing is ever opened for that." if str(got.get("method", "")).startswith("dns01") else "; port 80 opens only then."),
                "It is under System, Trust, Certificates."]
    if got.get("why") == "no answer yet":
        return [f"Let's Encrypt has not answered yet for {name}. The firewall keeps trying; look again in a few minutes "
                "(Services, ACME Client, Certificates)."]
    if got.get("method") == "dns01gd":
        return [f"Let's Encrypt did not issue it ({got.get('why')}).",
                f"The proof goes to GoDaddy with your API key: it has to be a Production key for the account that holds "
                f"{name}, and GoDaddy's API has to be reachable from the firewall.",
                "What happened is in Services, ACME Client, Log Files. Everything set up stays, so asking again is one press."]
    if got.get("method") == "dns01":
        return [f"Let's Encrypt did not issue it ({got.get('why')}).",
                f"The proof goes to DuckDNS with your token: the token has to be the one for {name}, and DuckDNS has to "
                "be reachable from the firewall.",
                "What happened is in Services, ACME Client, Log Files. Everything set up stays, so asking again is one press."]
    return [f"Let's Encrypt did not issue it ({got.get('why')}).",
            f"It has to reach port 80 at {name} from the internet: the name has to point at this firewall's internet "
            "address, and nothing in front of the firewall may block port 80.",
            "What happened is in Services, ACME Client, Log Files. Everything set up stays, so asking again is one press."]
