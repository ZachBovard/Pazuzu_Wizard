"""Find and install plugins on the firewall through its own API.

Only plugins on a short closed list of names can be listed or installed, and
only if the firewall itself lists them. Every call here uses the installer
account's key, which the caller loads and passes in.
"""
from __future__ import annotations

import re
import time


# Words a plugin name must contain to be offered at all.
ALLOWED_HINTS = ("zenarmor", "sunnyvalley", "sensei", "pazuzu", "hanbi")
# Installable by name (the changing-address name service), but never offered in the plugin list.
INSTALL_ONLY_HINTS = ("ddclient",)
_NAME = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,80}$")


class PluginError(Exception):
    """A problem the person can read."""


class NoAnswer(PluginError):
    """The firewall did not answer (or cut its answer off). A big install can do that for a while: it is not a refusal."""


def _refused(code: int, path: str) -> "PluginError":
    """401: the firewall does not know the key at all (reset or reinstalled since it was made). 403: it knows the account,
    which may not open that page. The page's path is said (never a key), so it is clear what was refused."""
    where = str(path).split("?")[0][:80]
    if code == 401:
        return PluginError("The firewall did not accept the installer account's key (" + where + "). The installer account "
                           "closes itself a day after it is made, and a reset or reinstalled firewall has never heard of it. "
                           "Make the installer account again on the setup page's Sign in step, then try again.")
    return PluginError("The installer account is not allowed to open " + where + " on this firewall. Its rights may have "
                       "changed with an update: on the firewall, System, Access, Users, check that the installer account "
                       "still has every page.")


def _allowed(name: str, hints=ALLOWED_HINTS) -> bool:
    low = name.lower()
    return bool(_NAME.fullmatch(low)) and any(h in low for h in hints)


def _lenient_json(session, base, path, timeout):
    """Read the body as it arrives and use whatever came, even when the firewall
    breaks the chunked framing at the very end (some do on large answers)."""
    r = session.get(base + path, timeout=timeout, stream=True,
                    headers={"Accept-Encoding": "identity"})
    if r.status_code in (401, 403):
        raise _refused(r.status_code, path)
    chunks = []
    try:
        for part in r.iter_content(8192):
            chunks.append(part)
    except Exception:
        pass                                   # keep what arrived
    import json
    text = b"".join(chunks).decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        rows = salvage_rows(text)
        if rows:
            return {"package": rows, "cut_off": True}   # the end was lost; the rows that arrived are real
        raise


_ROW = re.compile(r'\{[^{}]*"name"\s*:\s*"(os-[^"]+)"[^{}]*\}')


def salvage_rows(text: str) -> list[dict]:
    """Package rows from a package list that was cut off part-way: every complete {...} row that arrived whole."""
    import json
    rows = []
    for m in _ROW.finditer(text):
        try:
            row = json.loads(m.group(0))
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


# What the firewall's package log says when it finished (***DONE***) without installing anything.
_REFUSALS = (
    (re.compile(r"update to (opnsense-)?[0-9][0-9.]* is required|installation out of date", re.I),
     "The firewall will not install anything until it is updated{v}. Update it under System, Firmware, Updates "
     "(it may restart), then press Install again. Pazuzu did not update it for you."),
    (re.compile(r"no packages? (available|matching|found)|unable to find|not found in (the )?repositor", re.I),
     "The firewall's package sources do not have that package. Check its sources under System, Firmware, "
     "then press Install again."),
    (re.compile(r"\b(failed|fatal|cannot|can't|error:)\b", re.I),
     "The firewall started the install but reported a problem. Its Firmware page has the log."),
)


def refusal(log: str) -> str:
    """Plain words when the log shows the install did not happen, else an empty string."""
    for pattern, text in _REFUSALS:
        m = pattern.search(log or "")
        if m:
            ver = re.search(r"update to (?:opnsense-)?([0-9][0-9.]*[0-9])", log or "", re.I)
            return text.replace("{v}", f" to {ver.group(1)}" if ver else "")
    return ""


def _get(session, base, path, timeout):
    """GET and decode. A cut-off answer (the package list is large) is retried
    once with the plain body, then read piece by piece keeping what arrived."""
    attempts = ({}, {"Accept-Encoding": "identity", "Connection": "keep-alive"})
    last = None
    for extra in attempts:
        try:
            r = session.get(base + path, timeout=timeout, headers=extra or None)
        except Exception as exc:                  # cut off or reset mid-answer
            last = exc
            continue
        if r.status_code in (401, 403):
            raise _refused(r.status_code, path)
        try:
            return r.json()
        except ValueError:
            last = ValueError("not JSON")
    try:
        return _lenient_json(session, base, path, timeout)
    except PluginError:
        raise
    except Exception:
        pass
    raise NoAnswer("The firewall's answer was cut off or not understood. Press Check again."
                   f" ({type(last).__name__})")


def _post(session, base, path, timeout):
    r = session.post(base + path, timeout=timeout,
                     headers={"X-Requested-With": "XMLHttpRequest"})
    if r.status_code in (401, 403):
        raise _refused(r.status_code, path)
    try:
        return r.json()
    except ValueError:
        raise PluginError("The firewall's answer was not understood.")


def list_plugins(session, base: str, timeout: float = 20, hints=ALLOWED_HINTS, need: str | None = None) -> list[dict]:
    """Closed-list plugins the firewall says it can install."""
    data = _get(session, base, "/api/core/firmware/info", timeout)
    found, seen = [], set()
    for key in ("plugin", "package"):
        rows = data.get(key) if isinstance(data, dict) else None
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "")
            if name in seen or not _allowed(name, hints):
                continue
            seen.add(name)
            installed = str(row.get("installed", "0")).lower() in ("1", "true", "yes")
            found.append({"name": name, "version": str(row.get("version") or ""),
                          "comment": str(row.get("comment") or "")[:200],
                          "installed": installed})
    if need and isinstance(data, dict) and data.get("cut_off") and need not in seen:
        raise NoAnswer("The firewall's package list was cut off before the part that has this package. "
                       "Going step by step instead.")
    return sorted(found, key=lambda r: r["name"])


def _try_list(session, base, timeout):
    """The set of listed names, or None when the (large) list could not be read at all."""
    try:
        return {p["name"] for p in list_plugins(session, base, timeout, ALLOWED_HINTS + INSTALL_ONLY_HINTS)}
    except PluginError:
        return None


BUSY = ("running", "busy", "upgrading", "inprogress", "in progress")
DONE = ("done", "ok", "success")
FAILED = ("error", "failed")


def _job_state(session, base, timeout):
    """(status, log) of the firewall's package job; (None, "") when it did not answer."""
    try:
        state = _get(session, base, "/api/core/firmware/upgradestatus", timeout)
    except NoAnswer:
        return None, ""
    if not isinstance(state, dict):
        return "", ""
    return str(state.get("status", "")).lower(), str(state.get("log", ""))


def _wait_idle(session, base, say, timeout, wait, poll, sleep) -> tuple[str, str]:
    """Do not start a package job on top of one that is still running (an earlier try, or the firewall's own page).
    Returns the (status, log) seen when it is idle, which is what a finished status is later compared with."""
    waited, told = 0.0, False
    while True:
        status, log = _job_state(session, base, timeout)
        if status not in BUSY:
            return status or "", log
        if not told:
            say("The firewall is still busy with another package job. Waiting for it to finish before starting.")
            told = True
        if waited >= wait:
            raise PluginError("The firewall is still busy with another package job (an earlier install, or one "
                              "started on its own Firmware page). Nothing new was started. Wait for it to finish, "
                              "then press Check again.")
        sleep(poll)
        waited += poll or 0.5


def _settle(session, base, say, timeout, wait, poll, sleep) -> None:
    """After a job: wait until the firewall answers again twice in a row. A big package restarts services, and
    starting the next step while it is down is how an install ends up on top of itself."""
    waited, good, told = 0.0, 0, False
    while good < 2 and waited <= wait:
        try:
            _get(session, base, "/api/core/firmware/status", timeout)
            good += 1
        except NoAnswer:
            good = 0
            if not told:
                say("The firewall is restarting some of its services. Waiting for it to answer again.")
                told = True
        if good < 2:
            sleep(poll)
            waited += poll or 0.5
    if good < 2:
        raise PluginError("The firewall did not answer again after the install. Check that it is up and its web "
                          "page opens, then press Check again. Nothing else was started.")


def _follow(session, base, say, timeout, wait, poll, sleep, before=("", ""), name: str = "") -> bool:
    """Follow the running package job until it finishes. A status of "done" left over from the job before this one
    does not count: it must have been seen running, or its log must differ from before (or name this package)."""
    waited, last, saw_running, silent_said = 0.0, "", False, False
    stale_wait = min(45.0, wait / 2)
    while waited <= wait:
        sleep(poll)
        waited += poll or 0.5
        status, log = _job_state(session, base, timeout)
        if status is None:                              # not answering: a big install can do that, so keep waiting
            if not silent_said:
                say("The firewall is not answering for a moment (a large install can do that). Still waiting.")
                silent_said = True
            continue
        if status in BUSY:
            saw_running = True
        tail = [ln for ln in log.splitlines() if ln.strip()][-1:] or [""]
        if tail[0] and tail[0] != last:
            last = tail[0]
            say(last[:160])
        if status in DONE:
            fresh = saw_running or (log and log != before[1]) or (name and name in log)
            if fresh or waited >= stale_wait:
                if name:
                    why = refusal(log)
                    if why:
                        raise PluginError(why)
                return True
            continue                                    # probably the last job's status: give this one time to start
        if status in FAILED:
            if saw_running or log != before[1] or waited >= stale_wait:
                return False
    raise PluginError("This is taking a long time. Check the firewall's Firmware page.")


def install(session, base: str, name: str, say=print, timeout: float = 30,
            wait: float = 600, poll: float = 3, sleep=time.sleep) -> bool:
    """Install one listed plugin and follow the firewall's progress."""
    names = _try_list(session, base, timeout)
    if names is not None and name not in names:
        raise PluginError("The firewall does not list that plugin.")
    if names is None:
        say("The firewall's package list could not be read, so the firewall itself will say if it has this one.")
    before = _wait_idle(session, base, say, timeout, wait, poll, sleep)
    say(f"Asking the firewall to install {name}")
    answer = _post(session, base, f"/api/core/firmware/install/{name}", timeout)
    if isinstance(answer, dict) and str(answer.get("status", "")).lower() in ("error", "failed"):
        raise PluginError("The firewall refused to start the install.")
    if not _follow(session, base, say, timeout, wait, poll, sleep, before, name):
        raise PluginError(f"The install of {name} did not finish. The firewall's own Firmware page has the log.")
    _settle(session, base, say, timeout, min(wait, 300), poll, sleep)
    say(f"{name} is installed.")
    return True


ZENARMOR_CHAIN = ("os-sunnyvalley", "os-sensei")   # the vendor's source first, then Zenarmor


def refresh(session, base: str, say=print, timeout: float = 30, wait: float = 180,
            poll: float = 3, sleep=time.sleep) -> None:
    """Ask the firewall to check its sources again, so a newly added one is listed."""
    before = _wait_idle(session, base, say, timeout, wait, poll, sleep)
    say("Asking the firewall to check its package sources")
    _post(session, base, "/api/core/firmware/check", timeout)
    if not _follow(session, base, say, timeout, wait, poll, sleep, before):
        raise PluginError("The firewall could not check its package sources.")


def install_chain(session, base: str, names, say=print, timeout: float = 30,
                  wait: float = 600, poll: float = 3, sleep=time.sleep) -> None:
    """Install each package in order, checking the sources again when one is not
    listed yet (adding a vendor source makes its packages appear)."""
    for name in names:
        try:
            listed = {p["name"]: p for p in list_plugins(session, base, timeout, need=name)}
        except PluginError:
            listed = None                         # the list is too big for this firewall to send: go step by step
        if listed is None:
            say("The package list could not be read. Going step by step; the firewall will say if it lacks something.")
            install(session, base, name, say=say, timeout=timeout, wait=wait, poll=poll, sleep=sleep)
            if name != names[-1]:
                refresh(session, base, say, timeout, poll=poll, sleep=sleep)
            continue
        if name not in listed:
            refresh(session, base, say, timeout, poll=poll, sleep=sleep)
            listed = {p["name"]: p for p in list_plugins(session, base, timeout)}
        if name not in listed:
            raise PluginError(f"The firewall does not offer {name}, even after checking its sources. "
                          "If this firewall has no internet connection yet (a single cable to your computer gives it none), "
                          "it cannot download plugins: connect its internet port to your router and try again.")
        if listed[name]["installed"]:
            say(f"{name} is already installed.")
            continue
        install(session, base, name, say=say, timeout=timeout, wait=wait, poll=poll, sleep=sleep)


def _version_of(status) -> str:
    """The version the firewall says it is on, from its firmware status answer ("" when it does not say)."""
    if not isinstance(status, dict):
        return ""
    product = status.get("product") if isinstance(status.get("product"), dict) else {}
    return str(status.get("product_version") or product.get("product_version") or "")


def update(session, base: str, say=print, timeout: float = 30, wait: float = 1800,
           poll: float = 3, sleep=time.sleep) -> dict:
    """Run the firewall's own minor update (what System, Firmware, Update does) and follow it to the end.

    The firewall is asked to check first, so it knows what is newer. A major version change is not run from here:
    it restarts the firewall more than once and belongs on the firewall's own Firmware page. The firewall is never
    restarted from here either; the answer says whether it now asks for one. Returns {"reboot": bool}."""
    status = _get(session, base, "/api/core/firmware/status", timeout)
    v_before = _version_of(status)
    if isinstance(status, dict) and str(status.get("status", "")).lower() == "upgrade":
        raise PluginError("This is a change to a new major version. That belongs on the firewall's own page: System, "
                          "Firmware, Updates. Pazuzu does not run it.")
    try:
        refresh(session, base, say, timeout, min(wait, 300), poll, sleep)
    except PluginError:
        raise PluginError("The firewall could not check for updates. It may have no internet right now. "
                          "Connect its internet port to your router and try again.")
    before = _wait_idle(session, base, say, timeout, wait, poll, sleep)
    say("Asking the firewall to update itself")
    answer = _post(session, base, "/api/core/firmware/update", timeout)
    if isinstance(answer, dict) and str(answer.get("status", "")).lower() in FAILED:
        raise PluginError("The firewall refused to start the update.")
    if not _follow(session, base, say, timeout, wait, poll, sleep, before):
        # Some updates end with the firewall restarting itself, and its job report after that can read as a failure.
        # What counts is the version it is on now.
        say("The firewall's job report ended oddly. It may have restarted by itself. Checking its version instead.")
        try:
            _settle(session, base, say, timeout, min(wait, 600), poll, sleep)
            now = _get(session, base, "/api/core/firmware/status", timeout)
        except PluginError:
            now = None
        v_after = _version_of(now)
        if v_after and v_before and v_after != v_before:
            say(f"The firewall is now on version {v_after}.")
            return {"reboot": False, "version": v_after}
        raise PluginError("The update did not finish. The firewall's own Firmware page has the log.")
    _settle(session, base, say, timeout, min(wait, 300), poll, sleep)
    after = _get(session, base, "/api/core/firmware/status", timeout)
    reboot = isinstance(after, dict) and str(after.get("needs_reboot", "0")) in ("1", "true", "True")
    say("The update finished." + (" The firewall asks for a restart to finish it." if reboot else ""))
    return {"reboot": reboot}


def reboot(session, base: str, timeout: float = 30) -> None:
    """Ask the firewall to restart (POST /api/core/firmware/reboot). It goes away at once; the caller says so."""
    try:
        _post(session, base, "/api/core/firmware/reboot", timeout)
    except PluginError as exc:
        if "not understood" not in str(exc):          # a firewall that is already going down may not finish its answer
            raise
