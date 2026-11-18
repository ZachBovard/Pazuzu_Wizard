"""Finding and reading an OpenWrt access point on the home network. Read-only: nothing here changes the access point.

An OpenWrt device answers JSON-RPC at http://<address>/ubus. A fresh one has no root password, so a login with an
empty password works until one is set. This module only reads: the board and release, and the Wi-Fi and network settings.

Finding one: from the devices the firewall already knows (never a sweep of the network), keep the ones that could be an
access point (called "OpenWrt", or made by a maker that sells them) and ask each for the JSON-RPC answer. A name alone
proves nothing; the device has to answer like OpenWrt.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

NULL_SESSION = "0" * 32
TIMEOUT = 2.5
MAX_CANDIDATES = 12
MAX_REPLY = 1_000_000

TEST_SSID = "Test_IoT"      # the only network this build will change
APPLY_TIMEOUT = 90          # seconds the access point waits for a confirm before it puts the old settings back (seen: 90)
CONFIRM_FOR = 75.0          # how long we keep trying to confirm (less than APPLY_TIMEOUT, with room to spare): a network
                            # restart with VLANs can take most of a minute before the access point answers again
NO_DATA = 5                 # ubus status: nothing pending (a confirm after the timer already ran out)
DENIED = 6                  # ubus status: refused (also: another change is already waiting to be confirmed)
_SECTION = re.compile(r"^[A-Za-z0-9_]{1,64}$")

# Makers that sell access points and routers that OpenWrt runs on. A device with one of these (or the name "OpenWrt") is
# asked; everything else on the network is left alone.
AP_MAKERS = ("google", "tp-link", "tplink", "ubiquiti", "netgear", "linksys", "asus", "d-link", "gl technologies",
             "gl.inet", "xiaomi", "mercusys", "zyxel", "mikrotik", "buffalo", "belkin", "arcadyan", "ruijie", "cudy")
MAX_EVERYONE = 64           # BUILD 482: Hanbi's Wi-Fi step asks every device the box knows (named ones first), up to this
                            # (BUILD 488: 32 to 64, and the manager's search too: with 41 devices known, the access point was not asked)


class ApError(Exception):
    """A plain-words reason the access point could not be read."""


Post = Callable[[str, dict], Any]


def private_address(text) -> str | None:
    """The address as text if it is a private IPv4 address (only those are ever asked), else None."""
    try:
        a = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    return str(a) if a.version == 4 and a.is_private and not a.is_loopback and not a.is_link_local else None


# BUILD 556 (after a flash the browser landed on LuCI over https, so uhttpd may send http to
# https, "and a redirected /ubus would not give the wizard a JSON-RPC answer"): an access point that answers /ubus with
# a redirect to https on its own address is asked there instead. Its certificate is its own self-made one, so it is not
# checked: the same trust plain http has on the home network, and nothing leaves that address. Remembered for the run.
HTTPS_ONLY: set = set()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):                             # a redirect is looked at here, never followed blind
        return None


def _open(url: str, body: bytes, https: bool):
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    handlers: list = [_NoRedirect()]
    if https:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers).open(req, timeout=TIMEOUT)    # noqa: S310 (a private address, checked by the caller)


def _post(ip: str, payload: dict) -> Any:
    body = json.dumps(payload).encode("utf-8")
    if ip not in HTTPS_ONLY:
        try:
            with _open(f"http://{ip}/ubus", body, False) as r:
                return json.loads(r.read(MAX_REPLY).decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            where = str(exc.headers.get("Location") or "") if exc.code in (301, 302, 303, 307, 308) else ""
            if not re.match(r"https://\[?%s\]?(:443)?/" % re.escape(ip), where):
                raise
            HTTPS_ONLY.add(ip)
    with _open(f"https://{ip}/ubus", body, True) as r:
        return json.loads(r.read(MAX_REPLY).decode("utf-8", "replace"))


def _call(ip: str, post: Post, session: str, obj: str, method: str, args: dict | None = None) -> dict:
    """One ubus call. The data it returns, or ApError."""
    reply = post(ip, {"jsonrpc": "2.0", "id": 1, "method": "call", "params": [session, obj, method, args or {}]})
    if not isinstance(reply, dict):
        raise ApError("It did not answer like an OpenWrt device.")
    if reply.get("error"):
        raise ApError("It refused that read.")
    result = reply.get("result")
    if not isinstance(result, list) or not result:
        raise ApError("It did not answer like an OpenWrt device.")
    if result[0] != 0:
        raise ApError("It refused that read." if result[0] == 6 else "It could not give that.")
    return result[1] if len(result) > 1 and isinstance(result[1], dict) else {}


def identify(ip: str, post: Post | None = None) -> dict | None:
    """Does it answer like OpenWrt? {"no_password": bool} if so, None if not (or no answer at all)."""
    post = post or (lambda a, p: _post(a, p))
    try:
        reply = post(ip, {"jsonrpc": "2.0", "id": 1, "method": "call",
                          "params": [NULL_SESSION, "session", "login", {"username": "root", "password": ""}]})
    except Exception:
        return None
    if not isinstance(reply, dict) or not ("result" in reply or "error" in reply) or reply.get("jsonrpc") != "2.0":
        return None
    result = reply.get("result")
    return {"no_password": isinstance(result, list) and bool(result) and result[0] == 0}


NEEDS_PASSWORD = ("It asks for a password. Type its root password (the one for its own web page) to read it: it is used for "
                  "this read only and never kept.")
WRONG_PASSWORD = "That password was not accepted. Nothing was read."


def _login(ip: str, post: Post, password: str = "") -> str:
    """A session on the access point. The password, when one is given, is sent once to the access point and kept nowhere."""
    if not isinstance(password, str) or len(password) > 128 or any(ord(c) < 32 for c in password):
        raise ApError(WRONG_PASSWORD)
    try:
        data = _call(ip, post, NULL_SESSION, "session", "login", {"username": "root", "password": password})
    except ApError:
        raise ApError(WRONG_PASSWORD if password else NEEDS_PASSWORD)
    except Exception as exc:
        raise ApError(f"No answer from {ip} ({type(exc).__name__}).")
    session = data.get("ubus_rpc_session")
    if not isinstance(session, str) or not session:
        raise ApError("It did not give a session.")
    return session


# ----------------------------------------------------------------- plain words

_SECURITY = (("none", "Open: no password"), ("owe", "Open, encrypted"), ("sae-mixed", "WPA2/WPA3"), ("sae", "WPA3"),
             ("psk-mixed", "WPA/WPA2"), ("psk2", "WPA2"), ("psk", "WPA (old)"), ("wep", "WEP (broken)"),
             ("wpa3", "WPA3 with a server"), ("wpa2", "WPA2 with a server"), ("wpa", "WPA with a server"))


def security_words(encryption) -> str:
    enc = str(encryption or "none").lower().strip()
    for key, words in _SECURITY:
        if enc == key or enc.startswith(key + "+") or enc.startswith(key + "-"):
            return words
    return enc


def _band(sec: dict) -> str:
    band = str(sec.get("band") or "").lower()
    if band in ("2g", "5g", "6g"):
        return {"2g": "2.4 GHz", "5g": "5 GHz", "6g": "6 GHz"}[band]
    mode = str(sec.get("hwmode") or "").lower()
    if mode in ("11g", "11b"):
        return "2.4 GHz"
    if mode == "11a":
        return "5 GHz"
    try:
        return "5 GHz" if int(sec.get("channel")) > 14 else "2.4 GHz"
    except (TypeError, ValueError):
        return ""


def _is_on(sec: dict) -> bool:
    return str(sec.get("disabled") or "0").lower() not in ("1", "true", "yes", "on")


def summarise_wireless(values: Any) -> dict:
    """{"radios": [...], "networks": [...]} from the access point's wireless settings."""
    radios, networks = [], []
    for name, sec in (values.items() if isinstance(values, dict) else []):
        if not isinstance(sec, dict):
            continue
        kind = sec.get(".type")
        if kind == "wifi-device":
            radios.append({"name": str(name), "band": _band(sec), "channel": str(sec.get("channel") or ""),
                           "on": _is_on(sec)})
        elif kind == "wifi-iface":
            enc = str(sec.get("encryption") or "none")
            net = sec.get("network")
            nets = [str(x) for x in net] if isinstance(net, list) else ([str(net)] if net else [])
            networks.append({"section": str(name), "ssid": str(sec.get("ssid") or ""), "radio": str(sec.get("device") or ""),
                             "mode": str(sec.get("mode") or "ap"), "security": security_words(enc),
                             "open": enc.lower() in ("none", ""), "network": nets, "on": _is_on(sec),
                             "isolated": str(sec.get("isolate") or "0").lower() in ("1", "true", "yes", "on"),
                             # The names of the settings it has, never their values, so a network with nothing under
                             # "Network" can be understood (a password or key is never among what is shown).
                             "options": sorted(str(k) for k in sec if not str(k).startswith("."))})
    radios.sort(key=lambda r: r["name"])
    return {"radios": radios, "networks": networks}


def _as_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(x) for x in value]
    if value in (None, ""):
        return []
    return str(value).split()


def summarise_network(values: Any) -> dict:
    """How the access point itself gets its address, and how its ports and VLANs are laid out. Read-only.

    {"lan_proto", "vlans" (a count), "bridges": [{"name", "ports"}], "bridge_vlans": [{"device", "vlan", "ports"}],
     "switch_vlans": [{"vlan", "ports"}], "interfaces": [{"name", "proto", "device"}]}.
    Bridge VLANs are the newer (DSA) way; switch VLANs are the older (swconfig) way. No addresses are included."""
    values = values if isinstance(values, dict) else {}
    secs = [(str(k), v) for k, v in values.items() if isinstance(v, dict)]
    lan = values.get("lan") if isinstance(values.get("lan"), dict) else {}
    vlans = sum(1 for _n, s in secs if s.get(".type") in ("bridge-vlan", "switch_vlan"))
    bridges = [{"name": str(s.get("name") or ""), "ports": _as_list(s.get("ports"))}
               for _n, s in secs if s.get(".type") == "device" and str(s.get("type") or "") == "bridge"]
    bridge_vlans = [{"device": str(s.get("device") or ""), "vlan": str(s.get("vlan") or ""), "ports": _as_list(s.get("ports")),
                     "ours": str(_n).startswith("pz_")}
                    for _n, s in secs if s.get(".type") == "bridge-vlan"]
    switch_vlans = [{"vlan": str(s.get("vlan") or ""), "ports": _as_list(s.get("ports"))}
                    for _n, s in secs if s.get(".type") == "switch_vlan"]
    interfaces = [{"name": n, "proto": str(s.get("proto") or ""), "device": str(s.get("device") or s.get("ifname") or "")}
                  for n, s in secs if s.get(".type") == "interface" and n != "loopback"]
    return {"lan_proto": str(lan.get("proto") or ""), "vlans": vlans, "bridges": bridges, "bridge_vlans": bridge_vlans,
            "switch_vlans": switch_vlans, "interfaces": interfaces}


def read(ip: str, post: Post | None = None, password: str = "") -> dict:
    """Everything the Wi-Fi screen shows about one access point. Raises ApError with the reason."""
    address = private_address(ip)
    if address is None:
        raise ApError("Only an address on your own network can be read.")
    post = post or (lambda a, p: _post(a, p))
    session = _login(address, post, password)
    try:
        board = _call(address, post, session, "system", "board")
    except ApError:
        board = {}
    release = board.get("release") if isinstance(board.get("release"), dict) else {}
    out: dict[str, Any] = {"ip": address, "no_password": not password,
                           "model": str(board.get("model") or ""), "hostname": str(board.get("hostname") or ""),
                           "release": str(release.get("description") or release.get("version") or "")}
    try:
        wireless = _call(address, post, session, "uci", "get", {"config": "wireless"}).get("values")
    except ApError:
        wireless = None
    out.update(summarise_wireless(wireless))
    try:
        network = _call(address, post, session, "uci", "get", {"config": "network"}).get("values")
    except ApError:
        network = None
    if network is not None:
        out.update(summarise_network(network))
    else:
        out.update({"lan_proto": "", "vlans": 0, "bridges": [], "bridge_vlans": [], "switch_vlans": [], "interfaces": []})
    try:
        dhcp = _call(address, post, session, "uci", "get", {"config": "dhcp"}).get("values")
    except ApError:
        dhcp = None
    out["checks"] = checks(network, wireless, dhcp, no_password=not password)
    out["https_only"] = address in HTTPS_ONLY
    out["notes"] = port_notes(network)
    return out


def port_notes(network: Any) -> list:
    """BUILD 556: ports of the access point that are not in its bridge, said in plain words. Reads only."""
    net = network if isinstance(network, dict) else {}
    info = summarise_network(net)
    if len(info["bridges"]) != 1:
        return []
    inside = set(info["bridges"][0]["ports"])
    out = []
    for i in info["interfaces"]:
        dev = i["device"]
        if i["name"] in ("wan", "wan6") and dev and dev not in inside and not dev.startswith(("br-", "@")):
            line = (f"Its {dev} port is separate from its other ports: your networks reach it only through "
                    + (", ".join(sorted(inside)) or "its LAN ports") + f". Keep the firewall's cable out of {dev}.")
            if line not in out:
                out.append(line)
    return out


def _ipv6_state(network: Any, dhcp: Any) -> list[str]:
    """What on the access point still hands out or uses IPv6, in plain words (empty: IPv6 is off)."""
    net = network if isinstance(network, dict) else {}
    dh = dhcp if isinstance(dhcp, dict) else {}
    left = []
    g = net.get("globals") if isinstance(net.get("globals"), dict) else {}
    if g.get("ula_prefix"):
        left.append(f"a local IPv6 prefix ({g['ula_prefix']})")
    for name, s in net.items():
        if isinstance(s, dict) and s.get(".type") == "interface" and str(s.get("proto") or "") in ("dhcpv6", "6in4", "6rd", "6to4"):
            left.append(f"an IPv6 connection ({name})")
        if isinstance(s, dict) and s.get(".type") == "interface" and s.get("ip6assign"):
            left.append(f"IPv6 addresses on {name}")
    for name, s in dh.items():
        if isinstance(s, dict) and s.get(".type") == "dhcp":
            for opt in ("ra", "dhcpv6"):
                if str(s.get(opt) or "") not in ("", "disabled"):
                    left.append(f"IPv6 {opt.upper()} handed out on {s.get('interface') or name}")
    return left


COMMON_KEYS = {"password", "password1", "password123", "12345678", "123456789", "1234567890", "87654321", "11111111",
               "00000000", "88888888", "qwertyui", "qwertyuiop", "iloveyou", "abcd1234", "letmein1", "welcome1",
               "sunshine", "princess", "football", "baseball", "internet", "wireless", "changeme", "admin123",
               "opensesame", "trustno1", "passw0rd", "superman", "starwars", "homewifi", "mywifi123"}


def weak_key(key: Any, ssid: str = "") -> str:
    """Why a Wi-Fi password is weak ("" when it is fine). Never says the password itself."""
    k = str(key or "")
    if not k:
        return ""
    low = k.lower()
    if len(k) < 12:
        return "shorter than 12 characters"
    if low in COMMON_KEYS or low.rstrip("0123456789!") in COMMON_KEYS:
        return "a common password"
    if k.isdigit():
        return "only numbers"
    if ssid and (low == ssid.lower() or ssid.lower() in low):
        return "contains the network's own name"
    if len(set(low)) <= 3:
        return "almost the same character over and over"
    return ""


def checks(network: Any, wireless: Any, dhcp: Any, no_password: bool) -> list[dict]:
    """The access point against the baseline: [{"ok", "text", "fix"}]. Reads only. "fix" names the app's own fix, if any."""
    out = []
    out.append({"ok": not no_password, "text": "Root has a password" if not no_password else
                "No root password: anyone on the network can change this access point", "fix": ""})
    v6 = _ipv6_state(network, dhcp)
    out.append({"ok": not v6, "text": "IPv6 is off" if not v6 else "IPv6 is still on: " + "; ".join(v6[:4]),
                "fix": "" if not v6 else "ipv6_off"})
    dh = dhcp if isinstance(dhcp, dict) else {}
    lan = dh.get("lan") if isinstance(dh.get("lan"), dict) else None
    serving = lan is not None and str(lan.get("ignore") or "0") not in ("1", "true")
    out.append({"ok": not serving, "text": "It leaves handing out addresses to the firewall" if not serving else
                "It hands out addresses itself on its main network, next to the firewall's own", "fix": "" if not serving else "dhcp_off"})
    nets = summarise_wireless(wireless).get("networks", [])
    open_ = [n["ssid"] for n in nets if n["open"] and n["on"]]
    out.append({"ok": not open_, "text": "Every Wi-Fi network has a password" if not open_ else
                "Open Wi-Fi with no password: " + ", ".join(open_[:4]), "fix": ""})
    weak = [n["ssid"] for n in nets if n["security"] in ("wpa", "psk", "wep", "psk-mixed") or "WEP" in n["security"]]
    out.append({"ok": not weak, "text": "Each network uses WPA2 or WPA3" if not weak else
                "Old, weak security on: " + ", ".join(weak[:4]), "fix": ""})
    wl = wireless if isinstance(wireless, dict) else {}
    soft = []
    for _name, sec in wl.items():
        if not (isinstance(sec, dict) and sec.get(".type") == "wifi-iface" and _is_on(sec)):
            continue
        if str(sec.get("encryption") or "none").lower() in ("none", "", "owe"):
            continue
        why = weak_key(sec.get("key"), str(sec.get("ssid") or ""))
        if why:
            soft.append(f"{sec.get('ssid') or '(no name)'} ({why})")
    out.append({"ok": not soft, "text": "Every Wi-Fi password is strong" if not soft else
                "Weak Wi-Fi password on: " + ", ".join(soft[:4]) + ". Change it on the access point (Network, Wireless, "
                "Edit, Wireless Security) to 12 or more characters you don't use anywhere else", "fix": ""})
    net = network if isinstance(network, dict) else {}
    used = {x for n in nets for x in n["network"]}
    stray = [k for k, s in net.items() if str(k).startswith("pz_v") and isinstance(s, dict) and k not in used]
    out.append({"ok": not stray, "text": "Nothing left over from an earlier Pazuzu change" if not stray else
                "Left over from an earlier Pazuzu change: " + ", ".join(stray[:4]), "fix": "" if not stray else "tidy"})
    return out


def _stage_apply(address: str, post: Post, session: str, ops: list, check: Callable[[dict, dict], bool],
                 sleep, clock, say: Callable[[str], None]) -> None:
    """Stage `ops` ([(method, args)] on ubus uci), apply them with the access point's own rollback timer, wait for it
    to answer, check with `check(network, dhcp)`, and confirm. Anything that does not check out is put back by the
    access point itself."""
    configs = {a.get("config") for _m, a in ops}
    staged = False
    try:
        for method, args in ops:
            st, _ = _status(address, post, session, "uci", method, args)
            if st not in (0, 4) and not (method == "delete" and st == 4):
                raise ApError("It would not take that change.")
            staged = True
        say(f"Applying, with its own {APPLY_TIMEOUT}-second safety timer.")
        st, _ = _status(address, post, session, "uci", "apply", {"timeout": APPLY_TIMEOUT, "rollback": True})
        if st == DENIED:
            raise ApError("It refused: it may be waiting on another change. Wait a minute and try again.")
        if st != 0:
            raise ApError(f"It would not apply the change (code {st}).")
        staged = False
    except Exception as exc:
        if staged:
            for cfg in configs:
                try:
                    _status(address, post, session, "uci", "revert", {"config": cfg})
                except Exception:
                    pass
        if isinstance(exc, ApError):
            raise
        raise ApError(f"No answer from {address} ({type(exc).__name__}). Nothing was changed.")
    deadline = clock() + CONFIRM_FOR
    sleep(2.0)
    checked = False
    while True:
        try:
            if not checked:
                net = _call(address, post, session, "uci", "get", {"config": "network"}).get("values") or {}
                dh = _call(address, post, session, "uci", "get", {"config": "dhcp"}).get("values") or {}
                if not check(net, dh):
                    raise _Mismatch()
                checked = True
                say("It answered and kept the change. Confirming it, so the safety timer stops.")
            st, _ = _status(address, post, session, "uci", "confirm")
            if st == 0:
                say("Confirmed.")
                return
            if st == NO_DATA:
                raise ApError("The access point had already put the old settings back (the change was not confirmed in time).")
        except _Mismatch:
            raise ApError("The access point did not keep the change when asked back, so it will put the old settings back "
                          f"by itself within {APPLY_TIMEOUT} seconds.")
        except ApError as exc:
            if "already put" in str(exc):
                raise
        except Exception:
            pass
        if clock() >= deadline:
            raise ApError(f"The access point did not answer in time after the change. It puts the old settings back by "
                          f"itself within {APPLY_TIMEOUT} seconds, so nothing is left half-done.")
        sleep(0.5)


def tidy(ip: str, password: str = "", post: Post | None = None, sleep=None, clock=None,
         say: Callable[[str], None] | None = None) -> dict:
    """Remove what an earlier Pazuzu change left on the access point: its own networks (pz_v...) that no Wi-Fi network
    uses any more. Nothing of anyone else's is touched."""
    sleep, clock = sleep or time.sleep, clock or time.monotonic
    say = say or (lambda _t: None)
    address = private_address(ip)
    if address is None:
        raise ApError("Only an address on your own network can be changed.")
    post = post or (lambda a, p: _post(a, p))
    session = _login(address, post, password)
    net = _call(address, post, session, "uci", "get", {"config": "network"}).get("values") or {}
    wl = _call(address, post, session, "uci", "get", {"config": "wireless"}).get("values") or {}
    used = {x for n in summarise_wireless(wl).get("networks", []) for x in n["network"]}
    stray = [k for k, s in net.items() if str(k).startswith("pz_v") and isinstance(s, dict) and k not in used
             and _SECTION.match(str(k))]
    if not stray:
        return {"removed": []}
    say("Removing: " + ", ".join(stray))
    ops = [("delete", {"config": "network", "section": k}) for k in stray]
    _stage_apply(address, post, session, ops, lambda n, d: not any(k in n for k in stray), sleep, clock, say)
    return {"removed": stray}


def dhcp_off(ip: str, password: str = "", post: Post | None = None, sleep=None, clock=None,
             say: Callable[[str], None] | None = None) -> dict:
    """Stop the access point handing out addresses on its main network (lan), so only the firewall does. Applied with
    its own rollback timer, checked, confirmed. Nothing else in its DHCP settings is changed."""
    sleep, clock = sleep or time.sleep, clock or time.monotonic
    say = say or (lambda _t: None)
    address = private_address(ip)
    if address is None:
        raise ApError("Only an address on your own network can be changed.")
    post = post or (lambda a, p: _post(a, p))
    say(f"Signing in to the access point at {address}.")
    session = _login(address, post, password)
    dh = _call(address, post, session, "uci", "get", {"config": "dhcp"}).get("values") or {}
    lan = dh.get("lan") if isinstance(dh.get("lan"), dict) else None
    if lan is None or str(lan.get("ignore") or "0") in ("1", "true"):
        return {"changed": False}
    say("Preparing: the access point stops handing out addresses on its main network.")
    ops = [("set", {"config": "dhcp", "section": "lan", "values": {"ignore": "1"}})]
    _stage_apply(address, post, session, ops,
                 lambda n, d: str((d.get("lan") or {}).get("ignore") or "0") in ("1", "true"), sleep, clock, say)
    return {"changed": True}


def ipv6_off(ip: str, password: str = "", post: Post | None = None, sleep=None, clock=None,
             say: Callable[[str], None] | None = None) -> dict:
    """IPv6 off on the access point: no local IPv6 prefix, no IPv6 connection of its own, no IPv6 addresses on its
    networks, and nothing IPv6 handed out. Applied with its own rollback timer, checked, confirmed."""
    sleep, clock = sleep or time.sleep, clock or time.monotonic
    say = say or (lambda _t: None)
    address = private_address(ip)
    if address is None:
        raise ApError("Only an address on your own network can be changed.")
    post = post or (lambda a, p: _post(a, p))
    say(f"Signing in to the access point at {address}.")
    session = _login(address, post, password)
    net = _call(address, post, session, "uci", "get", {"config": "network"}).get("values") or {}
    dh = _call(address, post, session, "uci", "get", {"config": "dhcp"}).get("values") or {}
    ops: list = []
    if isinstance(net.get("globals"), dict) and net["globals"].get("ula_prefix"):
        ops.append(("delete", {"config": "network", "section": "globals", "option": "ula_prefix"}))
    for name, s in net.items():
        if not (isinstance(s, dict) and s.get(".type") == "interface" and _SECTION.match(str(name))):
            continue
        if str(s.get("proto") or "") in ("dhcpv6", "6in4", "6rd", "6to4"):
            ops.append(("delete", {"config": "network", "section": name}))
        elif s.get("ip6assign"):
            ops.append(("delete", {"config": "network", "section": name, "option": "ip6assign"}))
    for name, s in dh.items():
        if isinstance(s, dict) and s.get(".type") == "dhcp" and _SECTION.match(str(name)):
            if any(str(s.get(o) or "") not in ("", "disabled") for o in ("ra", "dhcpv6", "ndp")):
                ops.append(("set", {"config": "dhcp", "section": name,
                                    "values": {"ra": "disabled", "dhcpv6": "disabled", "ndp": "disabled"}}))
    if not ops:
        return {"changed": False}
    say("Preparing: " + str(len(ops)) + " IPv6 setting(s) to switch off.")
    _stage_apply(address, post, session, ops, lambda n, d: not _ipv6_state(n, d), sleep, clock, say)
    return {"changed": True}


# ----------------------------------------------------------------- the one change

def passphrase_problem(text) -> str | None:
    """Why this cannot be a Wi-Fi password (WPA2 wants 8 to 63 ordinary characters), or None if it can."""
    if not isinstance(text, str):
        return "Type a password."
    if not 8 <= len(text) <= 63:
        return "A Wi-Fi password must be 8 to 63 characters."
    if any(not 32 <= ord(ch) <= 126 for ch in text):
        return "Use only ordinary letters, numbers and symbols (no accents or emoji)."
    if text != text.strip():
        return "Leave out spaces at the start and end."
    return None


def wifi_qr_text(ssid: str, phrase: str, hidden: bool = False) -> str:
    """The text a phone camera reads to join: WIFI:T:WPA;S:<name>;P:<password>;;  (\\ ; , : \" are escaped)."""
    def esc(x: str) -> str:
        return "".join("\\" + ch if ch in '\\;,:"' else ch for ch in x)
    return f"WIFI:T:WPA;S:{esc(ssid)};P:{esc(phrase)};" + ("H:true;" if hidden else "") + ";"


def _status(ip: str, post: Post, session: str, obj: str, method: str, args: dict | None = None) -> tuple[int, dict]:
    """One ubus call, giving back the ubus status as well (0 = fine) instead of raising on a non-zero one."""
    reply = post(ip, {"jsonrpc": "2.0", "id": 1, "method": "call", "params": [session, obj, method, args or {}]})
    if not isinstance(reply, dict) or reply.get("error"):
        raise ApError("It did not answer like an OpenWrt device.")
    result = reply.get("result")
    if not isinstance(result, list) or not result or not isinstance(result[0], int):
        raise ApError("It did not answer like an OpenWrt device.")
    return result[0], (result[1] if len(result) > 1 and isinstance(result[1], dict) else {})


def test_sections(values: Any, ssid: str = TEST_SSID) -> list[dict]:
    """The Wi-Fi networks (access-point mode) called `ssid`: [{"id", "encryption", "key", "hidden"}]."""
    out = []
    for name, sec in (values.items() if isinstance(values, dict) else []):
        if (isinstance(sec, dict) and sec.get(".type") == "wifi-iface" and str(sec.get("ssid") or "") == ssid
                and str(sec.get("mode") or "ap") == "ap" and _SECTION.match(str(name))):
            key = sec.get("key")
            out.append({"id": str(name), "encryption": str(sec.get("encryption") or "none"),
                        "key": key if isinstance(key, str) else None,
                        "hidden": str(sec.get("hidden") or "0").lower() in ("1", "true", "yes", "on")})
    return sorted(out, key=lambda x: x["id"])


def _write(ip: str, post: Post, session: str, wanted: dict, sleep, clock) -> None:
    """Stage `wanted` ({section: {"encryption", "key" or None}}), apply it with a rollback timer, check it, confirm it."""
    staged = False
    try:
        for sec, w in wanted.items():
            values = {"encryption": w["encryption"]}
            if w.get("key") is not None:
                values["key"] = w["key"]
            _call(ip, post, session, "uci", "set", {"config": "wireless", "section": sec, "values": values})
            staged = True
            if w.get("key") is None:
                st, _ = _status(ip, post, session, "uci", "delete", {"config": "wireless", "section": sec, "options": ["key"]})
                if st not in (0, 4):                         # 4 = there was no key to remove
                    raise ApError("It would not take that change.")
        st, _ = _status(ip, post, session, "uci", "apply", {"timeout": APPLY_TIMEOUT, "rollback": True})
        if st == DENIED:
            raise ApError("It refused: it may be waiting on another change. Wait a minute and try again.")
        if st != 0:
            raise ApError(f"It would not apply the change (code {st}).")
        staged = False                                      # apply took the staged change (and now owns the rollback)
    except ApError:
        if staged:
            try:
                _status(ip, post, session, "uci", "revert", {"config": "wireless"})
            except Exception:
                pass
        raise
    except Exception as exc:
        if staged:
            try:
                _status(ip, post, session, "uci", "revert", {"config": "wireless"})
            except Exception:
                pass
        raise ApError(f"No answer from {ip} ({type(exc).__name__}). Nothing was changed.")

    deadline = clock() + CONFIRM_FOR
    sleep(1.0)                                              # LuCI also gives the Wi-Fi a moment before it confirms
    checked = False
    while True:
        try:
            if not checked:
                got = _call(ip, post, session, "uci", "get", {"config": "wireless"}).get("values")
                live = {x["id"]: x for x in test_sections(got)}
                for sec, w in wanted.items():
                    now = live.get(sec)
                    if now is None or now["encryption"] != w["encryption"] or now["key"] != w.get("key"):
                        raise _Mismatch()
                checked = True
            st, _ = _status(ip, post, session, "uci", "confirm")
            if st == 0:
                return
            if st == NO_DATA:
                raise ApError("The access point had already put the old settings back (the change was not confirmed in time).")
        except _Mismatch:
            raise ApError("The access point did not keep the change when asked back, so it will put the old settings back "
                          f"by itself within {APPLY_TIMEOUT} seconds.")
        except ApError as exc:
            if "already put" in str(exc):
                raise
        except Exception:
            pass                                            # the Wi-Fi restarting can drop a call: try again
        if clock() >= deadline:
            raise ApError(f"The access point did not answer in time. It puts the old settings back by itself within "
                          f"{APPLY_TIMEOUT} seconds, so nothing is left half-done.")
        sleep(0.25)


class _Mismatch(Exception):
    pass


def set_passphrase(ip: str, passphrase: str, post: Post | None = None, sleep=None, clock=None) -> dict:
    """Give the test network a WPA2 password. Returns {"ssid", "hidden", "sections": [...], "previous": {id: {...}}};
    `previous` is what to hand to restore() to put it back. Raises ApError with the reason, having changed nothing."""
    sleep, clock = sleep or time.sleep, clock or time.monotonic
    bad = passphrase_problem(passphrase)
    if bad:
        raise ApError(bad)
    address = private_address(ip)
    if address is None:
        raise ApError("Only an address on your own network can be changed.")
    post = post or (lambda a, p: _post(a, p))
    session = _login(address, post)
    values = _call(address, post, session, "uci", "get", {"config": "wireless"}).get("values")
    found = test_sections(values)
    if not found:
        raise ApError(f"No Wi-Fi network called {TEST_SSID} was found on it.")
    wanted = {x["id"]: {"encryption": "psk2", "key": passphrase} for x in found}
    _write(address, post, session, wanted, sleep, clock)
    return {"ssid": TEST_SSID, "hidden": any(x["hidden"] for x in found), "sections": [x["id"] for x in found],
            "previous": {x["id"]: {"encryption": x["encryption"], "key": x["key"]} for x in found}}


def restore(ip: str, previous: dict, post: Post | None = None, sleep=None, clock=None) -> dict:
    """Put the test network back as `previous` (from set_passphrase) had it, for example open again."""
    sleep, clock = sleep or time.sleep, clock or time.monotonic
    address = private_address(ip)
    if address is None:
        raise ApError("Only an address on your own network can be changed.")
    wanted = {}
    for sec, w in (previous.items() if isinstance(previous, dict) else []):
        if not _SECTION.match(str(sec)) or not isinstance(w, dict) or not isinstance(w.get("encryption"), str):
            continue
        key = w.get("key")
        wanted[str(sec)] = {"encryption": w["encryption"], "key": key if isinstance(key, str) else None}
    if not wanted:
        raise ApError("There is nothing to put back.")
    post = post or (lambda a, p: _post(a, p))
    session = _login(address, post)
    values = _call(address, post, session, "uci", "get", {"config": "wireless"}).get("values")
    live = {x["id"] for x in test_sections(values)}
    if not set(wanted) <= live:
        raise ApError(f"The network {TEST_SSID} is not set the way it was left; nothing was changed.")
    _write(address, post, session, wanted, sleep, clock)
    return {"ssid": TEST_SSID, "sections": sorted(wanted)}


def candidates(clients: list[dict] | None, vendor_of: Callable[[str], str], everyone: bool = False) -> list[dict]:
    """The devices the firewall already knows that could be an access point: named OpenWrt, or from a maker that sells them.
    BUILD 482 (the maintainer, 5 Nov: "if it looks configurable we handle it"): with `everyone`, every other device the box knows
    comes after those, so an access point with its own name, a maker not on the list, or a fixed address (seen by the
    box's ARP, not its DHCP) is still asked. Asking is one sign-in attempt with no password: nothing is changed."""
    out, rest, seen = [], [], set()
    for c in clients or []:
        if not isinstance(c, dict):
            continue
        ip = private_address(c.get("ip"))
        if ip is None:
            continue
        name = str(c.get("name") or "")
        vendor = vendor_of(c.get("mac") or "") if c.get("mac") else ""
        low = (name + " " + vendor).lower()
        if ip in seen:
            continue
        seen.add(ip)
        row = {"ip": ip, "name": name, "vendor": vendor, "mac": str(c.get("mac") or "")}
        if "openwrt" in low or "lede" in name.lower() or any(m in vendor.lower() for m in AP_MAKERS):
            out.append(row)
        elif everyone:
            rest.append(row)
    return (out + rest)[:MAX_EVERYONE] if everyone else out[:MAX_CANDIDATES]


def find(clients: list[dict] | None, vendor_of: Callable[[str], str], post: Post | None = None,
         everyone: bool = False) -> dict:
    """Ask each candidate whether it answers like OpenWrt. {"found": [...], "tried": n}."""
    cands = candidates(clients, vendor_of, everyone)

    def ask(c: dict) -> dict | None:
        got = identify(c["ip"], post)
        return {**c, **got} if got else None
    with ThreadPoolExecutor(max_workers=12) as pool:     # BUILD 488: 6 to 12, so asking 64 takes seconds, not a minute
        got = list(pool.map(ask, cands))
    found = [x for x in got if x]
    # BUILD 556 (an access point's cable was in `wan`, which the factory bridge leaves out): a device
    # that calls itself OpenWrt and gives no answer is most likely cabled by its WAN port, where OpenWrt answers nothing.
    silent = [{"ip": c["ip"], "name": c["name"]} for c, x in zip(cands, got)
              if not x and re.search(r"openwrt|lede", c["name"], re.I)]
    return {"found": found, "tried": len(cands), "silent": silent[:4]}


# ----------------------------------------------------------------- VLAN tagging to match the firewall
PZ_IFACE = "pz_v{tag}"           # the access point's own name for a network carried on one VLAN
PZ_WIFI = "pz_w{n}"              # the access point's own name for a zone Wi-Fi network Pazuzu creates on it


def vlan_plan(network: Any, wireless: Any, mapping: dict) -> dict:
    """What tagging the access point needs so each Wi-Fi network named in `mapping` ({section: VLAN number or None})
    rides on that VLAN, and everything else stays on the untagged network it is on now. Reads only; raises ApError.

    Only the plain layout is taken: one bridge (br-lan) that the lan network uses, with no VLANs on it yet (the newer,
    DSA way). The untagged network stays untagged on every port of the bridge, so the access point is reached the same
    way as before; each VLAN is added tagged on those ports."""
    network = network if isinstance(network, dict) else {}
    wireless = wireless if isinstance(wireless, dict) else {}
    secs = {str(k): v for k, v in network.items() if isinstance(v, dict)}
    ours = sorted(k for k in secs if k.startswith(("pz_bv", "pz_v")))      # Pazuzu's own earlier tagging: replaced
    lan0 = secs.get("lan") or {}
    secs = {k: v for k, v in secs.items() if k not in ours}
    if ours and str(lan0.get("device") or "").endswith(".1"):
        secs["lan"] = dict(lan0, device=str(lan0["device"])[:-2])           # as it was before that tagging
    if any(s.get(".type") in ("bridge-vlan", "switch_vlan", "switch") for s in secs.values()):
        raise ApError("It already has VLANs or a switch set up, so Pazuzu leaves its tagging to you (Network, Interfaces, "
                      "Devices, br-lan, Bridge VLAN filtering). Nothing was changed.")
    bridges = [(k, s) for k, s in secs.items() if s.get(".type") == "device" and str(s.get("type") or "") == "bridge"]
    if len(bridges) != 1:
        raise ApError("It does not have exactly one bridge, so Pazuzu cannot tell where to add the VLANs. Nothing was changed.")
    bkey, bridge = bridges[0]
    bname = str(bridge.get("name") or "")
    ports = _as_list(bridge.get("ports"))
    if not bname or not ports or not all(re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", p) for p in ports):
        raise ApError("Its bridge has no ports listed, so there is nowhere to carry the VLANs. Nothing was changed.")
    lan = secs.get("lan") or {}
    if lan.get(".type") != "interface" or str(lan.get("device") or "") != bname:
        raise ApError(f"Its lan network is not on {bname} as expected, so Pazuzu left it alone. Nothing was changed.")
    tags: list[int] = []
    for sec, tag in mapping.items():
        w = wireless.get(sec)
        if not _SECTION.match(str(sec)) or not isinstance(w, dict) or w.get(".type") != "wifi-iface":
            raise ApError("A Wi-Fi network named in the change is not on it any more. Read it again. Nothing was changed.")
        if tag is None:
            continue
        if not isinstance(tag, int) or isinstance(tag, bool) or not 2 <= tag <= 4094:
            raise ApError("A VLAN number must be 2 to 4094. Nothing was changed.")
        if tag not in tags:
            tags.append(tag)
    if not tags:
        raise ApError("No Wi-Fi network was given a VLAN, so there is nothing to change.")
    return {"bridge": bname, "bridge_section": bkey, "ports": ports, "tags": sorted(tags),
            "wifi": {str(s): t for s, t in mapping.items() if t is not None}, "replace": ours}


def set_vlans(ip: str, mapping: dict, password: str = "", post: Post | None = None, sleep=None, clock=None,
              say: Callable[[str], None] | None = None) -> dict:
    """Tag the access point to match the firewall's VLANs (vlan_plan says what), apply it with the access point's own
    rollback timer, check it, confirm it. If anything does not check out, the access point puts the old settings back by
    itself. The password is used for this one change and kept nowhere."""
    sleep, clock = sleep or time.sleep, clock or time.monotonic
    say = say or (lambda _t: None)                  # each step in plain words, for the progress the person sees
    address = private_address(ip)
    if address is None:
        raise ApError("Only an address on your own network can be changed.")
    post = post or (lambda a, p: _post(a, p))
    say(f"Signing in to the access point at {address}.")
    session = _login(address, post, password)
    say("Reading its network and Wi-Fi settings.")
    network = _call(address, post, session, "uci", "get", {"config": "network"}).get("values")
    wireless = _call(address, post, session, "uci", "get", {"config": "wireless"}).get("values")
    plan = vlan_plan(network, wireless, mapping)
    br, ports = plan["bridge"], plan["ports"]
    say(f"Preparing: the main network stays untagged on {', '.join(ports)}; VLAN "
        + ", ".join(map(str, plan["tags"])) + " tagged.")
    staged = False
    try:
        for old in plan["replace"]:                      # Pazuzu's own earlier tagging goes first (same rollback)
            _status(address, post, session, "uci", "delete", {"config": "network", "section": old})
            staged = True
        _call(address, post, session, "uci", "add", {"config": "network", "type": "bridge-vlan", "name": "pz_bv1",
                                                      "values": {"device": br, "vlan": "1", "ports": [p + ":u*" for p in ports]}})
        staged = True
        for tag in plan["tags"]:
            _call(address, post, session, "uci", "add", {"config": "network", "type": "bridge-vlan", "name": f"pz_bv{tag}",
                                                          "values": {"device": br, "vlan": str(tag), "ports": [p + ":t" for p in ports]}})
            _call(address, post, session, "uci", "add", {"config": "network", "type": "interface",
                                                          "name": PZ_IFACE.format(tag=tag),
                                                          "values": {"proto": "none", "device": f"{br}.{tag}"}})
        _call(address, post, session, "uci", "set", {"config": "network", "section": "lan", "values": {"device": f"{br}.1"}})
        for sec, tag in plan["wifi"].items():
            _call(address, post, session, "uci", "set", {"config": "wireless", "section": sec,
                                                          "values": {"network": [PZ_IFACE.format(tag=tag)]}})
        for sec, w in (wireless.items() if isinstance(wireless, dict) else []):
            # A Wi-Fi network that was on one of the VLANs being replaced, and is not put on one now, goes back to the main one.
            if (isinstance(w, dict) and w.get(".type") == "wifi-iface" and sec not in plan["wifi"] and _SECTION.match(str(sec))
                    and any(n in plan["replace"] for n in _as_list(w.get("network")))):
                _call(address, post, session, "uci", "set", {"config": "wireless", "section": sec, "values": {"network": ["lan"]}})
        say(f"Applying, with its own {APPLY_TIMEOUT}-second safety timer. Its network restarts now.")
        st, _ = _status(address, post, session, "uci", "apply", {"timeout": APPLY_TIMEOUT, "rollback": True})
        if st == DENIED:
            raise ApError("It refused: it may be waiting on another change. Wait a minute and try again.")
        if st != 0:
            raise ApError(f"It would not apply the change (code {st}).")
        staged = False
    except Exception as exc:
        if staged:
            for cfg in ("network", "wireless"):
                try:
                    _status(address, post, session, "uci", "revert", {"config": cfg})
                except Exception:
                    pass
        if isinstance(exc, ApError):
            raise
        raise ApError(f"No answer from {address} ({type(exc).__name__}). Nothing was changed.")

    deadline = clock() + CONFIRM_FOR
    sleep(2.0)                                   # the network restarts: give it a moment before asking back
    checked = False
    while True:
        try:
            if not checked:
                net = _call(address, post, session, "uci", "get", {"config": "network"}).get("values") or {}
                wl = _call(address, post, session, "uci", "get", {"config": "wireless"}).get("values") or {}
                ok = str((net.get("lan") or {}).get("device")) == f"{br}.1" and all(
                    _as_list((wl.get(s) or {}).get("network")) == [PZ_IFACE.format(tag=t)] for s, t in plan["wifi"].items())
                if not ok:
                    raise _Mismatch()
                checked = True
                say("It answered and kept the change. Confirming it, so the safety timer stops.")
            st, _ = _status(address, post, session, "uci", "confirm")
            if st == 0:
                say("Confirmed.")
                return {"tags": plan["tags"], "ports": ports, "bridge": br, "wifi": plan["wifi"]}
            if st == NO_DATA:
                raise ApError("The access point had already put the old settings back (the change was not confirmed in time).")
        except _Mismatch:
            raise ApError("The access point did not keep the change when asked back, so it will put the old settings back "
                          f"by itself within {APPLY_TIMEOUT} seconds.")
        except ApError as exc:
            if "already put" in str(exc):
                raise
        except Exception:
            pass
        if clock() >= deadline:
            raise ApError(f"The access point did not answer in time after the change. It puts the old settings back by "
                          f"itself within {APPLY_TIMEOUT} seconds, so nothing is left half-done.")
        sleep(0.5)


# ----------------------------------------------------------------- creating the firewall's zone Wi-Fi on the access point
def after_made(address: str, post: Post, session: str, bname: str, tags: list, sleep, clock,
               say: Callable[[str], None]) -> dict:
    """BUILD 556 ("restart networking and check a DHCP lease per VLAN on the access point;
    radios re-attached after wireless restarts gave clients no address until a network restart"). After the change is
    confirmed: restart the access point's network once, wait for it to answer, then ask for an address on each VLAN
    from the access point itself, which shows the firewall's network really arrives there tagged. Nothing is kept from
    the answer and nothing is changed by the asking. Never fails the change: {tag: True | False | None (not checked)}."""
    out: dict = {int(t): None for t in tags}
    try:
        _status(address, post, session, "network", "restart")
    except Exception:  # noqa: BLE001 - the call itself may be cut off by the restart
        pass
    say("Its network was restarted, so every Wi-Fi network picks up its VLAN.")
    end = clock() + 45.0
    sleep(3.0)
    up = False
    for _try in range(45):                           # bounded by count as well as by the clock
        if clock() >= end:
            break
        try:
            _call(address, post, session, "system", "board")
            up = True
            break
        except Exception:  # noqa: BLE001
            sleep(1.0)
    if not up:
        say("It has not answered again yet, so the VLANs were not checked for addresses.")
        return out
    for tag in tags:
        try:
            st, got = _status(address, post, session, "file", "exec",
                              {"command": "/sbin/udhcpc", "params": ["-i", f"{bname}.{int(tag)}", "-n", "-q", "-R", "-t", "3",
                                                                     "-T", "2", "-s", "/bin/true"]})   # -R: the address is given back at once
        except Exception:  # noqa: BLE001
            continue
        if st != 0 or not isinstance(got, dict) or not isinstance(got.get("code"), int):
            continue                                   # this access point cannot run it: not checked, and not a fault
        out[int(tag)] = got["code"] == 0
        say(f"VLAN {int(tag)}: " + ("the firewall hands out addresses on it here." if out[int(tag)] else
                                    "no address came. The cable or switch between the firewall and the access point "
                                    "may not carry this VLAN tagged."))
    return out


def _plain_bridge(network: Any) -> tuple:
    """The single plain bridge (its name and ports) the lan network uses, and Pazuzu's own earlier plumbing to replace —
    the same plain DSA layout set_vlans needs. ApError for anything else, so nothing is guessed. Reads only."""
    network = network if isinstance(network, dict) else {}
    secs = {str(k): v for k, v in network.items() if isinstance(v, dict)}
    ours = sorted(k for k in secs if k.startswith(("pz_bv", "pz_v")))
    lan0 = secs.get("lan") or {}
    base = {k: v for k, v in secs.items() if k not in ours}
    if ours and str(lan0.get("device") or "").endswith(".1"):
        base["lan"] = dict(lan0, device=str(lan0["device"])[:-2])           # as it was before that tagging
    if any(s.get(".type") in ("bridge-vlan", "switch_vlan", "switch") for s in base.values()):
        raise ApError("It already has VLANs or a switch set up, so Pazuzu leaves its tagging to you (Network, Interfaces, "
                      "Devices, br-lan, Bridge VLAN filtering). Nothing was changed.")
    bridges = [(k, s) for k, s in base.items() if s.get(".type") == "device" and str(s.get("type") or "") == "bridge"]
    if len(bridges) != 1:
        raise ApError("It does not have exactly one bridge, so Pazuzu cannot tell where to add the VLANs. Nothing was changed.")
    _bkey, bridge = bridges[0]
    bname = str(bridge.get("name") or "")
    ports = _as_list(bridge.get("ports"))
    if not bname or not ports or not all(re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", p) for p in ports):
        raise ApError("Its bridge has no ports listed, so there is nowhere to carry the VLANs. Nothing was changed.")
    lan = base.get("lan") or {}
    if lan.get(".type") != "interface" or str(lan.get("device") or "") != bname:
        raise ApError(f"Its lan network is not on {bname} as expected, so Pazuzu left it alone. Nothing was changed.")
    return bname, ports, ours


def can_carry(ip: str, password: str = "", post: Post | None = None) -> str:
    """BUILD 482: "" when the access point's layout is the plain one add_networks needs (one bridge, no VLANs of its
    own), else the plain-words reason. Reads only."""
    address = private_address(ip)
    if address is None:
        return "Only an address on your own network can be asked."
    post = post or (lambda a, p: _post(a, p))
    try:
        session = _login(address, post, password)
        _plain_bridge(_call(address, post, session, "uci", "get", {"config": "network"}).get("values"))
    except ApError as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001
        return f"No answer from {address} ({type(exc).__name__})."
    return ""


def set_root_password(ip: str, new: str, password: str = "", post: Post | None = None) -> None:
    """BUILD 482 (the maintainer, 5 Nov: "try as for the password"): give the access point's root a password the box made, the way
    its own web page does (LuCI's setPassword), then sign in with it to prove it took. The new one is kept on the box
    only (the caller keeps it), so the person never types it. ApError if it did not take."""
    address = private_address(ip)
    if address is None:
        raise ApError("Only an address on your own network can be changed.")
    if not isinstance(new, str) or not 16 <= len(new) <= 64 or any(ord(c) < 33 or ord(c) > 126 for c in new):
        raise ApError("That new password is not one this can set.")
    post = post or (lambda a, p: _post(a, p))
    session = _login(address, post, password)
    try:
        _call(address, post, session, "luci", "setPassword", {"username": "root", "password": new})
    except ApError:
        raise ApError("It would not take a new password for its own web page (it may not have LuCI).")
    except Exception as exc:  # noqa: BLE001
        raise ApError(f"No answer from {address} ({type(exc).__name__}).")
    try:
        _login(address, post, new)
    except ApError:
        raise ApError("It took the new password but does not sign in with it. Its old one may still work.")


ENCRYPTIONS = {"psk2": None, "sae-mixed": "1", "sae": "2"}    # BUILD 482: what a network may use; its 802.11w setting


def add_networks(ip: str, specs: list, password: str = "", post: Post | None = None, sleep=None, clock=None,
                 say: Callable[[str], None] | None = None) -> dict:
    """Create Wi-Fi networks on the access point — the firewall's own zone SSIDs — each tagged onto its zone VLAN, so a
    device that joins one lands in that zone and rides its scrambled subnet. specs = [{"ssid", "passphrase", "tag",
    "radio"}]. Management is never among them: the caller leaves it out, so it is never broadcast. The untagged main
    network (lan on the bridge) is left exactly as it is, so the access point stays reachable there for administration —
    the management back door. Re-runnable: Pazuzu's own earlier VLAN plumbing and zone SSIDs are replaced under the same
    rollback. Applied with the access point's own rollback timer, checked, confirmed; anything that does not check out is
    put back by the access point itself. The password is used for this one change and kept nowhere.

    BUILD 482 (Hanbi's own Wi-Fi, the maintainer 5 Nov 2026), all optional per spec, so the PC page's calls are unchanged:
      "home": True with "tag": None  the Home network, on the main network untagged (Trusted); at most one;
      "radios": [..]                  one network per radio, the same name on each band (in place of "radio");
      "encryption": "psk2" | "sae-mixed" | "sae", with protected management frames for the two WPA3 ones;
      "isolate": True                 the devices on it cannot reach each other.
    Every network Pazuzu makes has WPS off. A radio a network is put on is switched on (a factory OpenWrt has its radios
    off) with the old 11b rates off, and an OPEN network the access point already had on that radio is switched off, so switching the radio on never
    broadcasts an open Wi-Fi."""
    sleep, clock = sleep or time.sleep, clock or time.monotonic
    say = say or (lambda _t: None)
    address = private_address(ip)
    if address is None:
        raise ApError("Only an address on your own network can be changed.")
    if not isinstance(specs, list) or not specs:
        raise ApError("No Wi-Fi networks were given to create. Nothing was changed.")
    post = post or (lambda a, p: _post(a, p))
    say(f"Signing in to the access point at {address}.")
    session = _login(address, post, password)
    say("Reading its network and Wi-Fi settings.")
    network = _call(address, post, session, "uci", "get", {"config": "network"}).get("values")
    wireless = _call(address, post, session, "uci", "get", {"config": "wireless"}).get("values") or {}
    bname, ports, ours = _plain_bridge(network)
    radios = {str(k) for k, s in wireless.items() if isinstance(s, dict) and s.get(".type") == "wifi-device"}
    if not radios:
        raise ApError("The access point has no Wi-Fi radio to put a network on. Nothing was changed.")
    clean, tags, seen, homes = [], [], set(), 0
    for sp in specs:
        if not isinstance(sp, dict):
            raise ApError("A Wi-Fi network to create was not understood. Nothing was changed.")
        ssid = str(sp.get("ssid") or "").strip()
        key = str(sp.get("passphrase") or "")
        tag = sp.get("tag")
        home = bool(sp.get("home"))
        on = sp.get("radios")
        on = [str(r) for r in on] if isinstance(on, list) and on else [str(sp.get("radio") or "") or sorted(radios)[0]]
        enc = str(sp.get("encryption") or "psk2")
        if not ssid or len(ssid) > 32:
            raise ApError("Each Wi-Fi name must be 1 to 32 characters. Nothing was changed.")
        if ssid in seen:
            raise ApError(f"Two networks share the name {ssid}. Nothing was changed.")
        seen.add(ssid)
        if not 8 <= len(key) <= 63:
            raise ApError(f"The Wi-Fi password for {ssid} must be 8 to 63 characters. Nothing was changed.")
        if home:
            homes += 1
            if tag is not None or homes > 1:
                raise ApError("Only one Home network, on the main network with no VLAN. Nothing was changed.")
        elif not isinstance(tag, int) or isinstance(tag, bool) or not 2 <= tag <= 4094:
            raise ApError("A VLAN number must be 2 to 4094. Nothing was changed.")
        for r in on:
            if r not in radios:
                raise ApError(f"The access point has no radio called {r}. Nothing was changed.")
        if enc not in ENCRYPTIONS:
            raise ApError(f"{enc} is not a Wi-Fi security this can set. Nothing was changed.")
        for r in on:
            clean.append({"ssid": ssid, "key": key, "tag": None if home else int(tag), "radio": r, "enc": enc,
                          "isolate": bool(sp.get("isolate"))})
        if not home and tag not in tags:
            tags.append(int(tag))
    used = sorted({c["radio"] for c in clean})
    old_wifi = sorted(k for k, s in wireless.items() if isinstance(s, dict) and s.get(".type") == "wifi-iface"
                      and str(k).startswith("pz_w") and _SECTION.match(str(k)))
    open_wifi = sorted(k for k, s in wireless.items() if isinstance(s, dict) and s.get(".type") == "wifi-iface"
                       and not str(k).startswith("pz_w") and _SECTION.match(str(k)) and str(s.get("device")) in used
                       and str(s.get("encryption") or "none") in ("none", "open", "owe-transition")
                       and str(s.get("disabled") or "0") != "1")
    made: list = []
    staged = False
    try:
        for old in ours:                                   # Pazuzu's own earlier VLAN plumbing, replaced under the same rollback
            _status(address, post, session, "uci", "delete", {"config": "network", "section": old})
            staged = True
        for ow in old_wifi:                                # and its own earlier zone SSIDs, so a re-run is clean
            _status(address, post, session, "uci", "delete", {"config": "wireless", "section": ow})
            staged = True
        _call(address, post, session, "uci", "add", {"config": "network", "type": "bridge-vlan", "name": "pz_bv1",
                                                      "values": {"device": bname, "vlan": "1", "ports": [p + ":u*" for p in ports]}})
        staged = True
        for tag in tags:
            _call(address, post, session, "uci", "add", {"config": "network", "type": "bridge-vlan", "name": f"pz_bv{tag}",
                                                          "values": {"device": bname, "vlan": str(tag), "ports": [p + ":t" for p in ports]}})
            _call(address, post, session, "uci", "add", {"config": "network", "type": "interface", "name": PZ_IFACE.format(tag=tag),
                                                          "values": {"proto": "none", "device": f"{bname}.{tag}"}})
        _call(address, post, session, "uci", "set", {"config": "network", "section": "lan", "values": {"device": f"{bname}.1"}})
        for ow in open_wifi:                               # BUILD 482: never an open Wi-Fi once the radio is on
            _call(address, post, session, "uci", "set", {"config": "wireless", "section": ow, "values": {"disabled": "1"}})
        for r in used:                                     # BUILD 482: a factory OpenWrt has its radios off; no 11b
            _call(address, post, session, "uci", "set", {"config": "wireless", "section": r,
                                                          "values": {"disabled": "0", "legacy_rates": "0"}})
        for i, c in enumerate(clean):
            name = PZ_WIFI.format(n=i + 1)
            values = {"device": c["radio"], "mode": "ap", "ssid": c["ssid"], "encryption": c["enc"], "key": c["key"],
                      "network": ["lan" if c["tag"] is None else PZ_IFACE.format(tag=c["tag"])], "wps_pushbutton": "0"}
            if ENCRYPTIONS[c["enc"]]:
                values["ieee80211w"] = ENCRYPTIONS[c["enc"]]
            if c["isolate"]:
                values["isolate"] = "1"
            _call(address, post, session, "uci", "add", {"config": "wireless", "type": "wifi-iface", "name": name,
                                                          "values": values})
            made.append({"section": name, "ssid": c["ssid"], "tag": c["tag"], "radio": c["radio"]})
        say("Preparing: " + ", ".join(f"“{m['ssid']}” " + ("on the main network" if m["tag"] is None else f"on VLAN {m['tag']}")
                                      + f" ({m['radio']})" for m in made)
            + f"; the main network stays on {bname} untagged, so the access point stays reachable there for admin.")
        say(f"Applying, with its own {APPLY_TIMEOUT}-second safety timer. Its Wi-Fi restarts now.")
        st, _ = _status(address, post, session, "uci", "apply", {"timeout": APPLY_TIMEOUT, "rollback": True})
        if st == DENIED:
            raise ApError("It refused: it may be waiting on another change. Wait a minute and try again.")
        if st != 0:
            raise ApError(f"It would not apply the change (code {st}).")
        staged = False
    except Exception as exc:
        if staged:
            for cfg in ("network", "wireless"):
                try:
                    _status(address, post, session, "uci", "revert", {"config": cfg})
                except Exception:
                    pass
        if isinstance(exc, ApError):
            raise
        raise ApError(f"No answer from {address} ({type(exc).__name__}). Nothing was changed.")

    deadline = clock() + CONFIRM_FOR
    sleep(2.0)                                   # the Wi-Fi restarts: give it a moment before asking back
    checked = False
    while True:
        try:
            if not checked:
                net = _call(address, post, session, "uci", "get", {"config": "network"}).get("values") or {}
                wl = _call(address, post, session, "uci", "get", {"config": "wireless"}).get("values") or {}
                ok = (str((net.get("lan") or {}).get("device")) == f"{bname}.1"
                      and all(PZ_IFACE.format(tag=t) in net for t in tags)
                      and all(str((wl.get(m["section"]) or {}).get("ssid")) == m["ssid"]
                              and _as_list((wl.get(m["section"]) or {}).get("network"))
                              == ["lan" if m["tag"] is None else PZ_IFACE.format(tag=m["tag"])]
                              for m in made))
                if not ok:
                    raise _Mismatch()
                checked = True
                say("It answered and kept the change. Confirming it, so the safety timer stops.")
            st, _ = _status(address, post, session, "uci", "confirm")
            if st == 0:
                say("Confirmed.")
                leases = after_made(address, post, session, bname, sorted(tags), sleep, clock, say)
                return {"made": made, "tags": sorted(tags), "bridge": bname, "ports": ports, "leases": leases}
            if st == NO_DATA:
                raise ApError("The access point had already put the old settings back (the change was not confirmed in time).")
        except _Mismatch:
            raise ApError("The access point did not keep the change when asked back, so it will put the old settings back "
                          f"by itself within {APPLY_TIMEOUT} seconds.")
        except ApError as exc:
            if "already put" in str(exc):
                raise
        except Exception:
            pass
        if clock() >= deadline:
            raise ApError(f"The access point did not answer in time after the change. It puts the old settings back by "
                          f"itself within {APPLY_TIMEOUT} seconds, so nothing is left half-done.")
        sleep(0.5)
