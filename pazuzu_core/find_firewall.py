"""Find the firewall on whatever network this device is on.

Read-only and local. It looks at this device's own addresses, its gateway
and its neighbour table, tries a TCP connect on the web GUI ports, and asks
anything that answers for its front page. A page that says "OPNsense" is the
signature. It sends no password, no key and no request that changes anything,
and it only ever talks to addresses in the private ranges, so nothing here can
reach the internet.

It also lists nearby Wi-Fi networks whose name starts with "Hanbi", because a
Hanbi box makes its own setup network. It does not join one: that is the
person's own Wi-Fi setting.

Every operating-system call and every network call is injected, so the tests
run without a network. The defaults use the standard library only.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable

GUI_PORTS = (443, 8443)
# Other ports people move the page to. Tried only on the likely addresses (a typed one, the
# gateway, a device this device has seen, a usual last number), not on every address.
MORE_PORTS = (4443, 9443, 10443, 444, 8444, 7443, 4433, 943)
# What marks an OPNsense page. Never the host name: someone may have renamed the firewall to
# anything at all. The product's own name appears in the page's own files, whatever the box is called.
SIGNATURES = (b"opnsense", b"deciso")
READ_LIMIT = 65536
CONNECT_TIMEOUT = 0.4
PAGE_TIMEOUT = 3.0
MAX_HOSTS = 600
WIFI_PREFIX = "hanbi"
# Last octets tried first, before the rest of the /24.
LIKELY_LAST = (1, 254, 2, 100, 10)

Run = Callable[[list[str]], str]
Connect = Callable[[str, int], bool]
Fetch = Callable[[str, int], bytes | None]


@dataclass(frozen=True)
class Found:
    host: str
    port: int
    via: str

    @property
    def url(self) -> str:
        return f"https://{self.host}" + ("" if self.port == 443 else f":{self.port}")


@dataclass
class Report:
    mine: list[str] = field(default_factory=list)       # this device's usable addresses
    link_only: bool = False                             # only 169.254.x.x addresses
    found: list[Found] = field(default_factory=list)
    wifi: list[dict] = field(default_factory=list)      # {"name", "signal"}
    looked: int = 0
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "mine": self.mine,
            "link_only": self.link_only,
            "found": [{"host": f.host, "port": f.port, "url": f.url, "via": f.via}
                      for f in self.found],
            "wifi": self.wifi,
            "looked": self.looked,
            "note": self.note,
        }


# -- the operating system, as text -------------------------------------------------

def _run(cmd: list[str]) -> str:
    """Run one fixed command, no shell, short timeout. Failure is an empty answer."""
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout or ""


def _windows() -> bool:
    return sys.platform.startswith("win")


def local_addresses(run: Run = _run) -> list[str]:
    """This device's IPv4 addresses (every adapter), best effort."""
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    # The address the system would use to reach a private network: no packet is sent.
    for probe in ("10.255.255.255", "192.168.255.255", "172.31.255.255"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((probe, 9))
                found.add(s.getsockname()[0])
        except OSError:
            pass
    if _windows():
        # "IPv4 Address", "Autoconfiguration IPv4 Address" and the other languages' versions all say IPv4.
        found.update(re.findall(r"IPv4[^:\n]*:\s*(\d+\.\d+\.\d+\.\d+)", run(["ipconfig"])))
    else:
        text = run(["ip", "-4", "-o", "addr"]) or run(["ifconfig"])
        found.update(re.findall(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", text))
    return sorted(a for a in found if _valid_v4(a))


def _valid_v4(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).version == 4
    except ValueError:
        return False


def default_gateways(run: Run = _run) -> list[str]:
    text = run(["route", "print", "-4"]) if _windows() else run(["ip", "-4", "route"])
    out: list[str] = []
    if _windows():
        for m in re.finditer(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s", text, re.M):
            out.append(m.group(1))
    else:
        for m in re.finditer(r"^default via (\d+\.\d+\.\d+\.\d+)", text, re.M):
            out.append(m.group(1))
    return [g for g in dict.fromkeys(out) if _valid_v4(g)]


def neighbours(run: Run = _run) -> list[str]:
    """Addresses this device has recently talked to on its own networks."""
    if _windows():
        text = run(["arp", "-a"])
        found = re.findall(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+[0-9a-fA-F-]{17}\s", text, re.M)
    else:
        text = run(["ip", "-4", "neigh"]) or run(["arp", "-an"])
        found = re.findall(r"^(\d+\.\d+\.\d+\.\d+)\s", text, re.M)
        found += re.findall(r"\((\d+\.\d+\.\d+\.\d+)\)", text)
    return [n for n in dict.fromkeys(found) if _valid_v4(n)]


def parse_netsh_wifi(text: str) -> list[dict]:
    """`netsh wlan show networks mode=bssid`: [{"name", "signal"}] with signal 0-100."""
    out: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        m = re.match(r"^\s*SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            current = {"name": m.group(1).strip(), "signal": 0}
            out.append(current)
            continue
        m = re.match(r"^\s*Signal\s*:\s*(\d+)\s*%", line)
        if m and current is not None:
            current["signal"] = max(current["signal"], int(m.group(1)))
    return [o for o in out if o["name"]]


def parse_nmcli_wifi(text: str) -> list[dict]:
    """`nmcli -t -f SSID,SIGNAL dev wifi`: colons inside a name are escaped as \\:."""
    out: list[dict] = []
    for line in text.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) < 2:
            continue
        name = parts[0].replace("\\:", ":").strip()
        try:
            signal = int(parts[-1])
        except ValueError:
            signal = 0
        if name:
            out.append({"name": name, "signal": signal})
    return out


def wifi_signals(run: Run = _run, prefix: str = WIFI_PREFIX) -> list[dict]:
    """Nearby Wi-Fi networks whose name starts with the prefix, strongest first."""
    if _windows():
        seen = parse_netsh_wifi(run(["netsh", "wlan", "show", "networks", "mode=bssid"]))
    elif sys.platform == "darwin":
        seen = []     # macOS no longer ships a command-line scanner
    else:
        seen = parse_nmcli_wifi(run(["nmcli", "-t", "-f", "SSID,SIGNAL", "dev", "wifi"]))
    best: dict[str, dict] = {}
    for item in seen:
        if item["name"].lower().startswith(prefix.lower()):
            if item["name"] not in best or item["signal"] > best[item["name"]]["signal"]:
                best[item["name"]] = item
    return sorted(best.values(), key=lambda i: -i["signal"])


# -- the network -------------------------------------------------------------------

def private_only(host: str) -> bool:
    """True for addresses on a private or link-local network. Never public ones."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.version == 4 and (addr.is_private or addr.is_link_local) and not addr.is_loopback \
        and not addr.is_unspecified and not addr.is_multicast


def tcp_open(host: str, port: int) -> bool:
    if not private_only(host):
        return False
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def fetch_front_page(host: str, port: int) -> bytes | None:
    """GET / over TLS without checking the certificate (it is self-signed) and without
    sending anything but the request line. The page is only read, never trusted: the
    wizard still asks the person to compare the certificate fingerprint."""
    if not private_only(host):
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=PAGE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=None) as tls:
                tls.settimeout(PAGE_TIMEOUT)
                tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
                            "User-Agent: pazuzu-find\r\nAccept: text/html\r\n\r\n".encode("ascii"))
                data = b""
                while len(data) < READ_LIMIT:
                    chunk = tls.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                return data
    except (OSError, ssl.SSLError):
        return None


def server_header_says_opnsense(page: bytes | None) -> bool:
    """The firewall's own web server names itself in the reply headers (seen on 26.7: "Server: OPNsense")."""
    if not page:
        return False
    head = page.split(b"\r\n\r\n", 1)[0].lower()
    return any(line.strip().startswith(b"server:") and b"opnsense" in line for line in head.split(b"\r\n"))


def looks_like_opnsense(page: bytes | None) -> bool:
    """The reply header names it, or the page does. Never the host name, which anyone can change."""
    if not page:
        return False
    if server_header_says_opnsense(page):
        return True
    low = page.lower()
    return any(sig in low for sig in SIGNATURES)


def _subnet_hosts(address: str) -> list[str]:
    net = ipaddress.ip_network(f"{address}/24", strict=False)
    own = ipaddress.ip_address(address)
    return [str(h) for h in net.hosts() if h != own]


def candidate_hosts(mine: Iterable[str], gateways: Iterable[str], neighbour_list: Iterable[str],
                    typed: Iterable[str] = (), launch: Iterable[str] = ()) -> list[tuple[str, str]]:
    """[(host, why)] in the order they should be tried. Private addresses only, capped."""
    order: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(host: str, why: str) -> None:
        if host not in seen and private_only(host) and not ipaddress.ip_address(host).is_link_local:
            seen.add(host)
            order.append((host, why))

    for host in typed:
        add(host, "the address you gave")
    for host in launch:
        add(host, "the address the wizard started with")
    for host in gateways:
        add(host, "this device's gateway")
    for host in neighbour_list:
        add(host, "a device this device has seen")
    usable = [m for m in mine if private_only(m) and not ipaddress.ip_address(m).is_link_local]
    for address in usable:
        base = _subnet_hosts(address)
        by_last = {h.rsplit(".", 1)[1]: h for h in base}
        for last in LIKELY_LAST:
            if str(last) in by_last:
                add(by_last[str(last)], "a usual firewall address")
    for address in usable:
        for host in _subnet_hosts(address):
            add(host, "this network")
    return order[:MAX_HOSTS]


def find_firewall(
    *,
    typed: Iterable[str] = (),
    launch: Iterable[str] = (),
    extra_ports: Iterable[int] = (),
    run: Run = _run,
    connect: Connect = tcp_open,
    fetch: Fetch = fetch_front_page,
    addresses: Callable[[], list[str]] | None = None,
    workers: int = 48,
    wifi: bool = True,
) -> Report:
    report = Report()
    mine_all = addresses() if addresses is not None else local_addresses(run)
    report.mine = [m for m in mine_all
                   if private_only(m) and not ipaddress.ip_address(m).is_link_local]
    report.link_only = (not report.mine) and any(
        _valid_v4(m) and ipaddress.ip_address(m).is_link_local for m in mine_all)

    ports = tuple(dict.fromkeys([*GUI_PORTS, *(int(p) for p in extra_ports)]))
    candidates = candidate_hosts(report.mine, default_gateways(run), neighbours(run), typed, launch)
    report.looked = len(candidates)

    more = tuple(dict.fromkeys([*ports, *MORE_PORTS]))

    def check(item: tuple[str, str]) -> Found | None:
        host, why = item
        for port in (ports if why == "this network" else more):
            if connect(host, port) and looks_like_opnsense(fetch(host, port)):
                return Found(host, port, why)
        return None

    if candidates:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for hit in pool.map(check, candidates):
                if hit is not None:
                    report.found.append(hit)

    if wifi:
        report.wifi = wifi_signals(run)

    if report.found:
        report.note = ""
    elif report.link_only:
        report.note = ("This device has no usable address yet, only 169.254.x.x. The firewall is not "
                       "handing out addresses on this cable. Give this device a fixed address in the "
                       "firewall's range, or tell me the firewall's address.")
    elif not report.mine:
        report.note = "This device is not on any network right now. Plug in or join Wi-Fi first."
    else:
        report.note = ("No OPNsense answered on the networks this device is on. Check the cable is in "
                       "the port labelled LAN (or 1), or tell me the firewall's address.")
    return report


SEARCH_SECONDS = 120.0
MAX_OPEN_TO_ASK = 64


def search_harder(
    host: str,
    *,
    connect: Connect = tcp_open,
    fetch: Fetch = fetch_front_page,
    workers: int = 256,
    seconds: float = SEARCH_SECONDS,
    clock: Callable[[], float] | None = None,
    skip: Iterable[int] = (),
) -> Report:
    """Look at every port on ONE private address, for a firewall whose page was moved somewhere unusual.

    Opt-in: the person asks for it and names the address. It only connects and reads the front page of
    whatever answers, the same as the quick search does. It stops after `seconds` and says so."""
    import time as _time
    now = clock or _time.monotonic
    report = Report()
    host = (host or "").strip()
    if not private_only(host):
        report.note = "That is not a private address, so I will not look there."
        return report
    report.mine = []
    skipped = set(int(p) for p in skip)
    ports = [p for p in range(1, 65536) if p not in skipped]
    report.looked = len(ports)
    deadline = now() + seconds
    opened: list[int] = []
    cut_short = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for start in range(0, len(ports), 2048):
            if now() > deadline:
                cut_short = True
                break
            chunk = ports[start:start + 2048]
            for port, ok in zip(chunk, pool.map(lambda p: connect(host, p), chunk)):
                if ok:
                    opened.append(port)
    if len(opened) > MAX_OPEN_TO_ASK:
        report.note = (f"{len(opened)} ports answered on that address, which is too many to be a firewall "
                       "page. Something there answers on every port.")
        return report
    for port in opened:
        if looks_like_opnsense(fetch(host, port)):
            report.found.append(Found(host, port, "a full port search"))
    if report.found:
        report.note = ""
    elif cut_short:
        report.note = "I ran out of time before every port was checked, and found no OPNsense page yet."
    elif opened:
        report.note = f"{len(opened)} ports answered on that address, but none showed an OPNsense page."
    else:
        report.note = "Nothing answered on any port at that address. Check the address and the cable."
    return report
