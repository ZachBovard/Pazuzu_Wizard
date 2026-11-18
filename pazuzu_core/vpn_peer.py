"""One WireGuard peer for one device, made on this device, shown once, and never kept.

The firewall makes the peer's keys itself when it is asked to. Here the person makes them instead,
so the phone's private key never has to pass through the firewall's page or a screenshot of it. The
private key is drawn once as a QR code for the phone's WireGuard app. Only the PUBLIC key (and the
tunnel address) goes into the firewall's peer form.

Nothing in this file writes a file, talks to a network, or touches a firewall.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import secrets

from pazuzu_core import qr

DEFAULT_PORT = 51820
KEEPALIVE = 25
FULL_TUNNEL = "0.0.0.0/0, ::/0"
_NAME = re.compile(r"[^A-Za-z0-9._-]")
_HOST = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class PeerError(ValueError):
    pass


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _x25519():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    except ImportError:
        raise PeerError("Making keys needs the cryptography package. Install it with: python -m pip install cryptography")
    return serialization, X25519PrivateKey


def new_keypair() -> tuple[str, str]:
    serialization, X25519PrivateKey = _x25519()
    key = X25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _b64(private), _b64(public)


def new_preshared() -> str:
    return _b64(secrets.token_bytes(32))


def public_of(private_b64: str) -> str:
    serialization, X25519PrivateKey = _x25519()
    raw = _key32(private_b64, "private key")
    key = X25519PrivateKey.from_private_bytes(raw)
    return _b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _key32(text, what: str) -> bytes:
    try:
        raw = base64.b64decode(str(text or "").strip(), validate=True)
    except (ValueError, TypeError):
        raise PeerError(f"The {what} should be 44 letters and digits, ending in =.")
    if len(raw) != 32:
        raise PeerError(f"The {what} should be 44 letters and digits, ending in =.")
    return raw


def device_name(raw) -> str:
    name = _NAME.sub("", " ".join(str(raw or "").split()).replace(" ", "-"))[:32]
    if not re.search(r"[A-Za-z0-9]", name):
        raise PeerError("Give this device a name, like alex-phone.")
    return name


def tunnel_address(raw) -> str:
    """This device's own address inside the tunnel, as a /32. Private IPv4 only."""
    try:
        iface = ipaddress.ip_interface(str(raw or "").strip())
    except ValueError:
        raise PeerError("The tunnel address should look like 10.91.5.2.")
    if iface.version != 4 or not iface.ip.is_private or iface.ip.is_loopback or iface.ip.is_link_local:
        raise PeerError("The tunnel address should be a private one, like 10.91.5.2.")
    return f"{iface.ip}/32"


def next_address(instance_address) -> str:
    """The address after the firewall's own one on its tunnel network (10.91.5.1/24 gives 10.91.5.2)."""
    try:
        iface = ipaddress.ip_interface(str(instance_address or "").strip())
    except ValueError:
        raise PeerError("The firewall's tunnel address should look like 10.91.5.1/24.")
    if iface.version != 4 or not iface.ip.is_private:
        raise PeerError("The firewall's tunnel address should be a private one, like 10.91.5.1/24.")
    nxt = iface.ip + 1
    if nxt not in iface.network or nxt == iface.network.broadcast_address:
        raise PeerError("That tunnel network has no room for another device.")
    return str(nxt)


def next_free_address(instance_address, used) -> str:
    """The first host address in the firewall's tunnel network that no device has (the firewall holds the first)."""
    try:
        iface = ipaddress.ip_interface(str(instance_address or "").strip())
    except ValueError:
        raise PeerError("The firewall's tunnel address should look like 10.91.5.1/24.")
    taken = {iface.ip}
    for u in used:
        for part in str(u or "").split(","):
            try:
                taken.add(ipaddress.ip_interface(part.strip()).ip)
            except ValueError:
                continue
    for host in iface.network.hosts():
        if host not in taken:
            return str(host)
    raise PeerError("That tunnel network has no room for another device.")


def endpoint(host, port) -> str:
    h = str(host or "").strip()
    try:
        ipaddress.IPv4Address(h)
    except ValueError:
        if not _HOST.match(h) or "." not in h:
            raise PeerError("The firewall's outside address should be a name like home.example.net, or a number.")
    try:
        p = int(port) if str(port or "").strip() else DEFAULT_PORT
    except ValueError:
        raise PeerError("The port should be a number.")
    if not 1 <= p <= 65535:
        raise PeerError("The port should be between 1 and 65535.")
    return f"{h}:{p}"


def allowed_ips(mode, networks) -> str:
    if mode == "full":
        return FULL_TUNNEL
    parts = [x.strip() for x in str(networks or "").replace(";", ",").split(",") if x.strip()]
    if not parts:
        raise PeerError("Type the networks to reach, like 192.168.1.0/24, or choose everything.")
    out = []
    for item in parts:
        try:
            out.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            raise PeerError(f"{item[:40]} is not a network. Use the form 192.168.1.0/24.")
    return ", ".join(out)


def dns_line(raw) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        ipaddress.ip_address(text)
    except ValueError:
        raise PeerError("The name server should be a number like 10.91.5.1.")
    return text


def config_text(private, address, server_public, ep, allowed, dns="", preshared=None) -> str:
    lines = ["[Interface]", f"PrivateKey = {private}", f"Address = {address}"]
    if dns:
        lines.append(f"DNS = {dns}")
    lines += ["", "[Peer]", f"PublicKey = {server_public}"]
    if preshared:
        lines.append(f"PresharedKey = {preshared}")
    lines += [f"AllowedIPs = {allowed}", f"Endpoint = {ep}", f"PersistentKeepalive = {KEEPALIVE}", ""]
    return "\n".join(lines)


def make(*, name, server_public, host, port, address, mode, networks="", dns="", use_preshared=False) -> dict:
    """The keys, the phone's settings as text and as a QR picture, and what to type into the firewall."""
    dev = device_name(name)
    _key32(server_public, "firewall's public key")
    addr = tunnel_address(address)
    ep = endpoint(host, port)
    allowed = allowed_ips(mode, networks)
    dns_v = dns_line(dns)
    private, public = new_keypair()
    psk = new_preshared() if use_preshared else None
    text = config_text(private, addr, str(server_public).strip(), ep, allowed, dns_v, psk)
    try:
        svg = qr.svg(qr.encode(text, "L"), label=f"WireGuard settings for {dev}")
    except qr.QrError:
        svg = ""
    form = [["Name", dev], ["Public key", public], ["Allowed IPs", addr],
            ["Endpoint address and port", "leave empty (the phone connects to the firewall)"],
            ["Instance", "tick the instance you made"]]
    if psk:
        form.insert(2, ["Pre-shared key", psk])
    return {"device": dev, "public": public, "address": addr, "config": text, "svg": svg, "form": form,
            "preshared": psk}


def wan_hint(address) -> dict:
    """What the firewall's outside address says about whether a VPN can be reached from outside."""
    text = str(address or "").strip()
    if not text:
        return {"kind": "unknown", "say": ""}
    try:
        ip = ipaddress.ip_address(text.split("/")[0])
    except ValueError:
        raise PeerError("That is not an address. Type it like 203.0.113.7.")
    if ip.version == 6:
        return {"kind": "ok", "say": "An IPv6 address. Fine, as long as your phone's network has IPv6 too."}
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return {"kind": "unusable", "say": "That is not an address the internet can reach."}
    if any(ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
        return {"kind": "example", "say": "That is an example address used in guides, not a real one. Type the one your firewall shows for its Internet side."}
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return {"kind": "cgnat", "say": "Your provider shares one public address between many homes (CGNAT). A VPN cannot be reached from outside like this. Ask your provider for a public address, or use a provider-side option."}
    if ip.is_private:
        return {"kind": "double_nat", "say": "The outside port has a private address, so another router sits in front of this firewall. Forward the VPN port on that router to this firewall, or put that router in bridge mode."}
    return {"kind": "ok", "say": "A public address. A VPN can be reached from outside. It may change, so use a dynamic DNS name rather than the number."}
