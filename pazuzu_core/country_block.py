"""Block whole countries from reaching the firewall from the internet (inbound only).

What gets added, all in one passkey-approved step and all undoable:
  1. a country list on the firewall (a GeoIP alias) holding the countries the person picked;
  2. a rule, ahead of the block, that always lets the VPN's own port through;
  3. a rule, ahead of the block, that always lets traffic for the public-servers (DMZ) network through;
  4. one logged rule on the internet port that blocks the picked countries.
The exceptions come first on purpose: a blocked country can never cut off the VPN or a public server,
and a mistake in the country list can never lock the owner out of the VPN.
Outbound blocking is a separate, later choice. The firewall needs its country database; if it has
none, the block simply matches nothing, and the page says so.
Nothing in this file touches a firewall; the write engine does, from pages the probe has seen.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

KEY = "country_block"
CHOICES_FILE = "choices.json"
ALIAS = "PZ_blocked_countries"
SEQ_VPN, SEQ_DMZ, SEQ_BLOCK = "11", "12", "13"
MAX_PICKED = 250
_CODE = re.compile(r"^[A-Z]{2}$")

COUNTRIES: tuple[tuple[str, str], ...] = tuple(
    tuple(x.split("|")) for x in (
        "AF|Afghanistan,AX|Åland Islands,AL|Albania,DZ|Algeria,AS|American Samoa,AD|Andorra,AO|Angola,"
        "AI|Anguilla,AQ|Antarctica,AG|Antigua and Barbuda,AR|Argentina,AM|Armenia,AW|Aruba,AU|Australia,"
        "AT|Austria,AZ|Azerbaijan,BS|Bahamas,BH|Bahrain,BD|Bangladesh,BB|Barbados,BY|Belarus,BE|Belgium,"
        "BZ|Belize,BJ|Benin,BM|Bermuda,BT|Bhutan,BO|Bolivia,BQ|Bonaire, Sint Eustatius and Saba,"
        "BA|Bosnia and Herzegovina,BW|Botswana,BV|Bouvet Island,BR|Brazil,IO|British Indian Ocean Territory,"
        "BN|Brunei,BG|Bulgaria,BF|Burkina Faso,BI|Burundi,CV|Cabo Verde,KH|Cambodia,CM|Cameroon,CA|Canada,"
        "KY|Cayman Islands,CF|Central African Republic,TD|Chad,CL|Chile,CN|China,CX|Christmas Island,"
        "CC|Cocos (Keeling) Islands,CO|Colombia,KM|Comoros,CG|Congo,CD|Congo (Democratic Republic),"
        "CK|Cook Islands,CR|Costa Rica,CI|Côte d'Ivoire,HR|Croatia,CU|Cuba,CW|Curaçao,CY|Cyprus,"
        "CZ|Czechia,DK|Denmark,DJ|Djibouti,DM|Dominica,DO|Dominican Republic,EC|Ecuador,EG|Egypt,"
        "SV|El Salvador,GQ|Equatorial Guinea,ER|Eritrea,EE|Estonia,SZ|Eswatini,ET|Ethiopia,"
        "FK|Falkland Islands,FO|Faroe Islands,FJ|Fiji,FI|Finland,FR|France,GF|French Guiana,"
        "PF|French Polynesia,TF|French Southern Territories,GA|Gabon,GM|Gambia,GE|Georgia,DE|Germany,"
        "GH|Ghana,GI|Gibraltar,GR|Greece,GL|Greenland,GD|Grenada,GP|Guadeloupe,GU|Guam,GT|Guatemala,"
        "GG|Guernsey,GN|Guinea,GW|Guinea-Bissau,GY|Guyana,HT|Haiti,HM|Heard Island and McDonald Islands,"
        "VA|Holy See,HN|Honduras,HK|Hong Kong,HU|Hungary,IS|Iceland,IN|India,ID|Indonesia,IR|Iran,"
        "IQ|Iraq,IE|Ireland,IM|Isle of Man,IL|Israel,IT|Italy,JM|Jamaica,JP|Japan,JE|Jersey,JO|Jordan,"
        "KZ|Kazakhstan,KE|Kenya,KI|Kiribati,KP|North Korea,KR|South Korea,KW|Kuwait,KG|Kyrgyzstan,"
        "LA|Laos,LV|Latvia,LB|Lebanon,LS|Lesotho,LR|Liberia,LY|Libya,LI|Liechtenstein,LT|Lithuania,"
        "LU|Luxembourg,MO|Macao,MG|Madagascar,MW|Malawi,MY|Malaysia,MV|Maldives,ML|Mali,MT|Malta,"
        "MH|Marshall Islands,MQ|Martinique,MR|Mauritania,MU|Mauritius,YT|Mayotte,MX|Mexico,"
        "FM|Micronesia,MD|Moldova,MC|Monaco,MN|Mongolia,ME|Montenegro,MS|Montserrat,MA|Morocco,"
        "MZ|Mozambique,MM|Myanmar,NA|Namibia,NR|Nauru,NP|Nepal,NL|Netherlands,NC|New Caledonia,"
        "NZ|New Zealand,NI|Nicaragua,NE|Niger,NG|Nigeria,NU|Niue,NF|Norfolk Island,MK|North Macedonia,"
        "MP|Northern Mariana Islands,NO|Norway,OM|Oman,PK|Pakistan,PW|Palau,PS|Palestine,PA|Panama,"
        "PG|Papua New Guinea,PY|Paraguay,PE|Peru,PH|Philippines,PN|Pitcairn,PL|Poland,PT|Portugal,"
        "PR|Puerto Rico,QA|Qatar,RE|Réunion,RO|Romania,RU|Russia,RW|Rwanda,BL|Saint Barthélemy,"
        "SH|Saint Helena,KN|Saint Kitts and Nevis,LC|Saint Lucia,MF|Saint Martin,"
        "PM|Saint Pierre and Miquelon,VC|Saint Vincent and the Grenadines,WS|Samoa,SM|San Marino,"
        "ST|Sao Tome and Principe,SA|Saudi Arabia,SN|Senegal,RS|Serbia,SC|Seychelles,SL|Sierra Leone,"
        "SG|Singapore,SX|Sint Maarten,SK|Slovakia,SI|Slovenia,SB|Solomon Islands,SO|Somalia,"
        "ZA|South Africa,GS|South Georgia and the South Sandwich Islands,SS|South Sudan,ES|Spain,"
        "LK|Sri Lanka,SD|Sudan,SR|Suriname,SJ|Svalbard and Jan Mayen,SE|Sweden,CH|Switzerland,SY|Syria,"
        "TW|Taiwan,TJ|Tajikistan,TZ|Tanzania,TH|Thailand,TL|Timor-Leste,TG|Togo,TK|Tokelau,TO|Tonga,"
        "TT|Trinidad and Tobago,TN|Tunisia,TR|Türkiye,TM|Turkmenistan,TC|Turks and Caicos Islands,"
        "TV|Tuvalu,UG|Uganda,UA|Ukraine,AE|United Arab Emirates,GB|United Kingdom,US|United States,"
        "UM|United States Minor Outlying Islands,UY|Uruguay,UZ|Uzbekistan,VU|Vanuatu,VE|Venezuela,"
        "VN|Vietnam,VG|Virgin Islands (British),VI|Virgin Islands (U.S.),WF|Wallis and Futuna,"
        "EH|Western Sahara,YE|Yemen,ZM|Zambia,ZW|Zimbabwe"
    ).replace(", Sint Eustatius", " Sint Eustatius").replace("Cocos (Keeling)", "Cocos (Keeling)").split(",")
)
CODES = frozenset(c for c, _n in COUNTRIES)


def clean(raw: Any) -> list[str]:
    """The picked countries, checked: real two-letter codes, no repeats, at least one."""
    if isinstance(raw, dict):
        raw = raw.get("countries")
    if not isinstance(raw, list) or any(not isinstance(x, str) for x in raw):
        raise ValueError("Pick at least one country.")
    picked = sorted({x.strip().upper() for x in raw})
    if not picked:
        raise ValueError("Pick at least one country.")
    if len(picked) > MAX_PICKED or any(not _CODE.match(x) or x not in CODES for x in picked):
        raise ValueError("That is not one of the choices.")
    return picked


MAX_SOURCE = 2000


def clean_source(raw: Any) -> str:
    """The link the firewall downloads its country ranges from, as pasted: one https link with a real host, no spaces
    or control characters. The link usually holds the person's own key, so it is never shown back or kept here."""
    from urllib.parse import urlparse
    text = raw.strip() if isinstance(raw, str) else ""
    if not text or len(text) > MAX_SOURCE or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise ValueError("Paste the whole link you copied, on one line.")
    try:
        parts = urlparse(text)
        host = parts.hostname or ""
    except ValueError:
        raise ValueError("That is not a link the firewall can download from.")
    if parts.scheme != "https" or "." not in host:
        raise ValueError("The link has to start with https and name a site.")
    return text


def source_host(link: str) -> str:
    """Only the site's name, for showing in the passkey prompt: never the path or the key after it."""
    from urllib.parse import urlparse
    return urlparse(link).hostname or ""


def load(key_dir) -> list[str] | None:
    from pazuzu_core import choices_file
    data = choices_file.read(key_dir)          # under the shared lock: never a half-written file (10 Nov 2026)
    try:
        return clean((data.get(KEY) or {}).get("countries")) if KEY in data else None
    except (ValueError, AttributeError):
        return None


def save(key_dir, raw) -> list[str]:
    from pazuzu_core import choices_file
    picked = clean(raw)
    choices_file.update(key_dir, lambda data: data.__setitem__(KEY, {"countries": picked}))
    return picked


def forget(key_dir) -> None:
    """Drop the saved country choice (after the block is taken off the firewall)."""
    from pazuzu_core import choices_file
    if KEY not in choices_file.read(key_dir):
        return
    try:
        choices_file.update(key_dir, lambda data: data.pop(KEY, None))
    except OSError:
        pass


def detect_home() -> str | None:
    """The country this device says it is in, from its own region setting. Nothing is sent anywhere.

    Windows keeps a "region" setting; other systems carry one in their language setting. The answer is only a
    suggestion: the person is asked to confirm it before anything is blocked."""
    import locale
    import os
    code = None
    if os.name == "nt":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(16)
            k = ctypes.windll.kernel32
            if hasattr(k, "GetUserDefaultGeoName") and k.GetUserDefaultGeoName(buf, 16) > 0:
                code = buf.value
            if not code:
                geo = k.GetUserGeoID(16)                  # GEOCLASS_NATION
                if geo and k.GetGeoInfoW(geo, 4, buf, 16, 0) > 0:      # GEO_ISO2
                    code = buf.value
        except Exception:
            code = None
    if not code:
        try:
            lang = locale.getlocale()[0] or locale.getdefaultlocale()[0] or ""
            code = lang.split("_")[1][:2] if "_" in lang else None
        except Exception:
            code = None
    code = (code or "").strip().upper()
    return code if code in CODES else None


def all_but(home: str) -> list[str]:
    """Every country except `home`, ready to be saved as the block list."""
    home = (home or "").strip().upper()
    if home not in CODES:
        raise ValueError("That is not one of the choices.")
    return sorted(CODES - {home})


def state(key_dir) -> dict:
    home = detect_home()
    names = dict(COUNTRIES)
    return {"saved": load(key_dir), "home": {"code": home, "name": names.get(home, "")} if home else None, "countries": [{"code": c, "name": n} for c, n in COUNTRIES],
            "alias": ALIAS,
            "says": ["Blocks the countries you pick from reaching your firewall from the internet. Every block is logged.",
                     "Your VPN and your public servers (DMZ) are let through first, so a blocked country never cuts them off.",
                     "The firewall needs its own country list for this. If it has none, the block matches nothing until it has."]}


def rule_values(kind: str, **kw) -> dict[str, str]:
    """The fields of one of the three rules, in the firewall's own words."""
    base = {"enabled": "1", "interface": kw.get("wan", "wan"), "direction": "in", "ipprotocol": "inet46"}
    # The two exceptions let things in, so they are IPv4 only: IPv6 is off everywhere here, and an enabled pass rule that
    # names IPv6 is what the IPv6 check counts as IPv6 being allowed. The block itself names both, which is harmless.
    if kind == "vpn":
        return {**base, "ipprotocol": "inet", "sequence": SEQ_VPN, "action": "pass", "protocol": "UDP", "source_net": "any",
                "destination_net": "(self)", "destination_port": str(kw["port"]), "log": "0",
                "description": "Pazuzu: let the VPN through country blocking"}
    if kind == "dmz":
        return {**base, "ipprotocol": "inet", "sequence": SEQ_DMZ, "action": "pass", "protocol": "any", "source_net": "any",
                "destination_net": str(kw["dmz"]), "log": "0",     # the whole network, by its interface name
                "description": "Pazuzu: let the public servers through country blocking"}
    return {**base, "sequence": SEQ_BLOCK, "action": "block", "protocol": "any", "source_net": ALIAS,
            "destination_net": "any", "log": "1", "description": "Pazuzu: block the listed countries (inbound)"}


DNAT = "/api/firewall/d_nat/search_rule?rowCount=-1&searchPhrase="     # Firewall, NAT, Destination NAT (port forwards)
FWD_PREFIX = "Pazuzu: let a port forward through country blocking"
_PROTO = {"tcp": "TCP", "udp": "UDP", "tcp/udp": "TCP/UDP"}
_PORT = re.compile(r"^\d{1,5}(-\d{1,5})?$")
_V4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _pick(row: dict, *keys: str) -> str:
    for k in keys:
        v = row.get(k)
        if isinstance(v, dict):                                  # a pick-list: the chosen entry
            v = next((kk for kk, vv in v.items() if isinstance(vv, dict) and str(vv.get("selected")) in ("1", "True", "true")), "")
        if v not in (None, ""):
            return str(v).strip()
    return ""


def forwards(rows: list, inside=None) -> list[dict]:
    """The port forwards, as host, port and protocol: switched on, to one IPv4 host, with a port. `inside(ip)` keeps only
    those to that network (the public-servers one). Anything not plainly that is left out (and so stays blocked)."""
    out, seen = [], set()
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        off = _pick(r, "disabled")
        if off in ("1", "true", "True") or _pick(r, "enabled") in ("0", "false", "False"):
            continue
        host = _pick(r, "target", "redirect_target", "local_ip")
        port = _pick(r, "local-port", "local_port", "localport") or _pick(r, "destination_port", "destination.port", "dstport")
        proto = _PROTO.get(_pick(r, "protocol").lower())
        if not (_V4.match(host) and _PORT.match(port) and proto):
            continue
        if inside is not None and not inside(host):
            continue
        key = (host, port, proto)
        if key not in seen:
            seen.add(key)
            out.append({"host": host, "port": port, "protocol": proto, "name": _pick(r, "descr", "description")[:60]})
    return out


def forward_rule(fwd: dict, wan: str = "wan") -> dict[str, str]:
    """The narrow exception for one port forward: from anywhere, to that host and port only, IPv4."""
    return {"enabled": "1", "interface": wan, "direction": "in", "ipprotocol": "inet", "sequence": SEQ_DMZ,
            "action": "pass", "protocol": fwd["protocol"], "source_net": "any", "destination_net": fwd["host"],
            "destination_port": fwd["port"], "log": "0",
            "description": f"{FWD_PREFIX} ({fwd['host']} {fwd['protocol']} {fwd['port']})"}


def dmz_forwards(engine, dmz_device: str) -> list[dict] | None:
    """The port forwards into the public-servers network, or None when they cannot be read (then nothing is narrowed)."""
    import ipaddress
    try:
        body = engine._req("get", "/api/interfaces/overview/interfaces_info/true")
        rows = body.get("rows") if isinstance(body, dict) else body
        nets = []
        for r in rows if isinstance(rows, list) else []:
            if isinstance(r, dict) and str(r.get("device")) == dmz_device:
                for c in (r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]):
                    try:
                        nets.append(ipaddress.ip_interface(str(c)).network)
                    except ValueError:
                        pass
        if not nets:
            return None
        got = engine._req("get", DNAT)
    except Exception:  # noqa: BLE001 (no such page, or not allowed: leave things as they are)
        return None
    rows = got.get("rows") if isinstance(got, dict) else None
    if not isinstance(rows, list):
        return None
    return forwards(rows, lambda ip: any(ipaddress.ip_address(ip) in n for n in nets))


def exception_names() -> list[str]:
    """The notes on the two exception rules (the VPN's port and the public servers), which are what an earlier build made
    as IPv4 and IPv6."""
    return [rule_values(k, port="0", dmz="0")["description"] for k in ("vpn", "dmz")]


def build_plans(engine, countries, wan_device: str | None, dmz_device: str | None, found: list | None = None) -> list:
    """Plans for the alias, the two exceptions that apply, and the block, in the order they are sent.
    Anything already on the firewall (from an earlier try) is left alone, so a second try finishes the job.
    An empty list means it is all there already; `found` is filled with what was seen, by name."""
    picked = clean(list(countries))
    wan = engine.interface_id(wan_device) or "wan"
    have = getattr(engine, "exists", lambda *a: False)

    def want(cap, values):
        key = {"geo_alias": "name", "fw_rule": "description"}[cap]
        if have(cap, values[key]):
            if found is not None:
                found.append(values[key])
            return []
        return [engine.build(cap, values)]

    plans = want("geo_alias", {"enabled": "1", "name": ALIAS, "type": "geoip", "proto": "IPv4,IPv6",
                               "content": "\n".join(picked),
                               "description": "Pazuzu: countries blocked from the internet"})
    port = engine.vpn_port()
    if port:
        plans += want("fw_rule", rule_values("vpn", wan=wan, port=port))
    if dmz_device:
        dmz = engine.interface_id(dmz_device)
        if not dmz:
            raise engine_error("Pazuzu could not find the public-servers port on the firewall, so nothing was changed.")
        fwds = dmz_forwards(engine, dmz_device)
        if fwds is None:                       # the port forwards could not be read: the whole network, as before
            plans += want("fw_rule", rule_values("dmz", wan=wan, dmz=dmz))
        else:                                  # only what the port forwards open (none: nothing is let through)
            for f in fwds:
                plans += want("fw_rule", forward_rule(f, wan))
    plans += want("fw_rule", rule_values("block", wan=wan))
    return plans


def engine_error(msg: str):
    from pazuzu_core.write_engine import WriteError
    return WriteError(msg)
