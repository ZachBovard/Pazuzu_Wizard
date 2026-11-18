# Credits

Pazuzu stands on other people's work. Thank you to:

- Python, by the Python Software Foundation (PSF License)
- requests, and the libraries it uses (urllib3, idna, charset-normalizer, certifi)
- cryptography, by the Python Cryptographic Authority
- the block list authors, credited below

Each part keeps its own licence; the full texts ship with Pazuzu in THIRD-PARTY-LICENSES.

## Block lists

Pazuzu does not copy or change any block list. It tells your firewall where each list lives, and your firewall
downloads it directly from its author. The lists are the work of:

- HaGeZi — https://github.com/hagezi/dns-blocklists
- Steven Black — https://github.com/StevenBlack/hosts
- OISD — https://oisd.nl
- r0xd4n3t (Pi-hole lists, a list of lists) — https://github.com/r0xd4n3t/pihole-adlists
- The ad lists your firewall offers itself, which Pazuzu switches on by name: AdAway, AdGuard, EasyList and Peter
  Lowe's list (yoyo.org)

If a list blocks something it shouldn't, please tell its author.

## Packet inspection rules

When packet inspection is switched on, your firewall downloads its rules from their authors through its own Intrusion
Detection pages: the abuse.ch lists, and the Emerging Threats Open rules (which include the DShield and Spamhaus DROP
lists). Pazuzu copies none of them.

## OPNsense and Zenarmor

Pazuzu is an independent tool for OPNsense. OPNsense is a trademark of Deciso B.V.; Pazuzu is not part of the OPNsense
project and is not endorsed by Deciso. Zenarmor is a product of Sunny Valley Networks, under its own terms; Pazuzu is
not affiliated with or endorsed by Sunny Valley Networks.
