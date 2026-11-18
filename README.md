# Pazuzu beta 1 (build 564)

Pazuzu sets up your OPNsense firewall, over the firewall's own API.

No OPNsense yet? [docs/GETTING_OPNSENSE.md](docs/GETTING_OPNSENSE.md) says how to download it, and how to install it or
try it from a live disc.

It needs OPNsense 26.7 or newer. This is a beta: it changes your firewall, so save a backup of the firewall's
configuration first and keep a way back in.

## Run it

You need Python 3.11 or newer (python.org). Once, in a Command Prompt or PowerShell:

    py -m pip install requests cryptography

Then start it from this folder:

    py -m pazuzu_core.wizard_server

It opens the setup in your browser.

The Hanbi plugin and the manager are closed and are not in this repository. A few files that only work with them are
left out too, so some choices do not show in a copy run from here.

## Taking part

Beta 1 is a community collaboration. Fixes, firewalls the wizard got wrong, clearer words and plain reports are all
welcome: [CONTRIBUTING.md](CONTRIBUTING.md) says how to propose a change and what happens to it. Results from your own
hardware go in [Hanbi_Hardware](https://github.com/ZachBovard/Hanbi_Hardware).

## Licence and credits

Licence: Apache-2.0 ([LICENSE](LICENSE), [NOTICE.md](NOTICE.md)). Credits: [docs/ATTRIBUTIONS.md](docs/ATTRIBUTIONS.md).
Other people's licences: [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).
A security problem: [SECURITY.md](SECURITY.md) (security@hanbi.net, not a public issue).

Pazuzu is an independent tool for OPNsense. OPNsense is a trademark of Deciso B.V.; Pazuzu is not part of the
OPNsense project and is not endorsed by Deciso. Zenarmor is a product of Sunny Valley Networks, under its own terms;
Pazuzu is not affiliated with or endorsed by Sunny Valley Networks.
