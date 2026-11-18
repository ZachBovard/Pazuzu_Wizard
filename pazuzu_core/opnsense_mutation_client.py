from __future__ import annotations

import os
from typing import Any
from uuid import UUID

import requests

from pazuzu_core.opnsense_client import _base_url, _required_env, _tls_setting


def _validated_uuid(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"Invalid alias UUID: {value!r}") from exc


def _validated_rule_uuid(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"Invalid firewall-rule UUID: {value!r}") from exc


# The only rule fields set_firewall_rule_fields may change. Everything else
# about a rule (action, interface, ports, enabled) goes through other
# methods or not at all.
SETTABLE_RULE_FIELDS = frozenset({"description", "source_net"})
_FIELD_LIMIT = 255


def _validated_rule_fields(fields: Any) -> dict[str, str]:
    if not isinstance(fields, dict) or not fields:
        raise ValueError("Rule fields must be a non-empty object")

    unknown = sorted(set(fields) - SETTABLE_RULE_FIELDS)
    if unknown:
        raise ValueError(f"Rule fields not allowed: {', '.join(map(str, unknown))}")

    checked: dict[str, str] = {}
    for name, value in fields.items():
        if (
            not isinstance(value, str)
            or len(value) > _FIELD_LIMIT
            or any(ord(char) < 32 for char in value)
        ):
            raise ValueError(
                f"Rule field {name!r} must be text of at most {_FIELD_LIMIT} "
                "characters without control characters"
            )
        checked[name] = value
    return checked


class OPNsenseMutationClient:
    """Narrow client for verified OPNsense mutation lifecycles."""

    def __init__(self) -> None:
        self.base_url = _base_url()
        self.timeout = float(os.getenv("OPNSENSE_TIMEOUT", "10"))

        self.session = requests.Session()
        from pazuzu_core import activity
        activity.watch(self.session)
        self.session.max_redirects = 0
        self.session.auth = (
            _required_env("OPNSENSE_API_KEY"),
            _required_env("OPNSENSE_API_SECRET"),
        )
        self.session.verify = _tls_setting()
        # Ignore proxy and CA-bundle environment variables: left on, an
        # exported REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE overrides the
        # session's own verify setting (and a proxy variable could carry
        # the API credentials somewhere else). Use OPNSENSE_CA_BUNDLE.
        self.session.trust_env = False

    def get_alias(self, alias_uuid: str) -> Any:
        alias_uuid = _validated_uuid(alias_uuid)
        response = self.session.get(
            f"{self.base_url}/api/firewall/alias/get_item/{alias_uuid}",
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def set_alias(
        self,
        alias_uuid: str,
        payload: dict[str, Any],
    ) -> Any:
        alias_uuid = _validated_uuid(alias_uuid)
        response = self.session.post(
            f"{self.base_url}/api/firewall/alias/set_item/{alias_uuid}",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def add_alias(self, alias: dict[str, Any]) -> Any:
        response = self.session.post(
            f"{self.base_url}/api/firewall/alias/add_item",
            json={"alias": alias},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def delete_alias(self, alias_uuid: str) -> Any:
        alias_uuid = _validated_uuid(alias_uuid)
        response = self.session.post(
            f"{self.base_url}/api/firewall/alias/del_item/{alias_uuid}",
            json={},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def reconfigure_aliases(self) -> Any:
        response = self.session.post(
            f"{self.base_url}/api/firewall/alias/reconfigure",
            json={},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def get_firewall_rule_template(self) -> Any:
        response = self.session.get(
            f"{self.base_url}/api/firewall/filter/get_rule",
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def get_firewall_interfaces(self) -> Any:
        response = self.session.get(
            f"{self.base_url}/api/firewall/filter/get_interface_list",
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def add_firewall_rule(self, rule: dict[str, Any]) -> Any:
        response = self.session.post(
            f"{self.base_url}/api/firewall/filter/add_rule",
            json={"rule": rule},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def get_firewall_rule(self, rule_uuid: str) -> Any:
        rule_uuid = _validated_rule_uuid(rule_uuid)
        response = self.session.get(
            f"{self.base_url}/api/firewall/filter/get_rule/{rule_uuid}",
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def toggle_firewall_rule(self, rule_uuid: str, enabled: bool) -> Any:
        """Set a rule on or off. Always explicit: never a flip."""

        rule_uuid = _validated_rule_uuid(rule_uuid)
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be True or False")

        flag = "1" if enabled else "0"
        response = self.session.post(
            f"{self.base_url}/api/firewall/filter/toggle_rule/{rule_uuid}/{flag}",
            json={},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def set_firewall_rule_fields(
        self,
        rule_uuid: str,
        fields: dict[str, str],
    ) -> Any:
        """Change only the named fields of a rule (see SETTABLE_RULE_FIELDS).

        Sends just the given fields. That OPNsense leaves the other fields
        of the rule alone has not been proven against the firewall yet.
        """

        rule_uuid = _validated_rule_uuid(rule_uuid)
        checked = _validated_rule_fields(fields)

        response = self.session.post(
            f"{self.base_url}/api/firewall/filter/set_rule/{rule_uuid}",
            json={"rule": checked},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def delete_firewall_rule(self, rule_uuid: str) -> Any:
        rule_uuid = _validated_rule_uuid(rule_uuid)
        response = self.session.post(
            f"{self.base_url}/api/firewall/filter/del_rule/{rule_uuid}",
            json={},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def apply_firewall_rules(self) -> Any:
        response = self.session.post(
            f"{self.base_url}/api/firewall/filter/apply",
            json={},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self.session.close()
