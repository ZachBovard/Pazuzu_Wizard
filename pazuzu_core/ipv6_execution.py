from copy import deepcopy


class ApprovalRequired(RuntimeError):
    pass


class ExecutionFailed(RuntimeError):
    pass


WRITABLE_SETTINGS = (
    "disablechecksumoffloading",
    "disablesegmentationoffloading",
    "disablelargereceiveoffloading",
    "disablevlanhwfilter",
    "disableipv6",
    "dhcp6_debug",
    "dhcp6_norelease",
    "dhcp6_ratimeout",
    "dhcp6_duid",
)


def _picked(value):
    """A pick-list as the firewall reads it back (a list of {"value", "selected"} options, or a dict of them keyed by
    option) is sent back as the key of the selected option, which is what the save takes. A plain value is left as it is.
    Sending the list itself back made the save fail with a server error on 26.7."""
    if isinstance(value, list) and value and all(isinstance(x, dict) and "selected" in x for x in value):
        for index, option in enumerate(value):
            if str(option.get("selected")) in ("1", "True", "true"):
                return str(index)
        return ""
    if isinstance(value, dict) and value and all(isinstance(x, dict) and "selected" in x for x in value.values()):
        for key, option in value.items():
            if str(option.get("selected")) in ("1", "True", "true"):
                return str(key)
        return ""
    return value


def _settings_from(response):
    try:
        settings = response["settings"]
        return {key: _picked(settings[key]) for key in WRITABLE_SETTINGS}
    except (KeyError, TypeError) as exc:
        raise ExecutionFailed("Invalid settings/get response") from exc


def execute_disable_ipv6(client, *, approved=False):
    if not approved:
        raise ApprovalRequired("Explicit approval is required")

    original = _settings_from(client.get_settings())
    before = original["disableipv6"]

    if before == "1":
        return {
            "status": "already_applied",
            "before": "1",
            "after": "1",
            "rollback_available": False,
        }

    if before != "0":
        raise ExecutionFailed(
            f"Unexpected disableipv6 value: {before!r}"
        )

    desired = deepcopy(original)
    desired["disableipv6"] = "1"

    try:
        save_response = client.set_settings({"settings": desired})
        if save_response != {"result": "saved"}:
            raise ExecutionFailed(
                f"Unexpected save response: {save_response!r}"
            )

        apply_response = client.reconfigure({})
        if apply_response != {"status": "ok"}:
            raise ExecutionFailed(
                f"Unexpected reconfigure response: {apply_response!r}"
            )

        after = _settings_from(
            client.get_settings()
        )["disableipv6"]

        if after != "1":
            raise ExecutionFailed(
                f"Verification failed: disableipv6={after!r}"
            )

    except Exception as apply_error:
        try:
            rollback_save = client.set_settings(
                {"settings": original}
            )
            if rollback_save != {"result": "saved"}:
                raise ExecutionFailed(
                    f"Rollback save failed: {rollback_save!r}"
                )

            rollback_apply = client.reconfigure({})
            if rollback_apply != {"status": "ok"}:
                raise ExecutionFailed(
                    "Rollback reconfigure failed: "
                    f"{rollback_apply!r}"
                )

            restored = _settings_from(
                client.get_settings()
            )["disableipv6"]

            if restored != before:
                raise ExecutionFailed(
                    "Rollback verification failed: "
                    f"disableipv6={restored!r}"
                )

        except Exception as rollback_error:
            raise ExecutionFailed(
                f"Apply failed ({apply_error}) and rollback failed ({rollback_error})"
            ) from apply_error

        raise ExecutionFailed(
            "IPv6-disable transaction failed and was rolled back: "
            f"{apply_error}"
        ) from apply_error

    return {
        "status": "applied",
        "before": before,
        "after": after,
        "rollback_available": True,
    }
