"""External gateway policy hook (OPA / cedar-agent style).

When BROKER_GATEWAY_POLICY_URL is set, every gateway request that passes the
built-in checks (grant, method/path, limits) is additionally submitted to the
external policy endpoint as an OPA-data-API-shaped document:

    POST <url>
    {"input": {"tenant": ..., "agent": {...}, "route": {...},
               "request": {"method": ..., "path": ...}, "scopes": [...]}}

The decision is read from the response: a bare `{"result": true}` (an OPA
boolean rule) or `{"result": {"allow": true}}` (an OPA object rule /
cedar-agent) allows; anything else denies. Errors and timeouts deny by
default — fail-closed — unless BROKER_GATEWAY_POLICY_FAIL_OPEN is set (for
deployments that treat the hook as advisory).

Module-level _post is a seam for tests.
"""

import httpx

from .config import get_settings


def _post(url: str, document: dict, timeout: float) -> dict:
    resp = httpx.post(url, json=document, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def enabled() -> bool:
    return bool(get_settings().gateway_policy_url)


def evaluate(input_doc: dict) -> tuple[bool, str]:
    """Returns (allowed, reason). Never raises."""
    settings = get_settings()
    try:
        body = _post(
            settings.gateway_policy_url,
            {"input": input_doc},
            settings.gateway_policy_timeout_seconds,
        )
    except Exception as exc:
        if settings.gateway_policy_fail_open:
            return True, f"policy_unreachable_fail_open:{type(exc).__name__}"
        return False, "policy_unreachable"

    result = body.get("result")
    if result is True:
        return True, "policy_allow"
    if isinstance(result, dict) and result.get("allow") is True:
        return True, "policy_allow"
    return False, "policy_deny"
