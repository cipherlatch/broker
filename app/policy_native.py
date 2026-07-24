"""Native contextual policies: curated, parameterized controls evaluated
in-process — config, not a language (DECISIONS.md 2026-07-16). Deliberately not
a rule engine: a shop needing arbitrary logic graduates to the external
OPA/Cedar hook. The layers compose as additive vetoes (built-in route checks →
these → external hook); any layer denies, fail-closed.

Types:
- change_freeze:   deny everything between two UTC instants.
- business_hours:  allow only inside a weekly window (days + local time + zone).
- cidr_fence:      allow only client IPs inside the given networks.
"""

import ipaddress
from datetime import datetime, time, timezone
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

POLICY_TYPES = ("change_freeze", "business_hours", "cidr_fence")


def _parse_dt(value, field: str) -> datetime:
    try:
        dt = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        raise HTTPException(422, f"{field} must be an ISO-8601 datetime")
    # Naive datetimes are taken as UTC.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse_hhmm(value, field: str) -> time:
    try:
        hh, mm = str(value).split(":")
        return time(int(hh), int(mm))
    except (TypeError, ValueError):
        raise HTTPException(422, f'{field} must be "HH:MM"')


def validate_params(ptype: str, params: dict) -> dict:
    """Validate + normalize params at create/update, so evaluation never meets
    malformed config (it still fails closed if it somehow does)."""
    if ptype not in POLICY_TYPES:
        raise HTTPException(422, f"type must be one of {POLICY_TYPES}")
    if not isinstance(params, dict):
        raise HTTPException(422, "params must be a JSON object")

    if ptype == "change_freeze":
        unknown = set(params) - {"start", "end", "message"}
        if unknown:
            raise HTTPException(422, f"change_freeze: unknown params {sorted(unknown)}")
        start = _parse_dt(params.get("start"), "start")
        end = _parse_dt(params.get("end"), "end")
        if end <= start:
            raise HTTPException(422, "change_freeze: end must be after start")
        out = {"start": start.isoformat(), "end": end.isoformat()}
        if params.get("message"):
            out["message"] = str(params["message"])[:255]
        return out

    if ptype == "business_hours":
        unknown = set(params) - {"days", "start", "end", "timezone"}
        if unknown:
            raise HTTPException(422, f"business_hours: unknown params {sorted(unknown)}")
        days = params.get("days")
        if not isinstance(days, list) or not days or not all(
            isinstance(d, int) and 0 <= d <= 6 for d in days
        ):
            raise HTTPException(422, "business_hours: days must be a list of 0..6 (Mon=0)")
        start = _parse_hhmm(params.get("start"), "start")
        end = _parse_hhmm(params.get("end"), "end")
        if end <= start:
            raise HTTPException(422, "business_hours: end must be after start")
        tz = str(params.get("timezone") or "UTC")
        try:
            ZoneInfo(tz)
        except Exception:
            raise HTTPException(422, f"business_hours: unknown timezone '{tz}'")
        return {"days": sorted(set(days)), "start": start.strftime("%H:%M"),
                "end": end.strftime("%H:%M"), "timezone": tz}

    # cidr_fence
    unknown = set(params) - {"allow"}
    if unknown:
        raise HTTPException(422, f"cidr_fence: unknown params {sorted(unknown)}")
    allow = params.get("allow")
    if not isinstance(allow, list) or not allow:
        raise HTTPException(422, "cidr_fence: allow must be a non-empty list of CIDRs")
    nets = []
    for cidr in allow:
        try:
            nets.append(str(ipaddress.ip_network(str(cidr), strict=False)))
        except ValueError:
            raise HTTPException(422, f"cidr_fence: '{cidr}' is not a valid CIDR")
    return {"allow": nets}


def _evaluate_one(ptype: str, params: dict, *, ip: str, now: datetime) -> tuple[bool, str]:
    """(allowed, reason). Unknown types or malformed params deny — fail closed."""
    try:
        if ptype == "change_freeze":
            start = datetime.fromisoformat(params["start"])
            end = datetime.fromisoformat(params["end"])
            if start <= now <= end:
                return False, params.get("message") or "change freeze in effect"
            return True, ""

        if ptype == "business_hours":
            local = now.astimezone(ZoneInfo(params.get("timezone") or "UTC"))
            if local.weekday() not in params["days"]:
                return False, "outside business days"
            hh, mm = params["start"].split(":")
            start = local.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
            hh, mm = params["end"].split(":")
            end = local.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
            if not (start <= local <= end):
                return False, "outside business hours"
            return True, ""

        if ptype == "cidr_fence":
            addr = ipaddress.ip_address(ip)
            if any(addr in ipaddress.ip_network(n) for n in params["allow"]):
                return True, ""
            return False, "client network not allowed"
    except Exception:
        pass
    return False, f"policy misconfigured ({ptype})"  # fail closed


def evaluate(db: Session, *, route, agent, ip: str, now: datetime | None = None):
    """All active policies attached to the route or the agent must allow (AND).
    Returns None when allowed, else (policy, reason) for the first denial."""
    from sqlalchemy import and_, or_

    from .models import Policy, PolicyAttachment

    rows = db.scalars(
        select(Policy)
        .join(PolicyAttachment, PolicyAttachment.policy_id == Policy.id)
        .where(
            Policy.tenant_id == agent.tenant_id,
            Policy.active,
            or_(
                and_(PolicyAttachment.target_type == "route",
                     PolicyAttachment.target_id == route.id),
                and_(PolicyAttachment.target_type == "agent",
                     PolicyAttachment.target_id == agent.id),
            ),
        )
    ).all()
    # Dedupe in Python (a policy can be attached to both targets) — SQL
    # DISTINCT would have to compare the JSON params column, which Postgres
    # has no equality operator for.
    seen: set[str] = set()
    policies = [p for p in rows if not (p.id in seen or seen.add(p.id))]
    now = now or datetime.now(timezone.utc)
    for policy in policies:
        allowed, reason = _evaluate_one(policy.type, policy.params or {}, ip=ip, now=now)
        if not allowed:
            return policy, reason
    return None
