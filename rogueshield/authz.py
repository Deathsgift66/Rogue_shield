"""Offline, fixture-driven object- and tenant-authorization contract checks.

Never sends requests. Observed decisions must be supplied from disposable,
authorized test fixtures. Policies are explicit rather than inferred from HTTP
status codes or from a role name such as "admin".
"""
from __future__ import annotations

from collections import defaultdict
import re

from rogueshield.offline import finding, read_json

MAX_PRINCIPALS = 128
MAX_RESOURCES = 128
MAX_POLICIES = 32
MAX_OBSERVATIONS = 4000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}\Z")


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"Invalid synthetic {field} identifier")
    return value


def _records(data: dict, key: str, maximum: int, fields: set[str]) -> list[dict]:
    items = data.get(key)
    if not isinstance(items, list) or not 1 <= len(items) <= maximum:
        raise ValueError(f"{key} must be a nonempty bounded list")
    for item in items:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError(f"Invalid {key} entry or unsupported fields")
    return items


def _roles(value: object) -> frozenset[str]:
    if not isinstance(value, list) or len(value) > 16:
        raise ValueError("Roles must be a bounded list")
    names = [_identifier(role, "role") for role in value]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate role")
    return frozenset(names)


def inspect_authz(path: str) -> list[dict]:
    """Compare synthetic observed access decisions with an explicit policy.

    A report is evidence of fixture-policy consistency, not proof that a real
    application enforces authorization. Missing test cohorts are reported.
    """
    data = read_json(path)
    if set(data) != {"kind", "schema_version", "principals", "resources", "policies", "observations"}:
        raise ValueError("Unsupported authorization fixture fields")
    if data["kind"] != "authorization-matrix" or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Expected authorization-matrix schema_version 1")

    principals = _records(data, "principals", MAX_PRINCIPALS, {"id", "tenant", "roles"})
    resources = _records(data, "resources", MAX_RESOURCES, {"id", "type", "owner", "tenant"})
    policies = _records(data, "policies", MAX_POLICIES,
                        {"resource_type", "action", "allow_owner", "allow_roles", "require_same_tenant"})
    observations = _records(data, "observations", MAX_OBSERVATIONS,
                            {"principal", "resource", "action", "decision"})

    people: dict[str, dict] = {}
    for person in principals:
        identity = _identifier(person["id"], "principal")
        if identity in people:
            raise ValueError("Duplicate principal")
        people[identity] = {
            "tenant": _identifier(person["tenant"], "tenant"),
            "roles": _roles(person["roles"]),
        }

    objects: dict[str, dict] = {}
    for resource in resources:
        identity = _identifier(resource["id"], "resource")
        kind = _identifier(resource["type"], "resource type")
        owner = _identifier(resource["owner"], "owner")
        tenant = _identifier(resource["tenant"], "tenant")
        if identity in objects or owner not in people:
            raise ValueError("Duplicate resource or unknown owner")
        if people[owner]["tenant"] != tenant:
            raise ValueError("Synthetic resource owner must belong to its tenant")
        objects[identity] = {"type": kind, "owner": owner, "tenant": tenant}

    rules: dict[tuple[str, str], dict] = {}
    for policy in policies:
        kind = _identifier(policy["resource_type"], "resource type")
        action = _identifier(policy["action"], "action")
        if type(policy["allow_owner"]) is not bool or type(policy["require_same_tenant"]) is not bool:
            raise ValueError("Authorization policy flags must be boolean")
        roles = _roles(policy["allow_roles"])
        key = (kind, action)
        if key in rules:
            raise ValueError("Duplicate authorization policy")
        rules[key] = {"owner": policy["allow_owner"], "roles": roles,
                      "tenant": policy["require_same_tenant"]}

    for resource in objects.values():
        if not any(kind == resource["type"] for kind, _ in rules):
            raise ValueError("Resource type has no declared policy")

    seen: set[tuple[str, str, str]] = set()
    covered: dict[tuple[str, str], set[str]] = defaultdict(set)
    found: list[dict] = []
    for i, observation in enumerate(observations):
        principal = _identifier(observation["principal"], "principal")
        resource_id = _identifier(observation["resource"], "resource")
        action = _identifier(observation["action"], "action")
        if principal not in people or resource_id not in objects:
            raise ValueError("Observation references an unknown principal or resource")
        resource = objects[resource_id]
        policy = rules.get((resource["type"], action))
        if policy is None:
            raise ValueError("Observation references an undeclared policy")
        if observation["decision"] not in ("allow", "deny"):
            raise ValueError("Observed decision must be allow or deny")
        key = (principal, resource_id, action)
        if key in seen:
            raise ValueError("Duplicate synthetic observation")
        seen.add(key)

        person = people[principal]
        same_tenant = person["tenant"] == resource["tenant"]
        owner = principal == resource["owner"]
        cohort = "owner" if owner else ("same-tenant non-owner" if same_tenant else "cross-tenant")
        covered[(resource_id, action)].add(cohort)
        permitted = ((owner and policy["owner"]) or bool(person["roles"] & policy["roles"]))
        expected_allow = permitted and (same_tenant or not policy["tenant"])
        observed_allow = observation["decision"] == "allow"
        if observed_allow and not expected_allow:
            if not same_tenant and policy["tenant"]:
                found.append(finding("AUTHZ-TENANT-ESCAPE", "critical", f"observations[{i}]",
                                     "Synthetic cross-tenant access was allowed despite a tenant boundary"))
            else:
                found.append(finding("AUTHZ-BOLA", "high", f"observations[{i}]",
                                     "Synthetic access was allowed contrary to the declared object policy"))
        elif expected_allow and not observed_allow:
            found.append(finding("AUTHZ-OVERDENY", "medium", f"observations[{i}]",
                                 "Synthetic access was denied despite the declared object policy"))

    for i, (resource_id, resource) in enumerate(objects.items()):
        for (kind, action), _policy in sorted(rules.items()):
            if kind != resource["type"]:
                continue
            possible = {"owner"}
            if any(identity != resource["owner"] and person["tenant"] == resource["tenant"]
                   for identity, person in people.items()):
                possible.add("same-tenant non-owner")
            if any(person["tenant"] != resource["tenant"] for person in people.values()):
                possible.add("cross-tenant")
            missing = sorted(possible - covered[(resource_id, action)])
            if missing:
                found.append(finding("AUTHZ-COVERAGE", "low", f"resources[{i}]/{action}",
                                     "Missing synthetic access observations for: " + ", ".join(missing)))
    return found
