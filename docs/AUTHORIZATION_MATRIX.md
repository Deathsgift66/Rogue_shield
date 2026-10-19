# Offline Authorization Matrix (v0.5)

RogueShield can compare **synthetic, pre-recorded decisions** with an explicit
object-level authorization policy. It does not authenticate, call an API,
discover objects, issue requests, or infer real server behavior.

This is intended for teams that already have a **disposable local test
environment** and can safely export expected/observed authorization decisions
as synthetic, non-sensitive fixture data. Do not export real session tokens,
player identifiers, tenant names, personal information or production responses.

## Run it

```bash
python -m rogueshield authz examples/demo-authz.json
python -m rogueshield authz examples/broken-authz.json --format sarif --out authz.sarif
python -m rogueshield review ./your-project
```

A project review auto-detects `rogueshield-authz.json` in the project root.
Standalone `authorization-matrix` JSON files also work with `review`.

## Schema v1

```json
{
  "kind": "authorization-matrix",
  "schema_version": 1,
  "principals": [
    {"id": "alice", "tenant": "north", "roles": ["player"]},
    {"id": "bob", "tenant": "north", "roles": ["player"]},
    {"id": "eve", "tenant": "south", "roles": ["player"]}
  ],
  "resources": [
    {"id": "wallet-a", "type": "wallet", "owner": "alice", "tenant": "north"}
  ],
  "policies": [
    {
      "resource_type": "wallet",
      "action": "read",
      "allow_owner": true,
      "allow_roles": [],
      "require_same_tenant": true
    }
  ],
  "observations": [
    {"principal": "alice", "resource": "wallet-a", "action": "read", "decision": "allow"},
    {"principal": "bob", "resource": "wallet-a", "action": "read", "decision": "deny"},
    {"principal": "eve", "resource": "wallet-a", "action": "read", "decision": "deny"}
  ]
}
```

A policy permits an action if the principal is the owner with
`allow_owner: true`, or has at least one role listed in `allow_roles`.
If `require_same_tenant` is true, the principal must **also** belong to the
resource's tenant. The owner must be a declared principal in the resource's
tenant. Policies are keyed by `(resource_type, action)`. All observed actions
must have a policy. A role name like `admin` does **not** implicitly bypass
the tenant boundary.

## Findings

| Rule | Severity | Meaning |
| --- | --- | --- |
| `AUTHZ-TENANT-ESCAPE` | Critical | A fixture reports allowed cross-tenant access where policy requires isolation |
| `AUTHZ-BOLA` | High | A fixture reports access allowed contrary to the declared object/role policy |
| `AUTHZ-OVERDENY` | Medium | A fixture reports access denied even though the policy permits it |
| `AUTHZ-COVERAGE` | Low | A resource/action lacks applicable owner, same-tenant non-owner, or cross-tenant observations |

Coverage findings depend on which identity cohorts exist in the fixture. A
cohort that does not exist cannot be tested and is not reported as covered.
The tool rejects duplicate observations, unknown IDs, missing policies,
unexpected schema fields, malformed flags and oversized inputs rather than
silently treating them as clean.

## Limits and trust

- Up to 128 principals, 128 resources, 32 policies and 4,000 observations.
- Input is a regular local JSON file of at most 1 MB; symlinks are rejected.
- No runtime network activity, credentials, traffic capture or automatic
  construction of requests.
- A clean fixture **does not prove** that the real API prevents BOLA/IDOR.
  The declared policy and the observed fixture data must be independently
  reviewed; incorrect or fabricated observations can produce false confidence.
- Do not use production records or submit sensitive fixtures to public CI.
