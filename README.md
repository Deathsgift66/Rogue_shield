# RogueShield v0.5 — offline authorization and regression analysis

**Free, MIT-licensed defensive security review for indie developers, software teams, and game studios.**

> **Developer preview, not a comprehensive pentest.** v0.5 reviews files on your own computer. It **does not connect to target sites, run attacks, launch agents, test real-world capacity, or guarantee security**. Findings are leads requiring verification.

## Start in under two minutes

Requires Python **3.11+**. No paid services, external dependencies, accounts, API keys, AI model, container runtime, or remote telemetry are needed.

```bash
python -m rogueshield guide
python -m rogueshield setup
python -m rogueshield review ./your-project
python -m rogueshield review ./your-project --format html --out review.html
python -m rogueshield swarm-preview --agents 700
python -m rogueshield authz examples/demo-authz.json
```

To install locally from this repository: `python -m pip install .` and replace `python -m rogueshield` with `rogueshield`.

**Setup** asks for the assessment level (beginner, standard, advanced, or swarm-simulation), your environment (local, isolated-staging, staging, production), and an exact authorization statement. It saves `rogueshield.local.json`, ignored by Git. These selections describe your intended assessment: **v0.5 has one offline execution policy for all choices.** Production and advanced never unlock live or intrusive tests.

## What works today

| Feature | v0.5 status | What it does |
| --- | --- | --- |
| Guided local review | Working | Inspect Python AST indicators, `openapi.json` or `swagger.json`, optional `rogueshield-fixtures.json` and `rogueshield-authz.json` in one directory |
| Source inspection | Working, heuristic | Flags a small set of risky Python call patterns; cannot prove exploitability |
| OpenAPI review | Working, heuristic | Flags HTTP server URLs, anonymous security alternatives or missing auth declarations on selected sensitive paths, and deprecated modifying operations; never proves server-side authorization |
| Economy-state invariants | Working, synthetic | Check conservation, negative balances, and idempotent replay using supplied example JSON; optional `asset_transfers` checks each asset separately to catch cross-currency substitution |
| Object/tenant authorization matrix | Working, synthetic | Compare declared per-action ownership, role and tenant rules with supplied observations; report BOLA, tenant isolation, over-denial and missing test cohorts |
| Baseline regression comparison | Working, offline | Stable finding fingerprints, multiset-aware new/resolved/severity-change tracking and severity-based CI regression gating |
| Readable reports | Working | Text, standalone HTML (offline, escaped, CSP), deterministic JSON, and SARIF 2.1.0 for CI review |
| Virtual swarm model | Working, synthetic | Model local per-identity, per-origin and global quota behavior for up to 100,000 virtual identities; **no real agents or traffic** |
| Scope declaration validation | Working, offline | Check explicit origins, authorization acknowledgment, expiry, read-only methods, zero live-request budget and fingerprint scope |
| Dynamic web/API scanning, autonomous AI pentesting | **Not implemented** | Reserved for audited and independently approved later releases |

### Individual commands

```bash
python -m rogueshield static ./your-python-project --format text
python -m rogueshield openapi examples/demo-openapi.json --format html --out api-review.html
python -m rogueshield invariants examples/broken-invariants.json --format json --out economy-review.json
python -m rogueshield invariants examples/demo-asset-invariants.json
python -m rogueshield authz examples/broken-authz.json
python -m rogueshield review ./your-project --format sarif --out rogueshield.sarif
python -m rogueshield scope-check examples/scope-offline.example.json
# Generate reports at different revisions using separate output filenames:
python -m rogueshield compare current.json baseline.json --fail-on high
python -m rogueshield swarm-preview --agents 700 --rounds 10 --identity-limit 2 --global-limit 100
python -m unittest discover -s tests -v
```

Exit codes for scan and comparison commands: `0` no findings at the configured threshold, `2` review indicators at/above the threshold, `3` invalid input or permission. `--fail-on info|low|medium|high|critical` defaults to `high`. A zero exit code **does not mean your application is safe**. Comparison gates only new or worsening findings; existing baseline indicators still require review.

### What the report means

Each review indicator shows **severity, location, what was noticed, and what to do next**. SARIF 2.1.0 exports are suitable for compatible CI/code-review tools; their results are still unverified heuristic indicators. Severity is a prioritization hint, not proof of a vulnerability. Check the affected code/configuration manually before making changes. HTML reports have no external scripts or network assets.

**Authorization matrices are synthetic contract tests, not real BOLA exploitation.**
See [docs/AUTHORIZATION_MATRIX.md](docs/AUTHORIZATION_MATRIX.md) for the fixture schema,
policy semantics, and limits. For deterministic CI regression gating, see
[docs/BASELINE_COMPARISON.md](docs/BASELINE_COMPARISON.md). No new command makes
network requests or sends credentials.

The 700-agent **virtual** output summarizes quota decisions on abstract identities and cohorts. It is not a performance benchmark and cannot establish protection against an actual attack. See [docs/TESTING_LEVELS.md](docs/TESTING_LEVELS.md).

## Responsible use and privacy

RogueShield does not grant anyone permission to test systems belonging to others. Read [AUTHORIZED_USE.md](AUTHORIZED_USE.md) and [LEGAL.md](LEGAL.md). The MIT software license and intended-use guidance are distinct; guidance does **not** change license permissions. Nothing in the project guarantees immunity from liability or that misuse is impossible.

**Never commit third-party proprietary source, private game mechanics, player information, private endpoints, internal audits, credentials, or company secrets.** This public tool uses generic synthetic examples only; **no private project materials are included**.

No external telemetry is implemented. Input files remain local unless the operator explicitly moves or publishes a report. JSON inputs reject duplicate object keys and non-standard NaN/Infinity values to avoid ambiguous security declarations. Reports may include source-relative filenames and API path names; review them before sharing. Files are created privately and never overwrite existing report/configuration files.

## Open source and safety

This project uses the [MIT License](LICENSE) (as approved by its maintainer). See [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [ROADMAP.md](ROADMAP.md), [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md), and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

**v0.5 is a milestone, not a production security certification.** The roadmap separates aspirations from implemented functionality. Version 0.5 adds offline authorization fixtures and baseline comparison; it still does not include live API testing or autonomous attack agents.
