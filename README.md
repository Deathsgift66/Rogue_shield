# RogueShield

**Free, MIT-licensed, security-focused software for independent developers and game studios.**

RogueShield helps maintainers review common security risks in source code, web API specifications, and synthetic application/game economy state. The goal is to scale from beginner-friendly guidance to rigorous, authorized testing workflows—**without becoming an unrestricted hacking tool**.

**Status: early developer preview.** The public repository currently implements offline checks and a safety-focused setup flow. It does not yet perform validated end-to-end penetration tests, live 700-client swarm tests, AI-driven assessments, or real-world load testing. An empty findings list does not prove safety.

## Start here

Requires Python 3.11+. No paid account, AI subscription or runtime external dependency is required.

```sh
python -m rogueshield setup
python -m rogueshield static ./my-project --out my-report.json
python -m rogueshield openapi ./openapi.json --out api-report.json
python -m rogueshield invariants examples/demo-invariants.json --out economy-report.json
python -m rogueshield swarm-preview --agents 700
```

The setup flow prompts for **testing level** (beginner, standard, advanced or swarm-simulation), **environment** (local, isolated-staging, staging or production), and a typed declaration that the operator owns the target or is authorized to test it. It writes a local profile that should not be committed. **All profiles currently allow zero network requests.** Production selection does not unlock intrusive testing. The swarm-preview command merely validates a modeled agent count; it launches no processes, connections, or attack workload.

Test levels are currently planning/profile metadata, not different-depth automatic analyses. The current commands operate entirely offline. Actual beginner and advanced analysis workflows, readable HTML reporting, staging authorizations and high-scale synthetic simulation are future work.

For now, reports are JSON. Each reported finding is a review indicator, **not confirmation that a vulnerability is exploitable**. Exit code `0` means no issues meeting the configured threshold, `2` means qualifying issues were found, and `3` indicates an input or output problem. For existing commands, `--fail-on low|medium|high|critical` chooses the failure threshold (default: high).

## Project mission

RogueShield aims to cover websites, APIs, game servers, authentication and authorization, virtual currencies, inventories, marketplaces, multiplayer sessions, live-service infrastructure, AI/agent security, software supply chains, and safe resilience modeling. Support will be built progressively, with tests, documentation, platform coverage and explicit safety enforcement at every step.

## Security and responsible use

**No proprietary source code, infrastructure configuration, private security findings, player information, credentials or unreleased materials from any game or company belong in this repository.** All bundled examples use synthetic information.

Read [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md), [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md). You must have authorization for any systems you assess. A self-attestation is not independent verification of permission; future network features require stronger controls. The project intentionally excludes unrestricted offensive automation, credential attacks and service-exhaustion tooling from its official implementation.

## License and liability

RogueShield is distributed under the [MIT License](LICENSE), as approved by the project maintainer. It is supplied **AS IS**, without warranty, subject to the exact license terms and applicable law. The disclaimer does not guarantee that maintainers can never be held liable. This project makes no guarantee of complete protection, testing accuracy or fitness for a specific purpose.

See [ROADMAP.md](ROADMAP.md) for planned expansion.
