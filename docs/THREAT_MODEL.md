# RogueShield Threat Model (v0.3)

## Trust boundaries

Local source trees, JSON specifications, fixtures, filenames and generated findings are **untrusted inputs**. RogueShield's outputs must not execute code, render unescaped HTML, contact third-party servers, ingest credentials into reports, or treat instructions within a source file as authorization.

## In-scope capability

- Local Python AST heuristics.
- Local OpenAPI 3.x metadata heuristics.
- Local synthetic ledger and replay comparisons.
- Strict offline scope declaration checks (no network executor exists).
- Deterministic virtual-agent quota modeling without sockets/processes.
- Escaped, standalone HTML; text and JSON reports.

## Adversarial design concerns

- **Scope spoofing:** Self-attestation can be false; v0.3 prevents network execution entirely. A later scope broker must enforce target-side proof and pin network boundaries.
- **Source/path privacy:** Reports may contain path metadata; no body capture or centralized telemetry. Users should keep reports private.
- **HTML injection:** Report content is escaped and a local Content Security Policy restricts scripts and remote resources.
- **Work exhaustion:** Input JSON capped at 1MB, Python file count capped at 3,000, swarm workload capped at two million abstract decisions.
- **False confidence:** Reports explicitly say heuristics are not verified exploitability or complete coverage.
- **Forked copies:** MIT permits modifications; safeguards in official builds cannot be guaranteed for forks.

No code in v0.3 opens a target network connection. No UI/CLI choice can override that. No LLM executes arbitrary tools, and there are no external dependencies for runtime checks.

## Future high-risk components

Authenticated staging DAST, WebSockets, agent-assisted planning, genuine concurrency testing, plugins and controlled fixture mutations require separate policy-engine design and independent security review. Real swarms, brute force, evasion, persistence, denial-of-service or unauthorized exploitation are not part of this milestone.
