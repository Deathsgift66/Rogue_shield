# RogueShield Roadmap

## Implemented in v0.5

- Offline-only guided project review, bounded Python AST heuristics, OpenAPI
  security declaration checks and synthetic economy invariants.
- Synthetic object/tenant/role authorization matrices, policy mismatches,
  BOLA/IDOR-style fixture indicators and owner/peer/cross-tenant coverage gaps.
- Deterministic JSON report fingerprints, offline baseline comparison
  (new/resolved/worsened/improved/unchanged), SARIF 2.1.0 fingerprints and
  severity-based CI regression gating.
- Text, JSON, standalone escaped HTML and SARIF review reports; private,
  exclusive output files; strict JSON parsing and explicit offline scope checks.
- Synthetic 700-virtual-agent quota model. **No real network requests, real
  agent swarm, live authentication or exploitation.**

## Next priorities (not implemented)

1. **v0.6 — Offline policy coverage:** Validate authorization fixture
   coverage against OpenAPI operations, add explicit permission matrix
   completeness checks and synthetic denial/ownership fixtures for more
   resource types. Keep no-network semantics.
2. **v0.7 — Stronger static and state-machine checks:** Alias-aware Python
   AST rules with measured false positives; stateful synthetic resource
   transfer/replay fixtures and bounded deterministic scenario generation.
3. **v0.8 — Extensible check architecture:** Versioned typed offline-check
   registry, sandboxing/size budgets for plugins, per-check provenance,
   fixtures and compatibility tests. No arbitrary plugin execution by default.
4. **v0.9 — Operational assurance:** Dependency inventory/SBOM, pinned CI
   dependencies, provenance/signing and independent review of input parsing,
   authorization fixture semantics and output privacy.
5. **Authorized staging broker (separate design and approval):** Would
   require independent proof of target control, origin and IP pinning,
   redirect denial, DNS revalidation, non-destructive request budgets,
   kill switch, audit logs and an independent security review. Not present
   in v0.5, and no timeline or permission to build a live executor is implied.

**1.0 gate:** reproducible cross-version tests, documented false positives,
independent review, privacy and legal/ownership review, maintainer-supported
disclosure process and explicit maintainer release approval. No claim of
complete security or litigation immunity.
