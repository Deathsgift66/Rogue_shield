# Release and Legal/Operational Readiness Gates

This is a checklist, **not a claim** that every control is implemented. Adapted to an MIT-licensed project from the user-provided *Legal and Operational Risk-Reduction Framework for an Open-Source Dual-Use Penetration-Testing Tool*.

## Engineering: verified in v0.3 local tests

- [x] Standard MIT license and separate intended-use documents.
- [x] No network-capable assessment executor in the shipped Python package.
- [x] Consent and environment/level selection in setup.
- [x] Synthetic 700-virtual-identity model with bounded work.
- [x] Escaped plain HTML and understandable text/JSON reports.
- [x] Offline unit tests and an unprivileged GitHub Actions workflow configured.
- [ ] CI runs completed on GitHub and results verified.
- [ ] Independent maintainer/security review.
- [ ] SAST, secret scanning and supply-chain attestations verified.
- [ ] Signed source tag, release checksums and SBOM published.

## Owner / governance: not automatically satisfied by repository files

- [ ] Attorney review of licensing, disclaimer, project ownership and any commercial terms.
- [ ] Confirm copyright provenance and contributor employer/third-party rights.
- [ ] Decide whether an LLC/corporation is appropriate; complete ownership/IP transfer if established.
- [ ] Turn on GitHub private vulnerability reporting, branch protection, MFA/passkeys and required approvals.
- [ ] Appoint reachable security, abuse and legal contacts before advertising those channels.
- [ ] Decide whether insurance fits operations; obtain appropriate written coverage confirmation rather than assuming it exists.
- [ ] Obtain qualified export/sanctions review before introducing intrusion-related, encryption, hosted or international capabilities.
- [ ] Establish incident response, preservation/legal-hold practice and response documentation.
- [ ] Inventory distribution/website telemetry and prepare accurate privacy notices if anything beyond local CLI is offered.

Neither license nor disclaimer grants immunity; any legal/commercial risk guidance is general information, not legal advice.
