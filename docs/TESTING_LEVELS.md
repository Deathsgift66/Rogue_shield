# Testing Levels and Environments — v0.5

| Level | Intended user | Implemented in v0.5 |
| --- | --- | --- |
| Beginner | Indie developer or first-time reviewer | Guided setup and plain-language local findings |
| Standard | Small team | Same offline checks; scope/target recording for future authorized workflows |
| Advanced | Security team | Same offline checks plus direct access to commands, JSON, synthetic invariants, authorization matrices and baseline comparisons |
| Swarm Simulation | Teams modeling abuse by many identities | Deterministic virtual quota model with no real agents or network activity |

Environment selections: local, isolated-staging, staging, and production. **No environment or level grants live requests, active exploitation or mutating tests in v0.5.** All allow zero live network requests. This is a deliberate safety boundary, not an endorsement of production testing.

The swarm model works with synthetic counters for per-identity, per-origin and global limits; it makes no requests, cannot measure server capacity, and does not simulate a real intrusion. The `--agents 700` value configures **700 virtual identities**, not 700 processes or an actual adversarial attack.

Future features should require a validated scope manifest, independent proof of target control, network destination pinning, non-destructive defaults, bounded budgets, logs with redaction, and approval gates before anything other than local/offline checks.
