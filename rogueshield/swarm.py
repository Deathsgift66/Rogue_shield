"""Deterministic virtual-agent safety modeling. NEVER sends traffic or launches agents."""
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class SwarmConfig:
    agents: int = 700
    rounds: int = 10
    actions_per_agent: int = 4
    identity_limit: int = 2
    origin_limit: int = 30
    global_limit: int = 100
    origin_groups: int = 35

    def validate(self) -> None:
        values = asdict(self)
        if any(type(v) is not int for v in values.values()):
            raise ValueError("Swarm settings must be integers")
        if not 1 <= self.agents <= 100_000 or not 1 <= self.rounds <= 100:
            raise ValueError("Agent count or rounds outside virtual-simulation bounds")
        if not 1 <= self.actions_per_agent <= 20 or self.agents * self.rounds * self.actions_per_agent > 2_000_000:
            raise ValueError("Virtual simulation would exceed work budget")
        if any(getattr(self, key) < 1 for key in ("identity_limit", "origin_limit", "global_limit", "origin_groups")):
            raise ValueError("Virtual limits must be positive")


def simulate(config: SwarmConfig) -> dict:
    """Simulate tiered defensive quotas, not real capacity or attack success.

    Each virtual round resets three counters: per-identity, per-origin, and
    system-wide quotas. Origin groups are synthetic cohorts, not IP addresses.
    """
    config.validate()
    blocked = {"identity": 0, "origin": 0, "global": 0}
    allowed = 0
    peak_allowed = 0
    for _round in range(config.rounds):
        by_identity: dict[int, int] = {}
        by_origin: dict[int, int] = {}
        round_allowed = 0
        for action in range(config.actions_per_agent):
            for actor in range(config.agents):
                origin = actor % config.origin_groups
                if by_identity.get(actor, 0) >= config.identity_limit:
                    blocked["identity"] += 1
                elif by_origin.get(origin, 0) >= config.origin_limit:
                    blocked["origin"] += 1
                elif round_allowed >= config.global_limit:
                    blocked["global"] += 1
                else:
                    by_identity[actor] = by_identity.get(actor, 0) + 1
                    by_origin[origin] = by_origin.get(origin, 0) + 1
                    round_allowed += 1
        allowed += round_allowed
        peak_allowed = max(peak_allowed, round_allowed)
    attempted = config.agents * config.rounds * config.actions_per_agent
    if attempted != allowed + sum(blocked.values()):
        raise ValueError("Swarm model bookkeeping mismatch")
    return {
        "tool": "RogueShield", "kind": "offline-swarm-model", "schema_version": 1,
        "config": asdict(config), "modeled_attempts": attempted,
        "modeled_allowed": allowed, "modeled_blocked": sum(blocked.values()),
        "blocked_by": blocked, "peak_virtual_allowances_per_round": peak_allowed,
        "real_agents": 0, "live_requests": 0, "target_contacted": False,
        "explanation": "A deterministic quota model only. It does not benchmark, target, or validate a real service.",
        "next_step": "Review quota settings and test defensively with a separately authorized, disposable environment in future tooling.",
    }
