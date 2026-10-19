"""User-selected offline testing profiles and explicit authorization statements."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Literal

ENVIRONMENTS = ("local", "isolated-staging", "staging", "production")
LEVELS = ("beginner", "standard", "advanced", "swarm-simulation")
CONSENT_PHRASE = "I OWN OR AM AUTHORIZED TO TEST THIS SYSTEM"


@dataclass(frozen=True)
class Profile:
    level: str
    environment: str
    mode: Literal["offline"]
    max_live_requests: int = 0
    description: str = ""


def choose_profile(level: str, environment: str, acknowledgment: str) -> Profile:
    if level not in LEVELS:
        raise ValueError("Unknown assessment level")
    if environment not in ENVIRONMENTS:
        raise ValueError("Unknown assessment environment")
    if acknowledgment != CONSENT_PHRASE:
        raise PermissionError("Explicit authorization acknowledgment required")
    descriptions = {
        "beginner": "Basic local checks and beginner-friendly explanations",
        "standard": "Broader local inspection of supplied code and contracts",
        "advanced": "Expert review of offline security scenarios and invariants",
        "swarm-simulation": "Synthetic, offline high-scale adversarial modeling only",
    }
    return Profile(level, environment, "offline", 0, descriptions[level])


def simulate_swarm(agent_count: int, *, max_agents: int = 100_000) -> dict:
    """Legacy offline preview; no workload generated."""
    if type(agent_count) is not int or not 1 <= agent_count <= max_agents:
        raise ValueError("Invalid modeled agent count")
    return {"mode": "offline-model", "modeled_agent_count": agent_count,
            "live_requests": 0,
            "result": "No network workload executed; configuration preview only"}
