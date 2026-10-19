"""Safe profiles and local authorization acknowledgments.

This module does not grant authority to contact any target. Current public scans
remain offline. Network permissions need independent target-side verification.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
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
    """Choose an offline assessment profile; never issue network authorization."""
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
        "swarm-simulation": "Synthetic, offline high-scale adversarial simulation only",
    }
    return Profile(level, environment, "offline", 0, descriptions[level])


def simulate_swarm(agent_count: int, *, max_agents: int = 100_000) -> dict[str, int | str]:
    """Return modeled identities without launching agents, sockets or processes.

    This is a *configuration preview*, not a security or performance benchmark.
    """
    if isinstance(agent_count, bool) or not isinstance(agent_count, int):
        raise ValueError("Agent count must be an integer")
    if agent_count < 1 or agent_count > max_agents:
        raise ValueError("Agent count outside allowed synthetic range")
    return {
        "mode": "offline-model",
        "modeled_agent_count": agent_count,
        "live_requests": 0,
        "result": "No workload executed; this is a safe capacity-model configuration preview",
    }
