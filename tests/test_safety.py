import unittest

from rogueshield.safety import CONSENT_PHRASE, choose_profile, simulate_swarm


class SafetyTests(unittest.TestCase):
    def test_acknowledgment_required(self):
        with self.assertRaises(PermissionError):
            choose_profile("beginner", "local", "")

    def test_bad_environment_denied(self):
        with self.assertRaises(ValueError):
            choose_profile("advanced", "unknown", CONSENT_PHRASE)

    def test_bad_level_denied(self):
        with self.assertRaises(ValueError):
            choose_profile("unrestricted", "local", CONSENT_PHRASE)

    def test_all_profiles_are_offline(self):
        for level in ("beginner", "standard", "advanced", "swarm-simulation"):
            for environment in ("local", "isolated-staging", "staging", "production"):
                profile = choose_profile(level, environment, CONSENT_PHRASE)
                self.assertEqual(profile.mode, "offline")
                self.assertEqual(profile.max_live_requests, 0)

    def test_swarm_never_executes_requests(self):
        modeled = simulate_swarm(700)
        self.assertEqual(modeled["modeled_agent_count"], 700)
        self.assertEqual(modeled["live_requests"], 0)

    def test_invalid_swarm_count(self):
        for invalid in (-1, 0, 100_001, True, "700"):
            with self.assertRaises(ValueError):
                simulate_swarm(invalid)


if __name__ == "__main__":
    unittest.main()
