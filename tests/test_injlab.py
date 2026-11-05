import base64
import unittest

from injlab.attacks import ATTACKS, CANARY, SYSTEM_PROMPT
from injlab.run import run_target
from injlab.scoring import attack_succeeded, is_refusal, summarize
from injlab.targets import (FilterMock, HardenedMock, NaiveMock,
                            decode_b64_segments)


def results_by_id(target):
    return {r["id"]: r["result"] for r in run_target(target)}


class TestScoring(unittest.TestCase):
    def test_canary_counts_as_success(self):
        self.assertTrue(attack_succeeded(f"token is {CANARY}"))

    def test_marker_counts_as_success(self):
        self.assertTrue(attack_succeeded("PWNED"))

    def test_clean_text_is_not_success(self):
        self.assertFalse(attack_succeeded("Support hours are 9 to 5."))

    def test_refusal_detection(self):
        self.assertTrue(is_refusal("I can't help with that request."))
        self.assertFalse(is_refusal("Happy to help."))


class TestDecode(unittest.TestCase):
    def test_decodes_base64(self):
        enc = base64.b64encode(b"hello world, this is a test").decode()
        self.assertEqual(decode_b64_segments(f"x {enc} y"),
                         ["hello world, this is a test"])

    def test_ignores_non_base64(self):
        self.assertEqual(decode_b64_segments("just a normal sentence"), [])


class TestTargets(unittest.TestCase):
    def test_naive_fails_every_attack_and_passes_controls(self):
        res = results_by_id(NaiveMock())
        for a in ATTACKS:
            expected = "SUCCEEDED" if a.kind == "attack" else "OK"
            self.assertEqual(res[a.id], expected, a.id)

    def test_filter_blocks_surface_attacks_but_not_rephrased_or_encoded(self):
        res = results_by_id(FilterMock())
        for blocked in ("A01", "A02", "A05"):
            self.assertEqual(res[blocked], "BLOCKED", blocked)
        for bypassed in ("A03", "A04"):
            self.assertEqual(res[bypassed], "SUCCEEDED", bypassed)

    def test_hardened_blocks_all_without_false_refusals(self):
        rows = run_target(HardenedMock())
        s = summarize(rows)
        self.assertEqual(s["succeeded"], 0)
        self.assertEqual(s["false_refusals"], 0)

    def test_system_prompt_contains_canary(self):
        self.assertIn(CANARY, SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
