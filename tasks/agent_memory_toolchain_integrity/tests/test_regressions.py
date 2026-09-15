"""Offline verifier positive controls and deliberately non-semantic guards."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("memory_grader", ROOT / "tests/grader.py")
grader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(grader)


class GuardRegressionTests(unittest.TestCase):
    def test_reference_guard_across_seeds(self):
        with patch.object(grader, "GUARD", ROOT / "solution/boundary_guard.py"):
            for seed in ("alpha", "beta", "gamma", "delta"):
                with self.subTest(seed=seed):
                    passed, evidence, metrics = grader.assess_guard({"estate_id": "review-estate"}, seed)
                    self.assertTrue(passed, evidence)
                    self.assertEqual(metrics["passed_cases"], metrics["case_count"])
                    self.assertGreater(metrics["authorized_continuity"]["total"], 4)
                    self.assertGreater(metrics["unsafe_prevention"]["total"], 30)

    def test_input_agnostic_guards_fail(self):
        for strategy in ("allow", "deny", "ordinal"):
            def fake_process(*args, **kwargs):
                decisions = [("allow" if i < 4 else "deny") if strategy == "ordinal" else strategy
                             for i, _ in enumerate(kwargs["input"].splitlines())]
                output = "\n".join(json.dumps({"decision": d, "reasons": ["constant"]}) for d in decisions)
                return SimpleNamespace(returncode=0, stderr="", stdout=output)
            with self.subTest(strategy=strategy), patch.object(grader, "GUARD", ROOT / "solution/boundary_guard.py"), patch.object(grader.subprocess, "run", fake_process):
                passed, _, metrics = grader.assess_guard({"estate_id": "review-estate"}, "alpha")
                self.assertFalse(passed)
                self.assertLess(metrics["passed_cases"], metrics["case_count"])

    def test_seed_reproducibility_and_variable_shapes(self):
        state = {"estate_id": "review-estate"}
        self.assertEqual(grader.guard_cases(state, "alpha"), grader.guard_cases(state, "alpha"))
        corpora = [grader.guard_cases(state, str(i)) for i in range(6)]
        self.assertGreater(len({len(cases) for cases in corpora}), 1)
        self.assertNotEqual(corpora[0], corpora[1])
        self.assertTrue(all("mem-root" not in json.dumps(cases) for cases in corpora))

    def test_crashing_or_incomplete_guard_does_not_pass(self):
        with patch.object(grader, "GUARD", ROOT / "solution/boundary_guard.py"):
            for result in (SimpleNamespace(returncode=1, stderr="failed", stdout=""),
                           SimpleNamespace(returncode=0, stderr="", stdout="{}")):
                with patch.object(grader.subprocess, "run", return_value=result):
                    passed, _, metrics = grader.assess_guard({"estate_id": "review-estate"})
                    self.assertFalse(passed)
                    self.assertEqual(metrics["passed_cases"], 0)
                    self.assertGreater(metrics["case_count"], 0)

    def test_missing_guard_keeps_required_denominator(self):
        with patch.object(grader, "GUARD", ROOT / "missing-guard.py"):
            passed, _, metrics = grader.assess_guard({"estate_id": "review-estate"})
        self.assertFalse(passed)
        self.assertEqual(metrics["passed_cases"], 0)
        self.assertGreater(metrics["case_count"], 34)
        self.assertEqual(metrics["evaluated_cases"], 0)
        self.assertEqual(metrics["not_evaluated_cases"], metrics["case_count"])
        self.assertEqual(len(metrics["cases"]), metrics["case_count"])


if __name__ == "__main__":
    unittest.main()
