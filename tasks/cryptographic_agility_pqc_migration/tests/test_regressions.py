#!/usr/bin/env python3
"""Offline acceptance and negative controls for migration diagnostics."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TASK = Path(__file__).resolve().parents[1]
PUBLIC = TASK / "environment/assets/public"
sys.path.insert(0, str(PUBLIC / "tools"))
sys.path.insert(0, str(TASK / "tests"))
import agilityctl
import grade
import migration_model
from receipt_checks import check_receipts


class MigrationRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = agilityctl.load(PUBLIC)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.json"
            env = dict(os.environ, CRYPTO_CASE_ROOT=str(PUBLIC), MIGRATION_PLAN_OUTPUT=str(path), PYTHONDONTWRITEBYTECODE="1")
            subprocess.run([sys.executable, str(TASK / "solution/solution.py")], env=env, check=True, capture_output=True, text=True)
            cls.plan = json.loads(path.read_text())

    def test_oracle_and_coverage(self):
        result = migration_model.simulate(self.plan, TASK / "tests/fixtures")
        self.assertTrue(result["passed"], result["errors"])
        self.assertTrue(all(migration_model.exercise_adversarial_scenarios(self.plan, TASK / "tests/fixtures").values()))
        for metric in result["coverage"].values():
            self.assertEqual(metric["completed"], metric["required"])
            self.assertEqual(metric["unexpected"], 0)
            self.assertEqual(metric["rate"], 1)

    def test_prefix_rehearsal_does_not_claim_completion(self):
        plan = copy.deepcopy(self.plan)
        plan["actions"] = plan["actions"][:8]
        result = agilityctl.rehearse(plan, self.case)
        self.assertTrue(result["checks_passed"])
        self.assertNotIn("passed", result)
        self.assertFalse(result["complete_migration_verified"])
        self.assertIn("receipt_correctness", result["unchecked"])
        self.assertFalse(migration_model.simulate(plan, TASK / "tests/fixtures")["passed"])

    def test_correct_receipts_are_only_encoding_validation(self):
        result = check_receipts(self.plan, self.case)
        self.assertTrue(result["checks_passed"], result["violations"])
        self.assertEqual(result["valid_actions"], 13)
        self.assertFalse(result["complete_migration_verified"])
        plan = copy.deepcopy(self.plan)
        plan["final_policies"]["tls:telemetry-api"]["reject_downgrade"] = False
        self.assertTrue(check_receipts(plan, self.case)["checks_passed"])
        self.assertFalse(migration_model.simulate(plan, TASK / "tests/fixtures")["passed"])

    def test_mutated_receipts_and_identity_bindings(self):
        for mutation in ("canary", "fleet", "archive", "evidence", "work"):
            with self.subTest(mutation=mutation):
                plan = copy.deepcopy(self.plan)
                gates = [a for a in plan["actions"] if a["op"] == "upgrade_gate"]
                if mutation in {"canary", "fleet"}:
                    gate = next(a for a in gates if a["ring"] == mutation)
                    gate["recovery_steps"][0]["receipt"] = "0" * 64
                elif mutation == "archive":
                    next(a for a in plan["actions"] if a["op"] == "migrate_archive")["restore_proof"] = "0" * 64
                elif mutation == "evidence":
                    gates[0]["recovery_steps"][0]["evidence"] = gates[-1]["recovery_steps"][0]["evidence"]
                else:
                    gates[0]["recovery_steps"][0]["work_units"] = True
                result = check_receipts(plan, self.case)
                self.assertFalse(result["checks_passed"])
                self.assertTrue(result["violations"])

    def test_no_receipts_is_not_a_success(self):
        result = check_receipts({"actions": []}, self.case)
        self.assertFalse(result["checks_passed"])
        self.assertEqual(result["checked_actions"], 0)

    def test_metrics_cannot_turn_partial_plan_into_solve(self):
        plan = copy.deepcopy(self.plan)
        plan["actions"] = plan["actions"][:8]
        result = migration_model.simulate(plan, TASK / "tests/fixtures")
        adversarial = migration_model.exercise_adversarial_scenarios(plan, TASK / "tests/fixtures")
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            previous = grade.LOGS
            try:
                grade.LOGS = Path(tmp)
                self.assertFalse(grade.emit(result, adversarial=adversarial))
                detail = json.loads((Path(tmp) / "details.json").read_text())
            finally:
                grade.LOGS = previous
        self.assertEqual(detail["reward"], 0)
        self.assertEqual(detail["solved_service_ids"], [])
        self.assertEqual(detail["metrics"]["migration_coverage"]["signer_containment"]["rate"], 1)
        self.assertEqual(detail["metrics"]["migration_coverage"]["archive_gates"]["rate"], 0)
        self.assertEqual(sum(x["required"] for x in detail["metrics"]["policy_scenarios"].values()), 21)

    def test_diagnostic_total_is_not_capped(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            previous = grade.LOGS
            try:
                grade.LOGS = Path(tmp)
                grade.emit({"errors": [f"failure-{i}" for i in range(125)]})
                detail = json.loads((Path(tmp) / "details.json").read_text())
            finally:
                grade.LOGS = previous
        self.assertEqual(detail["diagnostics_count"], 125)
        self.assertEqual(len(detail["diagnostics"]), 120)
        self.assertTrue(detail["diagnostics_truncated"])
        self.assertIsNone(detail["metrics"]["policy_scenarios"]["tls"]["rate"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
