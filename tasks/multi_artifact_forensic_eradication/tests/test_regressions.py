"""Offline oracle rehearsal and independent forensic-verifier negative controls."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


grader = load("forensic_grader", "tests/grader.py")


class ForensicRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="forensic-review-")
        cls.directory = Path(cls.temp.name)
        cls.state = cls.directory / "state.json"
        cls.report = cls.directory / "report.json"
        cls.state.write_bytes((ROOT / "environment/assets/public/state-template.json").read_bytes())
        oracle = load("forensic_oracle", "solution/solution.py")
        control = load("forensic_control", "environment/assets/public/irctl.py")
        control.STATE = cls.state
        oracle.E = ROOT / "environment/assets/public/evidence"
        oracle.STATE = cls.state
        oracle.REPORT = cls.report
        def run_control(*args):
            result = control.main(list(args))
            if result != 0:
                raise RuntimeError(f"reference control failed: {args}")
        oracle.run = run_control
        with contextlib.redirect_stdout(io.StringIO()):
            oracle.main()
        cls.correct_report = json.loads(cls.report.read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        grader.D = {"reward": 0.0, "subscores": {}, "problems": [], "metrics": {}}
        self.report = copy.deepcopy(self.correct_report)

    def test_full_reference_pass_and_domain_metrics(self):
        grader.STATE = self.state
        grader.REPORT = type(self).report
        grader.LOGDIR = self.directory / "logs"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(grader.main(), 0, grader.D["problems"])
        self.assertEqual(grader.D["reward"], 1.0)
        self.assertEqual(grader.D["metrics"]["semantic_groups"], {"passed": 8, "total": 8})
        self.assertEqual(grader.D["metrics"]["timeline"]["covered_hops"], 2)

    def test_same_login_cannot_cover_both_lateral_hops(self):
        lateral = [r for r in self.report["timeline"] if r["kind"] == "lateral_access"]
        lateral[1].update(time_utc="2025-04-17T09:18:21Z", evidence=[{
            "path": "linux/backup-gw-02-auth.log", "locator": "2025-04-17T09:18:21Z"}])
        self.assertFalse(grader.check_timeline(self.report))

    def test_ssh_launch_is_not_persistence(self):
        self.report["timeline"] = [r for r in self.report["timeline"] if r["kind"] != "persistence_activation"]
        self.report["timeline"].append({"time_utc": "2025-04-17T09:23:41Z", "kind": "persistence_activation",
            "evidence": [{"path": "linux/backup-gw-02-audit.jsonl", "locator": "AUDIT-394"}]})
        self.assertFalse(grader.check_timeline(self.report))

    def test_equivalent_timestamps_order_and_cross_section_citations(self):
        for item in self.report["timeline"]:
            item["time_utc"] = item["time_utc"].replace("Z", "+00:00")
        self.report["timeline"].reverse()
        # Move corroboration to another existing section while retaining one
        # valid locator per finding. A report is an evidence graph, not a form.
        for item in self.report["persistence"]:
            self.report["initial_access"]["evidence"].extend(item["evidence"][1:])
            item["evidence"] = item["evidence"][:1]
        self.assertTrue(grader.check_timeline(self.report), grader.D["problems"])
        self.assertTrue(grader.check_persistence(self.report), grader.D["problems"])
        self.assertTrue(grader.check_lateral(self.report), grader.D["problems"])

    def test_unrelated_records_do_not_corroborate_a_hop(self):
        records = grader.selected_records(self.report)
        identity = grader.HOPS[0][:3]
        other_hop = [r for r in records if grader.HOPS[1][:3] in grader.record_hops(r)]
        one_flow = [r for r in records if r["family"] == "network" and identity in grader.record_hops(r)]
        self.assertFalse(grader.corroborated_hop(other_hop + one_flow, identity))

    def test_wrong_pid_or_host_does_not_join_runtime(self):
        records = [r for r in grader.selected_records(self.report) if r["family"] != "network"]
        for record in records:
            if record["family"] == "memory-socket" and record["host"] == "backup-gw-02":
                record["data"]["pid"] = "unrelated-pid"
        self.assertFalse(grader.service_support(records, "backup-gw-02", "/opt/cache/cert_sync.py", "203.0.113.201"))

    def test_alternative_unit_execution_and_network_corroboration(self):
        records = [r for r in grader.selected_records(self.report) if r["family"] != "memory-socket"]
        self.assertTrue(grader.service_support(records, "backup-gw-02", "/opt/cache/cert_sync.py", "203.0.113.201"))
        self.assertTrue(grader.service_support(records, "vault-prx-03", "/usr/local/libexec/.index-cache", "198.51.100.203"))

    def test_missing_malformed_and_partial_state_keep_denominators(self):
        partial = json.loads(self.state.read_text())
        del partial["credentials"]["CORP\\svc_reporting"]["version"]
        del partial["services"]["reporting-api"]["credential_version"]
        for state in (None, {}, [], {"hosts": []}, partial):
            with self.subTest(state_type=type(state).__name__):
                self.assertFalse(grader.check_state(state))
                self.assertFalse(grader.check_recovery(state))
                for name, total in (("eradication_and_preservation", 25), ("service_recovery", 7)):
                    metric = grader.D["metrics"][name]
                    self.assertEqual(metric["total"], total)
                    self.assertEqual(metric["evaluated"] + metric["not_evaluated"], total)
                    self.assertGreater(metric["not_evaluated"], 0)
                    self.assertLess(metric["passed"], total)

    def test_independent_authentication_citations_need_no_approved_key_literal(self):
        # Reproduce the independently authored public solve's key findings using
        # public record locators. No review artifacts are task runtime inputs.
        def remove_baselines(value):
            if isinstance(value, dict):
                if "evidence" in value:
                    value["evidence"] = [c for c in value["evidence"] if not c["path"].startswith("cmdb/")]
                for child in value.values(): remove_baselines(child)
            elif isinstance(value, list):
                for child in value: remove_baselines(child)
        remove_baselines(self.report)
        for item in self.report["persistence"]:
            if item["kind"] != "ssh_authorized_key": continue
            host = item["host"]
            gateway = host == "backup-gw-02"
            principal = "backupsvc" if gateway else "vaultsync"
            comment = "deploy@acct-ws-04" if gateway else "cache-maint@backup-gw-02"
            item["evidence"] = [
                {"path": f"linux/{host}-auth.log", "locator": "2025-04-17T09:18:20Z" if gateway else "2025-04-17T09:24:06Z"},
                {"path": f"linux/{host}-audit.jsonl", "locator": "AUDIT-393" if gateway else "VAUDIT-773"},
                {"path": f"filesystem/{host}/home/{principal}/.ssh/authorized_keys", "locator": comment}]
        self.assertTrue(grader.check_persistence(self.report), grader.D["problems"])

    def test_key_capture_accepts_each_documented_corroboration_family(self):
        for host, principal, fingerprint, comment, approved, audit in (
            ("backup-gw-02", "backupsvc", grader.ROGUE_FP, "deploy@acct-ws-04", grader.APPROVED_FP, "AUDIT-393"),
            ("vault-prx-03", "vaultsync", grader.ROGUE2_FP, "cache-maint@backup-gw-02", grader.APPROVED2_FP, "VAUDIT-773")):
            capture = {"path": f"filesystem/{host}/home/{principal}/.ssh/authorized_keys", "locator": comment}
            contexts = [{"path": "cmdb/assets.json", "locator": approved},
                        {"path": f"linux/{host}-auth.log", "locator": fingerprint},
                        {"path": f"linux/{host}-audit.jsonl", "locator": audit}]
            for context in contexts:
                with self.subTest(host=host, context=context["path"]):
                    records = grader.selected_records({"evidence": [capture, context]})
                    self.assertTrue(grader.malicious_key_support(records, host, fingerprint, comment))

    def test_wrong_key_and_wrong_host_cannot_corroborate_rogue_key(self):
        capture = {"path": "filesystem/backup-gw-02/home/backupsvc/.ssh/authorized_keys", "locator": "deploy@acct-ws-04"}
        wrong_key = dict(capture, locator="ops@vault")
        valid_auth = {"path": "linux/backup-gw-02-auth.log", "locator": grader.ROGUE_FP}
        other_auth = {"path": "linux/vault-prx-03-auth.log", "locator": grader.ROGUE2_FP}
        other_baseline = {"path": "cmdb/assets.json", "locator": grader.APPROVED2_FP}
        other_audit = {"path": "linux/vault-prx-03-audit.jsonl", "locator": "VAUDIT-773"}
        for citations in ([wrong_key, valid_auth], [capture, other_auth], [capture, other_baseline], [capture, other_audit]):
            records = grader.selected_records({"evidence": citations})
            self.assertFalse(grader.malicious_key_support(records, "backup-gw-02", grader.ROGUE_FP, "deploy@acct-ws-04"))

    def test_legitimate_key_findings_still_pass(self):
        for host, principal, comment, fingerprint in (
            ("backup-gw-02", "backupsvc", "ops@vault", grader.APPROVED_FP),
            ("vault-prx-03", "vaultsync", "archive-admin@corp", grader.APPROVED2_FP)):
            self.report["persistence"].append({"host": host, "kind": "ssh_authorized_key",
                "object": fingerprint, "effect": "reentry", "assessment": "benign", "evidence": [
                    {"path": f"filesystem/{host}/home/{principal}/.ssh/authorized_keys", "locator": comment},
                    {"path": "cmdb/assets.json", "locator": fingerprint}]})
        self.assertTrue(grader.check_persistence(self.report), grader.D["problems"])

    def runtime_citations(self, host):
        gateway = host == "backup-gw-02"
        return [
            {"path": f"linux/{host}-audit.jsonl", "locator": "AUDIT-392" if gateway else "VAUDIT-772"},
            {"path": f"memory/{host}-processes.csv", "locator": "cert_sync.py" if gateway else ".index-cache"}]

    def key_citations(self, host):
        gateway = host == "backup-gw-02"
        return [
            {"path": f"linux/{host}-auth.log", "locator": grader.ROGUE_FP if gateway else grader.ROGUE2_FP},
            {"path": f"linux/{host}-audit.jsonl", "locator": "AUDIT-393" if gateway else "VAUDIT-773"}]

    def test_report_accepts_runtime_corroboration_without_filesystem_captures(self):
        # Model run njVB2ng used these independent source pairs. Remove every
        # filesystem citation, including cross-section evidence, to reproduce
        # the formerly rejected presentation without leaking in oracle support.
        def remove_captures(value):
            if isinstance(value, dict):
                if "evidence" in value:
                    value["evidence"] = [c for c in value["evidence"] if not c["path"].startswith("filesystem/")]
                for child in value.values(): remove_captures(child)
            elif isinstance(value, list):
                for child in value: remove_captures(child)
        remove_captures(self.report)
        for item in self.report["persistence"]:
            if item["kind"] == "systemd_service":
                item["evidence"] = self.runtime_citations(item["host"])
            elif item["kind"] == "ssh_authorized_key":
                item["evidence"] = self.key_citations(item["host"])
        for check in (grader.check_scope, grader.check_initial, grader.check_lateral,
                      grader.check_persistence, grader.check_timeline, grader.check_indicators):
            with self.subTest(check=check.__name__):
                self.assertTrue(check(self.report), grader.D["problems"])

    def test_runtime_service_evidence_requires_activation_and_matching_process(self):
        for host, payload, c2 in (
            ("backup-gw-02", "/opt/cache/cert_sync.py", "203.0.113.201"),
            ("vault-prx-03", "/usr/local/libexec/.index-cache", "198.51.100.203")):
            records = grader.selected_records({"evidence": self.runtime_citations(host)})
            self.assertTrue(grader.service_support(records, host, payload, c2))
            for mutation in ("audit_only", "process_only", "wrong_host", "wrong_payload",
                             "wrong_unit", "disabled_unit", "old_process", "wrong_parent"):
                bad = copy.deepcopy(records)
                audit, process = bad
                if mutation == "audit_only": bad = [audit]
                elif mutation == "process_only": bad = [process]
                elif mutation == "wrong_host": process["host"] = "report-db-01"
                elif mutation == "wrong_payload": process["data"]["command_line"] = process["data"]["command_line"].replace(payload, payload + ".unrelated")
                elif mutation == "wrong_unit": audit["data"]["command"] = "systemctl enable --now unrelated.service"
                elif mutation == "disabled_unit": audit["data"]["command"] = audit["data"]["command"].replace("enable", "disable")
                elif mutation == "old_process": process["data"]["start_time_utc"] = "2025-04-17T07:00:00Z"
                else: process["data"]["ppid"] = "9999"
                with self.subTest(host=host, mutation=mutation):
                    self.assertFalse(grader.service_support(bad, host, payload, c2))

    def test_key_authentication_and_addition_require_same_identity_and_account(self):
        for host, fingerprint, comment in (
            ("backup-gw-02", grader.ROGUE_FP, "deploy@acct-ws-04"),
            ("vault-prx-03", grader.ROGUE2_FP, "cache-maint@backup-gw-02")):
            records = grader.selected_records({"evidence": self.key_citations(host)})
            self.assertTrue(grader.malicious_key_support(records, host, fingerprint, comment))
            for mutation in ("auth_only", "audit_only", "wrong_host", "wrong_key", "wrong_account",
                             "wrong_path", "no_addition", "duplicate_auth"):
                bad = copy.deepcopy(records)
                auth, audit = bad
                if mutation == "auth_only": bad = [auth]
                elif mutation == "audit_only": bad = [audit]
                elif mutation == "wrong_host": audit["host"] = "report-db-01"
                elif mutation == "wrong_key": auth["line"] = auth["line"].replace(fingerprint, grader.APPROVED_FP)
                elif mutation == "wrong_account": audit["data"]["auid"] = "unrelated"
                elif mutation == "wrong_path": audit["data"]["command"] += ".unrelated"
                elif mutation == "no_addition": audit["data"]["command"] = "cat " + audit["data"]["object"]
                else: bad = [auth, copy.deepcopy(auth)]
                with self.subTest(host=host, mutation=mutation):
                    self.assertFalse(grader.malicious_key_support(bad, host, fingerprint, comment))

    def test_trusted_fixture_matches_public_evidence(self):
        public = ROOT / "environment/assets/public/evidence"
        expected = {p.relative_to(public): p.read_bytes() for p in public.rglob("*") if p.is_file()}
        actual = {p.relative_to(grader.EVIDENCE): p.read_bytes() for p in grader.EVIDENCE.rglob("*") if p.is_file()}
        self.assertEqual(actual, expected)
        self.assertEqual(grader.EVIDENCE, ROOT / "tests/fixtures/evidence")

    def test_empty_report_and_unrepaired_state_fail(self):
        self.assertFalse(grader.check_timeline({"timeline": []}))
        self.assertFalse(grader.check_state(json.loads((ROOT / "environment/assets/public/state-template.json").read_text())))


if __name__ == "__main__":
    unittest.main()
