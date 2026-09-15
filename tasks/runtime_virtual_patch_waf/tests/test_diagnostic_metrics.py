"""Coverage regression: interrupted and invalid requests must not inflate scores."""
import unittest

from diagnostic_metrics import replay_metrics


class ReplayMetricsTests(unittest.TestCase):
    def test_interruption_keeps_full_denominator(self):
        rows = [("a", {}, "encoding", "json"), ("b", {}, "encoding", "json"),
                ("c", {}, "routing", "query")]
        metric = replay_metrics(rows, {"a", "b"}, {"a": {"decision": "block", "status": 403}}, "block")
        self.assertEqual((metric["passed"], metric["not_evaluated"], metric["pass_rate"]), (1, 2, 1 / 3))
        self.assertEqual(metric["by_carrier"]["query"]["attempted"], 0)
        self.assertEqual(metric["by_family"]["encoding"]["pass_rate"], 0.5)

    def test_server_error_is_not_successful_security_denial(self):
        rows = [("a", {}, "encoding", "json")]
        metric = replay_metrics(rows, {"a"}, {"a": {"decision": "block", "status": 500}}, "block")
        self.assertEqual((metric["passed"], metric["failed"]), (0, 1))

    def test_benign_deny_is_false_positive(self):
        rows = [("a", {}, "import", "multipart")]
        metric = replay_metrics(rows, {"a"}, {"a": {"decision": "block", "status": 403}}, "allow")
        self.assertEqual(metric["pass_rate"], 0)


if __name__ == "__main__":
    unittest.main()
