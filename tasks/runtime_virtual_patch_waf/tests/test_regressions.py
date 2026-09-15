#!/usr/bin/env python3
"""Diagnostic controls, then the full policy matrix when given KNOWN_GOOD_POLICY.json."""
import sys
import unittest

from test_diagnostic_metrics import ReplayMetricsTests


if __name__ == "__main__":
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(ReplayMetricsTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    if len(sys.argv) > 1:
        import regression_specimens
        regression_specimens.main()
