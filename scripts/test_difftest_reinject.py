"""Pure saved-log classification tests, not detector or reinjection receipts."""

import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("reinject_result", Path(__file__).with_name("reinject-result.py"))
RESULT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESULT)


class SavedResultTests(unittest.TestCase):
    def test_unrelated_nonzero_exits_never_count_as_findings(self):
        for code in (2, 3, 101, 127, -9):
            self.assertFalse(RESULT.detected("canonical", "ergo_tree", code,
                                            "[CANONICAL-GATE] FAIL: re-encoded != expected"))
        self.assertFalse(RESULT.detected("canonical", "ergo_tree", 1, "build failed"))

    def test_canonical_marker_requires_the_canonical_surface(self):
        output = "[CANONICAL-GATE] FAIL: re-encoded != expected"
        self.assertTrue(RESULT.detected("canonical", "ergo_tree", 1, output))
        self.assertFalse(RESULT.detected("canonical", "transaction", 1, output))

    def test_canonical_writer_failure_after_a_complete_decode_is_detected(self):
        # unparsed-tree-canonical's injected bug surfaces only as a writer error.
        output = "[CANONICAL-GATE] FAIL: re-encode failed after a complete decode: InvalidData"
        self.assertTrue(RESULT.detected("canonical", "ergo_tree", 1, output))
        self.assertFalse(RESULT.detected("canonical", "ergo_tree", 3, output))
        self.assertFalse(RESULT.detected("canonical", "ergo_tree", 3,
                                         "[CANONICAL-GATE] HARNESS ERROR: trailing input bytes"))

    def test_accept_reject_requires_the_declared_surface_and_class(self):
        self.assertTrue(RESULT.detected("accept-reject", "ergo_tree", 1, "  [AcceptReject] ergo_tree\n"))
        self.assertFalse(RESULT.detected("accept-reject", "header", 1, "  [AcceptReject] ergo_tree\n"))
        self.assertFalse(RESULT.detected("accept-reject", "ergo_tree", 1, "  [Canonical] ergo_tree\n"))

    def test_cost_marker_requires_equal_properties_and_different_costs(self):
        output = '  [Canonical] reduce\n    rust=Accept("P:d3|3")\n    jvm =Accept("P:d3|6")\n'
        self.assertTrue(RESULT.detected("cost", "reduce", 1, output))
        self.assertFalse(RESULT.detected("cost", "reduce", 1, output.replace("d3|6", "d2|6")))
        self.assertFalse(RESULT.detected("cost", "reduce", 1, output.replace("d3|6", "d3|3")))

    def test_panic_marker_cannot_be_a_fixed_point_or_another_surface(self):
        self.assertTrue(RESULT.detected("panic", "verify_avl", 1, "  [BUG] verify_avl: PANIC: fixture"))
        self.assertFalse(RESULT.detected("panic", "verify_avl", 1, "  [BUG] verify_avl: fixed-point mismatch"))
        self.assertFalse(RESULT.detected("panic", "verify_avl", 1, "  [BUG] header: PANIC: fixture"))

    def test_harness_error_wins_even_with_a_finding_marker(self):
        self.assertFalse(RESULT.detected("verify", "verify", 1,
                                        "  [Canonical] verify\noracle: HARNESS ERROR: incomplete"))


if __name__ == "__main__":
    unittest.main()
