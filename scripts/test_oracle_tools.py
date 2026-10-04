"""Finite offline checks: no oracle helper or HTTP failure may become a pass."""

import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test-vectors/scripts"))
import rejection_corpus as corpus
import verify_bytes_to_sign as messages


class MessageTests(unittest.TestCase):
    def test_matches_mismatches_helper_errors_and_complete_denominator(self):
        entries = [dict(id=str(i), bytes="ab", bytesToSign="cd") for i in range(4)]
        outcomes = [subprocess.CompletedProcess([], 0, stdout="cd\n", stderr=""),
                    subprocess.CompletedProcess([], 0, stdout="ff\n", stderr=""),
                    subprocess.CompletedProcess([], 1, stdout="cd\n", stderr="compile failed"),
                    subprocess.CompletedProcess([], 0, stdout="not hex", stderr="")]
        with patch.object(messages.subprocess, "run", side_effect=outcomes):
            rows = messages.verify(entries, ["fixture-helper"])
        self.assertEqual([row["status"] for row in rows], ["match", "MISMATCH", "ERROR", "ERROR"])
        self.assertEqual(len(rows), len(entries))

    def test_empty_or_malformed_inputs_fail(self):
        for entries in ([], {}, [dict(id="0", bytes="a", bytesToSign="cd")]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                messages.verify(entries, ["fixture-helper"])


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.info = dict(fullHeight=100, bestFullHeaderId="ab" * 32)
        self.context = dict(height=100, sourceBox=dict(boxId="cd" * 32), referenceInfo=self.info)
        self.rows = [dict(label=label, category=category, txHex="00", txJson=dict(case=label),
                          height=100, sourceBox=self.context["sourceBox"], sourceBoxId="cd" * 32)
                     for label, category in corpus.CATEGORIES.items()]
        self.response = dict(error=400, reason="Bad Request", detail="reference validation failed")

    def test_complete_capture_retains_submitted_object_and_response(self):
        with patch.object(corpus, "get", return_value=self.info), \
                patch.object(corpus, "request", return_value=(400, self.response)) as request:
            results = corpus.capture("http://fixture.invalid", self.context, self.rows, corpus.tip(self.info))
        self.assertEqual(len(results), 7)
        self.assertEqual([call.args[2] for call in request.call_args_list], [row["txJson"] for row in self.rows])
        self.assertTrue(all(row["referenceResponse"] == self.response for row in results))
        self.assertEqual([row["txHex"] for row in results], [row["txHex"] for row in self.rows])

    def test_acceptance_authentication_infrastructure_and_malformed_responses_fail(self):
        outcomes = [(200, "accepted"), (401, dict(reason="Unauthorized")),
                    (500, dict(error=500, detail="server error")), (400, []),
                    (400, dict(error=400, reason="Bad Request")),
                    (400, dict(detail="proxy failure"))]
        for response in outcomes:
            with self.subTest(response=response), patch.object(corpus, "get", return_value=self.info), \
                    patch.object(corpus, "request", return_value=response), self.assertRaises(ValueError):
                corpus.capture("http://fixture.invalid", self.context, self.rows, corpus.tip(self.info))

    def test_tip_change_before_or_during_submission_fails(self):
        changed = dict(self.info, bestFullHeaderId="ff" * 32)
        for info in ([changed], [self.info, changed]):
            with patch.object(corpus, "get", side_effect=info), \
                    patch.object(corpus, "request", return_value=(400, self.response)), self.assertRaises(ValueError):
                corpus.capture("http://fixture.invalid", self.context, self.rows, corpus.tip(self.info))

    def test_missing_duplicate_or_changed_context_mutations_fail(self):
        variants = [self.rows[:-1], self.rows + self.rows[:1],
                    [dict(row, height=101) for row in self.rows],
                    [dict(row, txHex="not-hex") for row in self.rows]]
        for rows in variants:
            completed = subprocess.CompletedProcess([], 0, stdout="\n".join(map(json.dumps, rows)))
            with patch.object(corpus.subprocess, "run", return_value=completed), self.assertRaises(ValueError):
                corpus.mutations(self.context, ["fixture-helper"])

    def test_categories_match_the_pinned_corpus_and_the_scala_helper(self):
        pinned = json.loads((ROOT / "test-vectors/mainnet/scala_rejection_corpus.json").read_text())
        self.assertEqual({row["label"]: row["expectedCategory"] for row in pinned}, corpus.CATEGORIES)
        helper = (ROOT / "test-vectors/scripts/scala/BuildMutations.scala").read_text()
        emitted = dict(re.findall(r'emit\("(\w+)", "(\w+)"', helper))
        self.assertEqual(emitted, corpus.CATEGORIES)


if __name__ == "__main__":
    unittest.main()
