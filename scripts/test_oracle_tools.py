"""Finite offline checks: no oracle helper or HTTP failure may become a pass."""

import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

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

    def test_main_exits_nonzero_unless_every_message_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            source, report = Path(directory) / "transactions.json", Path(directory) / "report.json"
            source.write_text(json.dumps([dict(id="0", bytes="ab", bytesToSign="cd")]))
            for helper_output, expected_exit in (("cd\n", 0), ("ff\n", 1)):
                completed = subprocess.CompletedProcess([], 0, stdout=helper_output, stderr="")
                with self.subTest(helper_output=helper_output), \
                        patch.object(sys, "argv", ["verify", str(source), str(report)]), \
                        patch.object(messages.subprocess, "run", return_value=completed):
                    self.assertEqual(messages.main(), expected_exit)
                    self.assertEqual(len(json.loads(report.read_text())), 1)

    def test_report_keeps_the_replaced_mode_or_the_umask_default(self):
        previous = os.umask(0o027)
        try:
            with tempfile.TemporaryDirectory() as directory:
                report = Path(directory) / "report.json"
                messages.write_report(report, [])
                self.assertEqual(report.stat().st_mode & 0o777, 0o640)
                report.chmod(0o644)
                messages.write_report(report, [dict(id="0")])
                self.assertEqual(report.stat().st_mode & 0o777, 0o644)
                self.assertEqual(json.loads(report.read_text()), [dict(id="0")])
        finally:
            os.umask(previous)


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.info = dict(fullHeight=100, bestFullHeaderId="ab" * 32)
        self.context = dict(height=100, sourceBox=dict(boxId="cd" * 32), referenceInfo=self.info)
        self.rows = [dict(label=label, category=category, txHex="00", txJson=dict(case=label),
                          height=100, sourceBox=self.context["sourceBox"], sourceBoxId="cd" * 32)
                     for label, category in corpus.CATEGORIES.items()]
        self.response = dict(error=400, reason="Bad Request", detail="reference validation failed")

    def helper_output(self, rows):
        return subprocess.CompletedProcess([], 0, stdout="\n".join(map(json.dumps, rows)))

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

    def test_complete_consistent_mutation_set_is_accepted(self):
        # Accepting control for the rejections below.
        with patch.object(corpus.subprocess, "run", return_value=self.helper_output(self.rows)):
            self.assertEqual(corpus.mutations(self.context, ["fixture-helper"]), self.rows)

    def test_missing_duplicate_or_changed_context_mutations_fail(self):
        variants = [self.rows[:-1], self.rows + self.rows[:1],
                    [dict(row, height=101) for row in self.rows],
                    [dict(row, txHex="not-hex") for row in self.rows],
                    [dict(row, category="PROOF") if row["label"] == "invalid_proof" else row
                     for row in self.rows],
                    [dict(row, sourceBox=dict(boxId="ef" * 32)) for row in self.rows],
                    [dict(row, sourceBoxId="ef" * 32) for row in self.rows]]
        for rows in variants:
            with self.subTest(rows=rows), \
                    patch.object(corpus.subprocess, "run", return_value=self.helper_output(rows)), \
                    self.assertRaises(ValueError):
                corpus.mutations(self.context, ["fixture-helper"])

    def test_failed_or_malformed_helper_output_is_never_a_mutation_set(self):
        complete = "\n".join(map(json.dumps, self.rows))
        # Every valid row printed, then a nonzero exit: the real subprocess
        # check must still reject the helper run.
        failing = [sys.executable, "-c", "import sys; print(sys.stdin.read() and sys.argv[1]); sys.exit(1)",
                   complete]
        with self.assertRaises(subprocess.CalledProcessError):
            corpus.mutations(self.context, failing)
        malformed = subprocess.CompletedProcess([], 0, stdout=complete + "\n{not json")
        with patch.object(corpus.subprocess, "run", return_value=malformed), self.assertRaises(ValueError):
            corpus.mutations(self.context, ["fixture-helper"])

    def test_categories_match_the_pinned_corpus_and_the_scala_helper(self):
        pinned = json.loads((ROOT / "test-vectors/mainnet/scala_rejection_corpus.json").read_text())
        self.assertEqual({row["label"]: row["expectedCategory"] for row in pinned}, corpus.CATEGORIES)
        helper = (ROOT / "test-vectors/scripts/scala/BuildMutations.scala").read_text()
        emitted = dict(re.findall(r'emit\("(\w+)", "(\w+)"', helper))
        self.assertEqual(emitted, corpus.CATEGORIES)

    def test_request_returns_the_http_error_status_and_body(self):
        error = HTTPError("http://fixture.invalid/x", 400, "Bad Request", {},
                          io.BytesIO(json.dumps(self.response).encode()))
        with patch.object(corpus, "urlopen", side_effect=error):
            self.assertEqual(corpus.request("http://fixture.invalid", "/x", dict(a=1)),
                             (400, self.response))

    def test_source_box_takes_the_first_unspent_token_free_p2pk_box(self):
        p2pk = "0008cd" + "02" * 33
        outputs = [dict(boxId="01" * 32, value=2_000_000, assets=[dict(tokenId="aa" * 32, amount=1)],
                        ergoTree=p2pk),
                   dict(boxId="02" * 32, value=2_000_000, assets=[], ergoTree="1000d1"),
                   dict(boxId="03" * 32, value=1_000_000, assets=[], ergoTree=p2pk),
                   dict(boxId="04" * 32, value=2_000_000, assets=[], ergoTree=p2pk),
                   dict(boxId="05" * 32, value=2_000_000, assets=[], ergoTree=p2pk)]
        reads = {"/blocks/at/100": ["block"],
                 "/blocks/block/transactions": dict(transactions=[dict(outputs=outputs)]),
                 "/blockchain/box/byId/" + "05" * 32: dict(boxId="05" * 32)}
        lookups = []

        def utxo(_, path):
            lookups.append(path)
            return (404, {}) if path.endswith("04" * 32) else (200, {})

        with patch.object(corpus, "get", side_effect=lambda _, path: reads[path]), \
                patch.object(corpus, "request", side_effect=utxo):
            self.assertEqual(corpus.source_box("http://fixture.invalid", 100), dict(boxId="05" * 32))
        # Token, non-P2PK and minimum-value boxes are never looked up; a spent
        # (404) box is skipped.
        self.assertEqual(lookups, ["/utxo/byId/" + "04" * 32, "/utxo/byId/" + "05" * 32])

    def test_source_box_aborts_on_lookup_failure_or_changed_identity(self):
        # A later eligible box must not replace one whose lookup failed.
        outputs = [dict(boxId=box * 32, value=2_000_000, assets=[], ergoTree="0008cd" + "02" * 33)
                   for box in ("05", "06")]
        reads = {"/blocks/at/100": ["block"],
                 "/blocks/block/transactions": dict(transactions=[dict(outputs=outputs)]),
                 "/blockchain/box/byId/" + "05" * 32: dict(boxId="07" * 32),
                 "/blockchain/box/byId/" + "06" * 32: dict(boxId="06" * 32)}
        for status in (401, 500, 200):
            def utxo(_, path, status=status):
                return (status if path.endswith("05" * 32) else 200), {}

            with self.subTest(status=status), \
                    patch.object(corpus, "get", side_effect=lambda _, path: reads[path]), \
                    patch.object(corpus, "request", side_effect=utxo), self.assertRaises(ValueError):
                corpus.source_box("http://fixture.invalid", 100)

    def test_failed_capture_leaves_the_previous_corpus_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "corpus.json"
            output.write_text("previous corpus\n")
            with patch.object(sys, "argv", ["build", str(output)]), \
                    patch.object(corpus, "get", return_value=self.info), \
                    patch.object(corpus, "source_box", return_value=self.context["sourceBox"]), \
                    patch.object(corpus, "mutations", return_value=self.rows), \
                    patch.object(corpus, "request", return_value=(200, "accepted")), \
                    self.assertRaises(ValueError):
                corpus.main()
            self.assertEqual(output.read_text(), "previous corpus\n")
            self.assertEqual(os.listdir(directory), ["corpus.json"])


if __name__ == "__main__":
    unittest.main()
