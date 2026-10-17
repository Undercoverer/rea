"""Orchestration-only tests; workspace_test.py checks the real Ghidra provider."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import json

spec = importlib.util.spec_from_file_location("workspace", Path(__file__).resolve().parents[3] / "bridge/ghidra/workspace.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Fake(m.Workspace):
    def __init__(self, path):
        self.project = Path(path)
        self.contexts = {a: dict(address=a, revision=0, context_hash=a, source_sha256=a,
                               source="return 1;", callees=[]) for a in ["a", "b"]}
        self.calls = []
        self.fail = None

    def context(self, address):
        return dict(self.contexts[address])

    def request_many(self, requests, timeout=600):
        return [dict(ok=True, result=self.context(r["params"]["address"])) for r in requests]

    def _improve(self, context, *args):
        a = context["address"]
        self.calls.append(a)
        if a == self.fail:
            raise ValueError("adapter failed")
        result = self.contexts[a]
        result["revision"] += 1
        result["context_hash"] += "x"
        return dict(result), False


class UnitTest(unittest.TestCase):
    def test_exact_edits(self):
        self.assertEqual(m.apply_edits("return 1;", [{"old": "1", "new": "2"}]), "return 2;")
        for source, old in [("aaa", "aa"), ("aa", "a"), ("abc", "z"), ("abc", "")]:
            with self.assertRaises(ValueError):
                m.apply_edits(source, [{"old": old, "new": "x"}])

    def test_resume_after_failure_and_task_changes(self):
        with tempfile.TemporaryDirectory() as root:
            w = Fake(root)
            w.fail = "b"
            with self.assertRaises(ValueError):
                w.reconstruct_many(["a", "b"], ["model"], "v1")
            w.fail = None
            result = w.reconstruct_many(["a", "a", "b"], ["model"], "v1")
            self.assertEqual([r["status"] for r in result], ["skipped", "completed"])
            self.assertEqual(w.calls, ["a", "b", "b"])
            w.reconstruct_many(["a"], ["model"], "v2")
            self.assertEqual(w.calls[-1], "a")
            result = w.reconstruct_many(["a"], ["model"], "v2", force=True)
            self.assertEqual(result[0]["status"], "completed")

    def test_pending_caller_is_refreshed(self):
        with tempfile.TemporaryDirectory() as root:
            w = Fake(root)
            w.contexts["b"]["callees"] = [{"address": "a"}]
            original = w.context
            refreshed = []
            def observe(address):
                if address == "b":
                    refreshed.append(w.contexts["a"]["revision"])
                return original(address)
            w.context = observe
            w.reconstruct_many(["a", "b"], ["model"], "task")
            self.assertEqual(refreshed, [0, 1])

    def test_journal_lock_refuses_duplicate_worker(self):
        with tempfile.TemporaryDirectory() as root:
            w = Fake(root)
            with open(Path(root) / ".rea-work.lock", "a") as lock:
                m.fcntl.flock(lock, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    w.reconstruct_many(["a"], ["model"], "task")
            self.assertEqual(w.calls, [])

    def test_budget_prevents_model_call(self):
        with tempfile.TemporaryDirectory() as root, patch.object(m.subprocess, "run") as run:
            w = Fake(root)
            with self.assertRaisesRegex(ValueError, "exceeds"):
                m.Workspace._improve(w, w.context("a"), ["model"], "instruction", 1)
            run.assert_not_called()

    def test_unchanged_and_invalid_responses(self):
        with tempfile.TemporaryDirectory() as root:
            w = Fake(root)
            for response in [{"unchanged": True}, {"unchanged": 1}, {"unchanged": True, "name": "bad"}, {"source": "x", "edits": []}]:
                with patch.object(m.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(response))):
                    if set(response) == {"unchanged"} and response["unchanged"] is True:
                        result, semantic = m.Workspace._improve(w, w.context("a"), ["model"], "", 65536)
                        self.assertEqual(result["revision"], 0)
                        self.assertFalse(semantic)
                    else:
                        with self.assertRaises(ValueError):
                            m.Workspace._improve(w, w.context("a"), ["model"], "", 65536)


if __name__ == "__main__":
    unittest.main()
