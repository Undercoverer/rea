"""Real Ghidra regressions. Run with GHIDRA_INSTALL_DIR and JAVA_HOME set."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("rea_workspace", ROOT / "bridge/ghidra/workspace.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@unittest.skipUnless(os.environ.get("GHIDRA_INSTALL_DIR"), "requires a real Ghidra installation")
class PersistentWorkspaceTest(unittest.TestCase):
    def test_reopen_sync_rollback_history_and_iteration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "fixture.c"
            source.write_text("int helper(int value) { return value + 3; }\n"
                              "int caller(int value) { return helper(value) * 2; }\n"
                              "int main(void) { return caller(4); }\n")
            binary = root / "fixture"
            subprocess.run(["gcc", "-g", "-O0", "-fno-inline", "-no-pie", str(source), "-o", str(binary)], check=True)
            symbols = {line.split()[-1]: line.split()[0] for line in
                       subprocess.check_output(["nm", str(binary)], text=True).splitlines() if len(line.split()) == 3}
            project = root / "project"
            def workspace():
                return module.Workspace(binary, project)
            address = symbols["helper"]
            initial = workspace().read(address)
            self.assertEqual(initial["revision"], 0)
            body = "long recovered(long value) { return value + 3; }"
            saved = workspace().write(address, body, 0, signature="long recovered(long value)",
                                      name="recovered", comment="Retained comment", summary="First recovery",
                                      declarations="struct Recovered { int left; int right; };")
            self.assertEqual(saved["source"], body)
            self.assertIn("long", saved["signature"])
            reopened = workspace().read(address)
            self.assertEqual(reopened["revision"], 1)
            self.assertEqual(reopened["comment"], "Retained comment")
            self.assertIn("recovered", workspace().read(symbols["caller"])["decompiled_source"])
            with self.assertRaisesRegex(RuntimeError, "Revision conflict"):
                workspace().write(address, "stale", 0)
            with self.assertRaises(RuntimeError):
                workspace().write(address, "invalid", 1, declarations="struct ShouldRollback { int x; };", signature="not C")
            after = workspace().read(address)
            self.assertEqual(after["source"], body)
            self.assertEqual(after["revision"], 1)
            agent = root / "agent.py"
            agent.write_text("import json,sys\nc=json.load(sys.stdin)['function']\n"
                             "print(json.dumps({'source': c['source'] + '\\n/* improved */', 'summary': 'iteration'}))\n")
            result = workspace().iterate(address, [os.sys.executable, str(agent)], iterations=2)
            self.assertEqual(result["revision"], 3)
            result = workspace().read(address)
            self.assertEqual(len(result["history"]), 3)
            self.assertEqual(result["source"].count("improved"), 2)
            self.assertFalse(result["machine_code_modified"])
            ws = workspace()
            compact = ws.context(address)
            self.assertNotIn("history", compact)
            self.assertEqual(compact["history_count"], 3)
            page = ws.history(address, limit=2)
            self.assertEqual(len(page["revisions"]), 2)
            self.assertNotIn("source", page["revisions"][0])
            batch = ws.request_many([{"method": "read_reconstruction", "params": {"address": address, "view": "context"}}] * 2)
            self.assertEqual(batch[0]["result"], batch[1]["result"])
            self.assertEqual(ws.last_statistics["decompile_calls"], 1)
            self.assertEqual(ws.last_statistics["cache_hits"], 1)
            first = ws.reconstruct_many([address], [os.sys.executable, str(agent)], "test")
            self.assertEqual(first[0]["status"], "completed")
            second = ws.reconstruct_many([address], [os.sys.executable, str(agent)], "test")
            self.assertEqual(second[0]["status"], "skipped")
            with self.assertRaisesRegex(RuntimeError, "Context conflict"):
                ws.write(address, "stale", first[0]["revision"], expected_context_hash=compact["context_hash"])
            # A callee source revision changes caller context even without metadata edits.
            caller_before = ws.context(symbols["caller"])
            ws.write(address, body, first[0]["revision"], view="receipt", summary="new callee insight")
            caller_after = ws.context(symbols["caller"])
            self.assertNotEqual(caller_before["context_hash"], caller_after["context_hash"])
            self.assertEqual(caller_before["revision"], caller_after["revision"])
            listing = ws.functions(limit=2)
            self.assertEqual(len(listing["functions"]), 2)
            following = ws.functions(after=listing["next_after"], limit=2)
            self.assertTrue(set(r["address"] for r in listing["functions"]).isdisjoint(r["address"] for r in following["functions"]))
            migration_scripts = root / "migration-scripts"
            migration_scripts.mkdir()
            shutil.copy2(ROOT / "bridge/ghidra/ReaGhidraReconstructionStore.java", migration_scripts)
            shutil.copy2(Path(__file__).parent / "ReaReconstructionMigrationTest.java", migration_scripts)
            migration = subprocess.run([str(ws.ghidra / "support/analyzeHeadless"), str(project), "rea-project",
                "-process", "*", "-noanalysis", "-scriptPath", str(migration_scripts),
                "-postScript", str(migration_scripts / "ReaReconstructionMigrationTest.java")], capture_output=True, text=True, timeout=600)
            self.assertEqual(migration.returncode, 0)
            self.assertIn("REA_MIGRATION_TEST_PASSED", migration.stdout + migration.stderr)
            other = root / "other"
            other.write_bytes(binary.read_bytes() + b"different")
            with self.assertRaisesRegex(RuntimeError, "digest"):
                module.Workspace(other, project).read(address)


if __name__ == "__main__":
    unittest.main()
