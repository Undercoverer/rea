"""Real Ghidra regressions. Run with GHIDRA_INSTALL_DIR and JAVA_HOME set."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
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
            self.assertEqual(len(result["history"]), 3)
            self.assertEqual(result["source"].count("improved"), 2)
            self.assertFalse(result["machine_code_modified"])
            other = root / "other"
            other.write_bytes(binary.read_bytes() + b"different")
            with self.assertRaisesRegex(RuntimeError, "digest"):
                module.Workspace(other, project).read(address)


if __name__ == "__main__":
    unittest.main()
