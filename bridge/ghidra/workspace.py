#!/usr/bin/env python3
"""Persistent REA Ghidra source API. Python 3.10+, standard library only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def binary_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as binary:
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Workspace:
    """One binary/project. Never overwrite a project or bypass Ghidra's lock."""
    def __init__(self, binary, project, ghidra=None):
        self.binary = Path(binary).resolve(strict=True)
        self.project = Path(project).resolve()
        self.ghidra = Path(ghidra or os.environ["GHIDRA_INSTALL_DIR"]).resolve(strict=True)

    def request(self, method, params, timeout=600):
        self.project.mkdir(parents=True, exist_ok=True, mode=0o700)
        scripts = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(prefix="rea-request-") as temporary:
            request = Path(temporary) / "request.json"
            response = Path(temporary) / "response.json"
            request.write_text(json.dumps({"binary_sha256": binary_digest(self.binary),
                                          "method": method, "params": params}), encoding="utf-8")
            reopening = (self.project / "rea-project.gpr").exists()
            command = [str(self.ghidra / "support" / "analyzeHeadless"), str(self.project), "rea-project"]
            command += ["-process", "*", "-noanalysis"] if reopening else ["-import", str(self.binary)]
            command += ["-scriptPath", str(scripts), "-postScript", str(scripts / "ReaGhidraWorkspace.java"),
                        str(request), str(response)]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            if completed.returncode or not response.exists():
                raise RuntimeError("Ghidra request failed:\n" + completed.stdout + completed.stderr)
            payload = json.loads(response.read_text(encoding="utf-8"))
            if not payload["ok"]:
                raise RuntimeError(payload["error"])
            # Headless may report import save failures with exit code zero.
            if not (self.project / "rea-project.rep").is_dir():
                raise RuntimeError("Ghidra did not save the project database")
            if "Save failed" in completed.stdout or "Save failed" in completed.stderr:
                raise RuntimeError("Ghidra could not save the imported program")
            return payload["result"]

    def read(self, address):
        return self.request("read_reconstruction", {"address": address})

    def write(self, address, source, expected_revision, **metadata):
        return self.request("write_reconstruction", dict(metadata, address=address,
                            source=source, expected_revision=expected_revision))

    def iterate(self, address, command, iterations=1, instruction="Improve the reconstructed C using the available evidence"):
        """Explicit caller-selected AI command: JSON context in, edit object out."""
        if iterations < 1:
            raise ValueError("iterations must be positive")
        for _ in range(iterations):
            context = self.read(address)
            completed = subprocess.run(command, input=json.dumps({"instruction": instruction, "function": context}),
                                       capture_output=True, text=True, check=True, timeout=600)
            edit = json.loads(completed.stdout)
            if not isinstance(edit, dict) or "source" not in edit:
                raise ValueError("AI command must return an object with source")
            if set(edit) - {"source", "summary", "signature", "name", "comment", "declarations"}:
                raise ValueError("Unknown AI edit field")
            result = self.write(address, expected_revision=context["revision"], **edit)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--project", required=True, help="Project directory; contains rea-project.gpr")
    parser.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"))
    parser.add_argument("--address", required=True, help="Original Ghidra function entry address")
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("read")
    write = commands.add_parser("write")
    write.add_argument("--edit", required=True, help="JSON file containing source, expected_revision and optional metadata")
    iterate = commands.add_parser("iterate")
    iterate.add_argument("--command", required=True, help="AI program and arguments, parsed with shlex; no shell")
    iterate.add_argument("--iterations", type=int, default=1)
    iterate.add_argument("--instruction", default="Improve the reconstructed C using the available evidence")
    args = parser.parse_args()
    workspace = Workspace(args.binary, args.project, args.ghidra)
    if args.operation == "read":
        result = workspace.read(args.address)
    elif args.operation == "write":
        result = workspace.write(args.address, **json.loads(Path(args.edit).read_text(encoding="utf-8")))
    else:
        result = workspace.iterate(args.address, shlex.split(args.command), args.iterations, args.instruction)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
