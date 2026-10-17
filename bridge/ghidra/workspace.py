#!/usr/bin/env python3
"""Persistent REA Ghidra source API. Python 3.10+, standard library only."""
import argparse
from contextlib import closing
import fcntl
import sqlite3
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
        return self._request({"method": method, "params": params}, timeout)

    def request_many(self, requests, timeout=600):
        if not 1 <= len(requests) <= 256:
            raise ValueError("A batch requires 1..256 requests")
        return self._request({"requests": requests}, timeout)

    def _request(self, envelope, timeout=600):
        self.project.mkdir(parents=True, exist_ok=True, mode=0o700)
        scripts = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(prefix="rea-request-") as temporary:
            request = Path(temporary) / "request.json"
            response = Path(temporary) / "response.json"
            request.write_text(json.dumps({"binary_sha256": binary_digest(self.binary),
                                          **envelope}), encoding="utf-8")
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
            self.last_statistics = payload.get("statistics", {})
            return payload["result"]

    def read(self, address):
        return self.request("read_reconstruction", {"address": address})

    def write(self, address, source, expected_revision, **metadata):
        return self.request("write_reconstruction", dict(metadata, address=address,
                            source=source, expected_revision=expected_revision))

    def context(self, address):
        return self.request("read_reconstruction", {"address": address, "view": "context"})

    def history(self, address, offset=0, limit=20, include_source=False):
        return self.request("read_reconstruction_history", dict(address=address, offset=offset,
                            limit=limit, include_source=include_source))

    def functions(self, after=None, limit=100):
        return self.request("list_reconstructions", dict(limit=limit, **({"after": after} if after else {})))

    def _improve(self, context, command, instruction, max_context_bytes):
        payload = json.dumps({"instruction": instruction, "function": context},
                             separators=(",", ":"), ensure_ascii=False)
        if len(payload.encode("utf-8")) > max_context_bytes:
            raise ValueError("Context exceeds max_context_bytes; no evidence was truncated or sent")
        completed = subprocess.run(command, input=payload, capture_output=True, text=True,
                                   check=True, timeout=600)
        edit = json.loads(completed.stdout)
        if not isinstance(edit, dict) or set(edit) - {"source", "edits", "unchanged", "summary", "signature", "name", "comment", "declarations"}:
            raise ValueError("Unknown AI edit field or non-object response")
        if sum(key in edit for key in ("source", "edits", "unchanged")) != 1:
            raise ValueError("Return exactly one of source, edits, or unchanged")
        if "unchanged" in edit:
            if set(edit) != {"unchanged"} or edit["unchanged"] is not True:
                raise ValueError("unchanged must be true and have no other fields")
            return {k: context[k] for k in ("address", "revision", "context_hash", "source_sha256")}, False
        if "edits" in edit:
            edit["source"] = apply_edits(context["source"], edit.pop("edits"))
        semantic = bool(set(edit) & {"signature", "name", "comment", "declarations"})
        result = self.write(context["address"], expected_revision=context["revision"],
                            expected_context_hash=context["context_hash"], view="receipt", **edit)
        return result, semantic

    def iterate(self, address, command, iterations=1,
                instruction="Improve the reconstructed C using the available evidence", max_context_bytes=65536):
        """Compact evidence in; exact edits, complete source, or unchanged out."""
        if iterations < 1:
            raise ValueError("iterations must be positive")
        for _ in range(iterations):
            result, _ = self._improve(self.context(address), command, instruction, max_context_bytes)
        return result

    def reconstruct_many(self, addresses, command, task_key, instruction="Improve the reconstructed C using the available evidence",
                         batch_size=32, max_context_bytes=65536, force=False):
        """Checkpoint each successful function; revalidate evidence before skipping AI."""
        if not task_key or not 1 <= batch_size <= 256:
            raise ValueError("task_key and batch_size in 1..256 are required")
        task = hashlib.sha256(json.dumps([1, task_key, command, instruction], separators=(",", ":")).encode()).hexdigest()
        self.project.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not isinstance(addresses, (list, tuple)) or not all(isinstance(a, str) and a for a in addresses):
            raise ValueError("addresses must be an array of nonempty address strings")
        addresses = list(dict.fromkeys(addresses))
        results, seen = [], set()
        with open(self.project / ".rea-work.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with closing(sqlite3.connect(self.project / "rea-work.sqlite3")) as db:
                db.execute("CREATE TABLE IF NOT EXISTS completed (task TEXT, address TEXT, context TEXT, PRIMARY KEY(task,address))")
                for start in range(0, len(addresses), batch_size):
                    replies = self.request_many([{"method": "read_reconstruction", "params": {"address": address, "view": "context"}}
                                                 for address in addresses[start:start + batch_size]])
                    dirty, all_dirty = set(), False
                    for reply in replies:
                        if not reply["ok"]:
                            raise RuntimeError(reply["error"])
                        context = reply["result"]
                        address = context["address"]
                        if address in seen:
                            continue
                        seen.add(address)
                        if all_dirty or any(c["address"] in dirty for c in context["callees"]):
                            context = self.context(address)
                        previous = db.execute("SELECT context FROM completed WHERE task=? AND address=?", (task, address)).fetchone()
                        if not force and previous and previous[0] == context["context_hash"]:
                            results.append({"address": address, "revision": context["revision"], "status": "skipped"})
                            continue
                        result, semantic = self._improve(context, command, instruction, max_context_bytes)
                        db.execute("INSERT OR REPLACE INTO completed VALUES (?,?,?)", (task, address, result["context_hash"]))
                        db.commit()
                        results.append(dict(result, status="completed"))
                        if result["revision"] != context["revision"]:
                            dirty.add(address)
                        all_dirty |= semantic
        return results


def apply_edits(source, edits):
    """Sequential exact replacements; reject ambiguous or missing anchors."""
    if not isinstance(edits, list) or not edits:
        raise ValueError("edits must be a nonempty array")
    for edit in edits:
        if not isinstance(edit, dict) or set(edit) != {"old", "new"} or not all(isinstance(v, str) for v in edit.values()):
            raise ValueError("Each edit requires old and new strings")
        old = edit["old"]
        if not old or source.find(old) < 0 or source.find(old) != source.rfind(old):
            raise ValueError("Edit anchor must occur exactly once")
        source = source.replace(old, edit["new"], 1)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--project", required=True, help="Project directory; contains rea-project.gpr")
    parser.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"))
    parser.add_argument("--address", help="Original Ghidra function entry address")
    commands = parser.add_subparsers(dest="operation", required=True)
    read = commands.add_parser("read")
    read.add_argument("--view", choices=["context", "full"], default="context")
    history = commands.add_parser("history")
    history.add_argument("--offset", type=int, default=0)
    history.add_argument("--limit", type=int, default=20)
    history.add_argument("--include-source", action="store_true")
    listing = commands.add_parser("list")
    listing.add_argument("--after")
    listing.add_argument("--limit", type=int, default=100)
    run = commands.add_parser("run")
    run.add_argument("--addresses", required=True, help="JSON array of function addresses")
    run.add_argument("--task-key", required=True)
    run.add_argument("--command", required=True)
    run.add_argument("--instruction", default="Improve the reconstructed C using the available evidence")
    run.add_argument("--batch-size", type=int, default=32)
    run.add_argument("--max-context-bytes", type=int, default=65536)
    run.add_argument("--force", action="store_true")
    write = commands.add_parser("write")
    write.add_argument("--edit", required=True, help="JSON file containing source, expected_revision and optional metadata")
    iterate = commands.add_parser("iterate")
    iterate.add_argument("--command", required=True, help="AI program and arguments, parsed with shlex; no shell")
    iterate.add_argument("--iterations", type=int, default=1)
    iterate.add_argument("--instruction", default="Improve the reconstructed C using the available evidence")
    iterate.add_argument("--max-context-bytes", type=int, default=65536)
    args = parser.parse_args()
    if args.operation not in ("list", "run") and not args.address:
        parser.error("--address is required for this operation")
    workspace = Workspace(args.binary, args.project, args.ghidra)
    if args.operation == "read":
        result = workspace.read(args.address) if args.view == "full" else workspace.context(args.address)
    elif args.operation == "history":
        result = workspace.history(args.address, args.offset, args.limit, args.include_source)
    elif args.operation == "list":
        result = workspace.functions(args.after, args.limit)
    elif args.operation == "run":
        result = workspace.reconstruct_many(json.loads(Path(args.addresses).read_text()), shlex.split(args.command),
                    args.task_key, args.instruction, args.batch_size, args.max_context_bytes, args.force)
    elif args.operation == "write":
        result = workspace.write(args.address, **json.loads(Path(args.edit).read_text(encoding="utf-8")))
    else:
        result = workspace.iterate(args.address, shlex.split(args.command), args.iterations, args.instruction, args.max_context_bytes)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
