"""Real Ghidra payload benchmark; optional pip install tiktoken. No model claims."""
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
import hashlib
import tiktoken

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("workspace", ROOT / "bridge/ghidra/workspace.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
encoding = tiktoken.get_encoding("cl100k_base")

def tokens(value):
    return len(encoding.encode(json.dumps(value, separators=(",", ":"), ensure_ascii=False)))

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    c = root / "fixture.c"
    c.write_text("\n".join(f"int fn{i}(int x) {{ return x + {i}; }}" for i in range(256)) + "\nint main(void) { return fn255(1); }\n")
    binary = root / "fixture"
    subprocess.run(["gcc", "-O0", "-g", "-fno-inline", "-no-pie", str(c), "-o", str(binary)], check=True)
    symbols = {line.split()[-1]: line.split()[0] for line in subprocess.check_output(["nm", str(binary)], text=True).splitlines() if len(line.split()) == 3}
    addresses = [symbols[f"fn{i}"] for i in [0, 64, 128, 255]]
    w = m.Workspace(binary, root / "project")
    started = time.monotonic()
    w.context(addresses[0])
    cold = time.monotonic() - started
    requests = []
    for address in addresses:
        for revision in range(12):
            source = "int recovered(int x) {\n" + "\n".join(f"  /* recovered invariant {j}: preserve input range and arithmetic */" for j in range(40)) + f"\n  return x + {revision};\n}}"
            requests.append({"method": "write_reconstruction", "params": dict(address=address, source=source, expected_revision=revision, summary=f"revision {revision + 1}", view="receipt")})
    assert all(r["ok"] for r in w.request_many(requests))
    def read(view):
        return [r["result"] for r in w.request_many([{"method": "read_reconstruction", "params": dict(address=a, view=view)} for a in addresses])]
    full = read("full")
    context = read("context")
    instruction = "Change return x + 11 to return x + 12, preserving all other source."
    baseline_input = sum(tokens(dict(instruction=instruction, function=f)) for f in full)
    compact_input = sum(tokens(dict(instruction=instruction, function=f)) for f in context)
    expected = [f["source"].replace("return x + 11", "return x + 12") for f in full]
    assert all(a["source"] == b["source"] and a["decompiled_source"] == b["decompiled_source"] for a, b in zip(full, context))
    full_output = sum(tokens({"source": source}) for source in expected)
    edit = {"edits": [{"old": "return x + 11", "new": "return x + 12"}]}
    edit_output = tokens(edit) * len(addresses)
    for f, source in zip(context, expected):
        assert m.apply_edits(f["source"], edit["edits"]) == source
    agent = root / "agent.py"
    agent.write_text("import json,sys\njson.load(sys.stdin)\nprint(" + repr(json.dumps(edit)) + ")\n")
    started = time.monotonic()
    first = w.reconstruct_many(addresses, [sys.executable, str(agent)], "benchmark-v1", instruction)
    first_seconds = time.monotonic() - started
    started = time.monotonic()
    resumed = w.reconstruct_many(addresses, [sys.executable, str(agent)], "benchmark-v1", instruction)
    resume_seconds = time.monotonic() - started
    assert all(r["status"] == "skipped" for r in resumed)
    final = read("context")
    assert [f["source"] for f in final] == expected
    report = dict(baseline="bbda1804ea0b5aeebfb8c5a23cb1ceb51f21452d full-history wire contract",
        fixture_functions=256, selected_functions=4, prior_revisions_per_function=12,
        fixture_source_sha256=hashlib.sha256(c.read_bytes()).hexdigest(), binary_sha256=m.binary_digest(binary),
        ghidra=context[0]["ghidra_version"], host=platform.platform(), tokenizer="tiktoken cl100k_base",
        scope="Deterministic source-edit task; tokenizer estimates, no actual model usage or quality evaluation. Full view retains the baseline wire contract; both views measured on candidate engine.",
        baseline_input_tokens=baseline_input, compact_input_tokens=compact_input,
        baseline_output_tokens=full_output, exact_edit_output_tokens=edit_output,
        total_reduction_percent=round(100 * (1-(compact_input+edit_output)/(baseline_input+full_output)), 2),
        first_run_ai_calls=len(first), resumed_ai_calls=0, final_sources_match=True,
        cold_import_seconds=round(cold,3), candidate_first_run_seconds=round(first_seconds,3), candidate_resume_seconds=round(resume_seconds,3),
        unmeasured=["actual model reasoning/usage", "production large-project reconstruction quality", "peak process-family memory", "CPU time", "baseline runtime"],
        resource_stops=0, cleanup="temporary project removed on successful exit")
    print(json.dumps(report, indent=2))
