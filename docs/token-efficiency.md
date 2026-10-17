# Token-efficient reconstruction

REA's persistent reconstruction adapter now sends current evidence instead of
resending every prior source revision. Exact-text edits reduce model output, and
a completion journal avoids invoking the model again for unchanged completed
work. Full history remains available explicitly. These changes apply to the
Python reconstruction workflow and Java reconstruction API; the existing general
MCP analysis tool catalog is unchanged.

## Measurement

A real Ghidra 12.1.4 run imported a source-built ELF with 256 functions. The task
changed one return expression in each of four selected functions, each with 12
prior revisions and a 40-comment-line reconstructed body. A deterministic adapter
returned exact replacements. The final saved sources were checked against the
expected complete replacements, while full and compact contexts were checked to
contain the same current source and live decompiled evidence.

| Four-function task                      | Full-history contract | Compact context + exact edits |
| --------------------------------------- | --------------------: | ----------------------------: |
| Estimated input tokens                  |                65,756 |                         3,654 |
| Estimated output tokens                 |                 2,480 |                            84 |
| Total                                   |                68,236 |                         3,738 |
| AI adapter calls on an unchanged repeat | No completion journal |                             0 |

This is **94.52% fewer estimated task payload tokens** in a history-heavy fixture.
Counts use `tiktoken 0.14.0`, `cl100k_base`, and compact JSON. The baseline is the
full-history wire contract from `bbda1804ea0b5aeebfb8c5a23cb1ceb51f21452d`, measured
through the retained full view on the candidate engine. It is not a timing run of
the old implementation. Both task variants include instruction/context input and
edit output. There are no tool schemas, catalog discovery, retries, or continuation
messages in this direct subprocess protocol. Provider system prompts, reasoning,
chat envelopes and actual billed usage are unmeasured. Baseline Python used
whitespace in JSON, so compact serialization here is conservative.

Cold import took 12.474 seconds; candidate first-pass reconstruction took 26.174
seconds; fresh-process resume validation took 4.706 seconds. These are one-run
observations, not speedup claims. CPU time and peak process-family memory were
not measured. No resource guards stopped the successful run; temporary projects
were removed. Tokenizer initialization was slow in the sandbox before the run;
that setup is outside the reported task timings. The initial extended migration
test failed because Ghidra isolates Java script directories; its harness now
places the test and store class in the same temporary script bundle.

The fixture deliberately exposes history amplification. It does not establish
model reconstruction quality, equivalent output for a real model, whole-project
recompilation, or a universal percentage saving on large applications. Functions
without history will save less. Current live source and reconstructed source are
both included when different. Large functions can still exceed the configured
context budget and require explicit analyst scoping.

Raw measurements: [token-efficiency-results.json](token-efficiency-results.json).
The source-built fixture digest and binary digest are recorded there; binary
hashes can change with compiler version and temporary debug paths.

## Reproduce

Follow [installation/build instructions](persistent-ghidra.md), export
`GHIDRA_INSTALL_DIR` and `JAVA_HOME`, and make `gcc` and `nm` available. Python
runtime features require only the standard library; the optional benchmark uses
a tokenizer dependency:

```sh
python3 -m venv .benchmark-venv
.benchmark-venv/bin/pip install tiktoken==0.14.0
.benchmark-venv/bin/python tests/conformance/ghidra/token_benchmark.py
python3 tests/conformance/ghidra/workspace_unit_test.py
python3 tests/conformance/ghidra/workspace_test.py
```

The implementation builds with the TypeScript 6 fallback and all Java bridge
sources compile against Ghidra 12.1.4/JDK 21. The focused TypeScript suite passed
133 tests (3 platform-dependent skips); six orchestration unit tests passed.
Module-boundary, test-discovery, formatting and package source-inclusion checks
also passed.

The real provider regression checks persistence, rollback, two AI iterations,
compact context, paged history, repeated-read decompiler reuse, completion resume,
stale evidence rejection, direct-callee invalidation, function pagination, and
legacy revision migration/rollback. The unit tests separately cover adapter
validation, exact replacement ambiguity, context-budget refusal, and interruption
resume. Build verification also includes the existing focused TypeScript suite.

See [API and resume instructions](persistent-ghidra.md#resuming-large-projects)
for cache ownership, invalidation, capacity and coverage limits. The existing
Unix-socket lifecycle remains untested in this sandbox; the real file adapter
exercises the shared Java reconstruction implementation across JVM restarts.
