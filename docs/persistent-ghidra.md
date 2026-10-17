# Persistent Ghidra projects and reconstructed source

This fork adds persistent POSIX Ghidra projects, a Java reconstruction API,
a standard-library Python API/CLI, and an external AI iteration adapter. The
existing TypeScript CLI/MCP workflows retain their default behavior.

## Clone, install, build

Install Node.js 24.18.0, npm 11.16.0, Python 3.10+, a JDK 21, and the official
Ghidra 12.1.4 distribution. Ghidra and Java are supplied by the user. Linux also
requires procps-compatible `ps`; real regression tests require GCC and `nm`.
No Gradle build is required: Ghidra compiles Java scripts when first used.

```sh
git clone https://github.com/Undercoverer/rea.git
cd rea
npm ci
npm run build:cached
export JAVA_HOME=/absolute/path/to/jdk-21
export PATH="$JAVA_HOME/bin:$PATH"
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra_12.1.4_PUBLIC
export REA_ANALYSIS_PROVIDER=ghidra
export REA_GHIDRA_PROJECT_DIR="$HOME/.local/share/rea/ghidra-projects"
node scripts/rea.mjs --help
```

Use `node scripts/rea.mjs setup` to review local MCP registration changes, or
`npm link` to install the checkout's `rea` command. Keep these variables in the
MCP server's environment when using an agent. See [installation](installation.md)
for provider setup. Node/npm/Java/Ghidra are never installed by this feature.

If the sandbox lacks `/proc/self/exe`, the native TypeScript 7 compiler cannot
run. The checked-in TypeScript 6 dependency provides this equivalent build:

```sh
node node_modules/typescript6/lib/tsc.js -p tsconfig.build.json
node scripts/record-catalog-digests.mjs
node scripts/bundle-runtime.mjs
node scripts/generate-skill-metadata.mjs
```

## Project ownership and reopen

`REA_GHIDRA_PROJECT_DIR` must be absolute. Each project lives in
`$REA_GHIDRA_PROJECT_DIR/<key>/rea-project.gpr` and its adjacent `.rep` directory.
The key is SHA-256 of UTF-8 `JSON.stringify([binarySha256, ghidraVersion,
analysisProfileDigest])`, without spaces or a trailing newline. Use the same
binary bytes, Ghidra release, analysis profile and storage directory to reopen
it through REA. A changed identity gets a separate project.

Persistent imports omit `-readOnly` and `-deleteProject`. Reopens use
`-process '*' -noanalysis`, without replaying seed, loader or repair scripts.
The bridge checkpoints the Program before acknowledging successful operations.
This retains symbols, comments, data types, structures, function signatures,
analysis state and source revisions. Runtime logs, credentials, snapshots and
sockets remain temporary and are cleaned by the existing lifecycle owner.

The initial import is checkpointed before the socket starts. Since headless
normally saves imports after post-scripts, the bridge marks its already-saved
initial Program temporary when it exits to prevent a duplicate headless import.
Existing Programs are saved normally. A disk save failure is an operation
failure, not a successful durability acknowledgement. Ghidra's exclusive project
lock rejects concurrent openers. Never remove an active project lock.

Close an REA session before using the Python CLI or opening the same project
in Ghidra's GUI. Back up both `.gpr` and `.rep` while the project is closed.
No automatic retention/deletion policy is applied to persistent projects.
Unsetting the variable restores ephemeral REA sessions; it does not delete
saved work. Windows persistence is rejected explicitly in the REA launcher.

## Edit recovered C

The Python API can create its own persistent project directory or open a
closed project from REA's storage. Always supply the original binary so the
saved executable SHA-256 can be checked. Address identity includes the address
space (`ram:00401106`, for example); use a local function's original entry.

```sh
python3 bridge/ghidra/workspace.py \
  --binary /absolute/path/to/program \
  --project /absolute/path/to/project-directory \
  --address 00401106 read
```

The CLI defaults to compact context: current source, live metadata, direct-callee
summaries and a freshness hash. Before the first reconstruction, `source` is the
live decompiler output. Distinct live decompiler output is included alongside
saved source; identical text is sent only once. No history is included.
Use `read --view full` for the original full response (including all history and
`metadata_changed_since_revision`). Python `workspace.read(address)` keeps that
full response for compatibility; `workspace.context(address)` selects compact
context. Saved text is never silently replaced by decompiler output.

Create `edit.json`:

```json
{
  "expected_revision": 0,
  "source": "long recovered(long value) { return value + 3; }",
  "signature": "long recovered(long value)",
  "name": "recovered",
  "comment": "Adds the recovered constant.",
  "declarations": "struct Pair { int left; int right; };",
  "summary": "Recovered the return and parameter types."
}
```

```sh
python3 bridge/ghidra/workspace.py \
  --binary /absolute/path/to/program \
  --project /absolute/path/to/project-directory \
  --address 00401106 write --edit edit.json
```

`source` and `expected_revision` are required. Other fields are optional.
Each edit stores a full source revision, timestamp, summary, requested metadata
and post-edit function identity in Program Options under `REA reconstructed
source v2`, keyed by original address and revision. A first successful write
transactionally migrates legacy v1 history; reads remain compatible with v1.
Each revision stores source once, and latest reads avoid loading old v2 revisions. To restore an old version, read history
and submit that source as a new revision using the current revision number.

Explicit `signature` edits use Ghidra's signature parser and command, including
parameter names/types and return type. `declarations` uses Ghidra's C parser for
structures, enums and typedefs. `name` renames the actual Function; `comment`
sets its function comment. These supported semantic edits share one transaction
with the source revision. Invalid metadata rolls everything back. Stale source
revision numbers fail without a write. Ghidra callers/references observe the
updated symbols and types; its decompiler caches are flushed after bridge edits.
Edits made externally in Ghidra are read back as live metadata on the next read.

Arbitrary C body edits are stored as reconstruction text. Local variable edits,
control-flow changes, inferred semantics and arbitrary C syntax are not inferred
or applied to the binary. Supply supported metadata fields explicitly; the API
does not guess semantic changes from a text diff. Previously saved source is
retained when Ghidra metadata changes, so an agent can reconcile it explicitly.

## APIs and iterative reconstruction

```python
# Import bridge/ghidra/workspace.py from this checkout.
from workspace import Workspace
workspace = Workspace(binary="/absolute/program", project="/absolute/project")
previous = workspace.read("00401106")
saved = workspace.write("00401106", source="int f(void) { return 3; }",
                        expected_revision=previous["revision"], summary="Pass 2")
result = workspace.iterate("00401106", ["python3", "/absolute/ai_adapter.py"],
                           iterations=3, instruction="Refine names and types")
```

The AI command is explicitly selected by the caller and runs locally without a
shell. Each iteration reads compact context and returns a compact receipt. Its
stdin is JSON `{ "instruction": "...", "function": <compact context> }`. It returns
exactly one of `source` (complete replacement), `edits` (exact replacements), or
`{"unchanged": true}`. Source/edits may include `summary`, `signature`, `name`,
`comment`, and `declarations`. Unchanged accepts no other fields.

```json
{
  "edits": [{ "old": "return value + 3;", "new": "return value + 4;" }],
  "summary": "Correct constant"
}
```

Each `old` anchor must occur exactly once; replacements apply sequentially and
never use fuzzy matching. The adapter supplies both revision and context hash,
so changed observed evidence rejects a stale edit. Failures stop iteration;
prior successful iterations remain saved. The default 65,536-byte UTF-8 context
budget rejects an oversized model request before invoking the command; it does
not truncate evidence. Configure `--max-context-bytes` explicitly. This is a byte
budget, not a provider token limit. Credentials and SDKs belong to the adapter.

```sh
python3 bridge/ghidra/workspace.py \
  --binary /absolute/program --project /absolute/project --address 00401106 \
  iterate --command 'python3 /absolute/ai_adapter.py' --iterations 3
```

The existing authenticated Java bridge also accepts `read_reconstruction`
(`address`) and `write_reconstruction` (the same edit fields plus `address`).
`GhidraClient.callTool` exposes these operations to TypeScript integrations.
Reads accept `view: "full" | "context"`; writes additionally accept `"receipt"`
and optional `expected_context_hash`. `read_reconstruction_history` accepts
`address`, zero-based `offset`, `limit` (1–1000), and `include_source` (false by
default). It returns `revisions`, `total`, and `next_offset`. `list_reconstructions`
accepts `after` (exclusive address cursor) and `limit` (1–1000), returning compact
`functions` and `next_after`. History and listing do not decompile functions.
The existing MCP tool catalog remains unchanged; use the Python API/CLI for
reconstruction, or the client API inside an REA integration. Never connect a
second client to an REA-owned socket or reuse a consumed session credential.

## Resuming large projects

List functions in bounded pages, then select the addresses relevant to the task:

```sh
python3 bridge/ghidra/workspace.py --binary /absolute/program --project /absolute/project list --limit 100
python3 bridge/ghidra/workspace.py --binary /absolute/program --project /absolute/project \
  run --addresses addresses.json --task-key recovery-v1 \
  --command 'python3 /absolute/ai_adapter.py' --batch-size 32
```

`addresses.json` is a JSON array of original entry addresses. Repeat the same
command after interruption. Each successful function is checkpointed immediately
in `rea-work.sqlite3` inside the project. Completed entries with the same current
context are skipped without invoking the AI. `task-key`, command arguments and
instruction identify the task; change the key when the model configuration,
external knowledge or intended quality threshold changes. `--force` revisits all
selected entries. Completion means a successful adapter pass, not proven code
correctness or convergence. Cyclic callers may require additional passes.

Python equivalents are `functions(after=None, limit=100)`,
`history(address, offset=0, limit=20, include_source=False)`, and
`reconstruct_many(addresses, command, task_key, instruction=..., batch_size=32,
max_context_bytes=65536, force=False)`. `request_many` accepts 1–256
`{"method": ..., "params": ...}` entries and preserves per-item success/error
results. A failed item does not roll back earlier saved items. The file adapter
uses one JVM and decompiler per batch. Run owns an exclusive POSIX journal lock;
Ghidra separately protects the project. Close other owners before using it.

Resume validation reads fresh Ghidra evidence, so it still incurs analysis I/O.
The hash covers binary identity, engine version, language/compiler spec, current
source/revision, live decompiled text, function metadata, and observed direct
callee signatures/comments/reconstruction summaries and revisions. It does not
prove that indirect calls, runtime libraries, external knowledge or every type
fact has been resolved. Use a new task key or force when those inputs change.
Within a batch, edits invalidate pending callers; metadata edits conservatively
refresh all remaining contexts. The journal stores hashes, not source copies.

Decompiler reuse belongs to one reconstruction service and Program. Its key is
function entry address; any Program modification clears the cache. Only complete
successful results are cached, with a 16 MiB UTF-16 text ceiling and LRU eviction.
The cache is discarded on close/Program replacement and never truncates source.
This cap excludes Ghidra's own native/Java memory, JSON buffers, and batch replies;
reduce batch size for large functions. No persistent raw decompiler cache is used.
Older revisions remain explicitly available through paged history.

See [the measured token benchmark](token-efficiency.md) for scope and results.

## Binary patching investigation

No machine-code patch API is enabled. All responses state
`machine_code_modified: false`; reconstructed C does not change executable bytes.
Actual patching needs a separate operation, artifact and verification contract:

- Bind to an exact input digest and original instruction bytes.
- Map initialized file-backed memory to a unique file offset; reject ambiguous
  mappings, relocations, overlays and unmapped destinations.
- Assemble for the selected ISA, mode, endianness and ABI. A C body may require
  compilation, placement, branch-range handling, relocations and unwind updates.
- Write to a new output artifact, check expected original bytes, recalculate
  affected format metadata and report signature invalidation where applicable.
- Re-import the patched output under a new digest and verify instructions,
  references and executable behavior with caller-supplied tests.

Ghidra memory writes alone are insufficient: they edit database memory and do not
provide a correct executable exporter. For this reason patching is deliberately
separate from reconstruction and has not been advertised as implemented.

## Validation

```sh
npm run test:focused -- tests/boundary/providers/ghidra/ghidraLauncher.test.ts
npm run test:local -- src/ghidra/GhidraSessionValues.test.ts
npm run test:focused -- tests/boundary/mcp/ghidraEvidenceMcp.test.ts
python3 tests/conformance/ghidra/workspace_test.py
npm run verify:test-discovery
```

The real Ghidra regression compiles a small ELF, edits source/types/signature,
reopens the database in separate JVMs, observes changed caller pseudocode,
checks rollback and stale revision refusal, runs two adapter iterations and
rejects a different binary digest. The adapter fixture is deterministic; no
external AI model quality is asserted.

Execution in the task sandbox used Ghidra 12.1.4, Temurin JDK 21.0.12.1, Python
3.12.14 and the TypeScript 6 build fallback. The downloaded Ghidra launch wrapper
required a sandbox-only replacement of Bash process substitution because
`/dev/fd` is unavailable; no installed user Ghidra files are changed by this fork.
All Java bridge sources compiled against the real distribution. The real
workspace regression passed; the live REA Unix socket lifecycle could not run
because this sandbox rejects Unix sockets. That lifecycle remains covered by
the existing boundary tests, not by a claimed real socket run.
