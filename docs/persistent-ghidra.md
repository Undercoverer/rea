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

The response includes the live Ghidra name, signature, comment, decompiled C,
reconstructed `source` (null before the first edit), revision number and full
revision history. `metadata_changed_since_revision` marks name/signature drift
since the last reconstruction. Live decompiled C and saved reconstructed C are
returned separately: the original machine instructions remain authoritative
for binary analysis. Saved text is never silently replaced by decompiler output.

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
source v1`, keyed by original address. To restore an old version, read history
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
shell. Each iteration reads fresh metadata, decompiled C, prior source and full
history. Its stdin is JSON `{ "instruction": "...", "function": <read result> }`.
It must return one JSON edit object on stdout, with `source` and optional
`summary`, `signature`, `name`, `comment`, `declarations`. The adapter supplies the
revision number from the read. Command failure, invalid output or a revision
conflict stops iteration. Prior successful iterations remain saved. AI provider
credentials and provider-specific SDKs are owned by the adapter.

```sh
python3 bridge/ghidra/workspace.py \
  --binary /absolute/program --project /absolute/project --address 00401106 \
  iterate --command 'python3 /absolute/ai_adapter.py' --iterations 3
```

The existing authenticated Java bridge also accepts `read_reconstruction`
(`address`) and `write_reconstruction` (the same edit fields plus `address`).
`GhidraClient.callTool` exposes both operations to TypeScript integrations.
The existing MCP tool catalog remains unchanged; use the Python API/CLI for
reconstruction, or the client API inside an REA integration. Never connect a
second client to an REA-owned socket or reuse a consumed session credential.

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
