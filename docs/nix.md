# Nix installation

This flake installs this fork as `rea` and `rea-agents`, using the same npm
package files and command dispatcher as upstream's global install. It builds
from this checkout and its package-lock.json. Linux x86-64 and AArch64 are
exposed; other systems are not currently packaged.

Enable Nix's `nix-command` and `flakes` experimental features, then install:

```sh
nix profile install github:Undercoverer/rea
rea setup
```

Review and approve the normal setup plan, then restart the selected clients.
Setup registers the installed fork directly, including its Node runtime. It does
not register an npm download of the upstream release. Shell commands such as
`rea doctor --json`, `rea decompile`, and `rea mcp` use their normal arguments.

To try it without a persistent installation:

```sh
nix run github:Undercoverer/rea -- --help
```

Install into a profile before running setup, so its store path remains a garbage
collection root. After a Nix upgrade, run `rea setup` again to refresh registered
store paths. Do not remove old profile generations until clients use the new
entry point. Replace guide commands of the form `npx rea-agents ...` or
`bunx rea-agents ...` with `rea ...`: package runners still download upstream.
The upstream curl installer also installs upstream, not this fork.

Use Nix to update this installation, rather than `rea update` or `npm update`:

```sh
nix profile list
nix profile upgrade '<name shown by nix profile list>'
rea setup
```

## NixOS and Home Manager

Add this input to your configuration flake:

```nix
inputs.rea.url = "github:Undercoverer/rea";
```

Then include `inputs.rea.packages.${pkgs.stdenv.hostPlatform.system}.default` in
`environment.systemPackages` (NixOS) or `home.packages` (Home Manager). Pass
`inputs` through your usual module arguments. Run `rea setup` as your normal user
after rebuilding. Update the `rea` input in your configuration's flake.lock and
rebuild to upgrade.

## Providers and limits

Node and Linux process tools are part of the package's runtime closure. Ghidra,
Java, IDA, browsers, and other analysis providers remain separately configured,
as in the upstream installation guide. No provider or agent configuration is
changed by the Nix build. Follow [provider setup](installation.md) and the
[fork workspace guide](persistent-ghidra.md). On NixOS, use a Nix-compatible
Ghidra installation: an unpatched upstream native binary may not run. The fork
validates its supported Ghidra release; do not assume any nixpkgs Ghidra version
will pass that check.

The optional Frida Node binding uses the same Linux N-API prebuild selected by
its npm installer. The flake fetches that archive with a fixed SHA-256 and
patches native Node modules for the Nix runtime. The complete npm dependency
tree is retained to avoid offline pruning failures; this makes the package
larger than a pruned npm installation.

## Build and check

```sh
git clone https://github.com/Undercoverer/rea.git
cd rea
nix build
nix flake check --print-build-logs
./result/bin/rea --help
```

The nixpkgs input is pinned to a commit in flake.nix and its content hash is
recorded in flake.lock. Configuration consumers also lock their inputs.
The installed-CLI check exercises both executable names and the direct dispatcher
with an empty PATH, loads the Frida binding, and checks that packaged skills
and fork Java sources exist.
The Nix CI workflow runs these checks on Linux. Provider execution requires its
own configured integration tests; a CLI smoke test does not test Ghidra or Frida.
