{ lib, buildNpmPackage, importNpmLock, nodejs_24, autoPatchelfHook,
  makeWrapper, stdenv, procps, runCommand, fetchurl, src }:
let
  package = lib.importJSON "${src}/package.json";
  nodejs = nodejs_24;
  fridaVersion = "17.23.2";
  fridaPlatform = {
    x86_64-linux = { arch = "x64"; sha256 = "9fa8f668ce91eb03713e8564de4f8fbde232233ee91d729c16773fde11dbae95"; };
    aarch64-linux = { arch = "arm64"; sha256 = "11083f016a429e87506cd68166bd1445da8febd506a24edf3f6c4a9a7a3ea9fe"; };
  }.${stdenv.hostPlatform.system};
  fridaNative = assert package.optionalDependencies.frida == fridaVersion; fetchurl {
    url = "https://github.com/frida/frida/releases/download/${fridaVersion}/frida-v${fridaVersion}-napi-v8-linux-${fridaPlatform.arch}.tar.gz";
    inherit (fridaPlatform) sha256;
  };
  rea = buildNpmPackage {
    pname = "rea-agents";
    inherit (package) version;
    inherit src nodejs;

    # Each dependency uses its existing package-lock integrity hash.
    npmDeps = importNpmLock { npmRoot = "${src}"; };
    npmConfigHook = importNpmLock.npmConfigHook;
    npmFlags = [ "--ignore-scripts" ];
    npmPackFlags = [ "--ignore-scripts" ];
    # Keep the imported dependency graph intact: pruning a lock rewritten to
    # store URLs can make npm attempt to resolve registry metadata offline.
    dontNpmPrune = true;
    env.HUSKY = "0";

    nativeBuildInputs = [ autoPatchelfHook makeWrapper ];
    buildInputs = [ stdenv.cc.cc.lib ];

    preBuild = ''
      # Same prebuild selected by Frida's install hook, fetched with a fixed
      # hash instead of allowing an install script to download during a build.
      tar -xzf ${fridaNative} -C node_modules/frida
      # npm installs both libc variants of some optional native packages.
      # This derivation uses glibc; musl variants are never selected at runtime.
      find node_modules -type d -name '*-linux-*-musl' -prune -exec rm -rf {} +
      autoPatchelf node_modules
    '';
    buildPhase = ''
      runHook preBuild
      # Same runtime/skill artifacts as upstream build:cached, using the
      # repository's supported JS compiler fallback instead of native TS7.
      node node_modules/typescript6/lib/tsc.js -p tsconfig.build.json
      node scripts/record-catalog-digests.mjs
      node scripts/bundle-runtime.mjs
      node scripts/generate-skill-metadata.mjs
      runHook postBuild
    '';

    postInstall = ''
      # Setup registers the JS dispatcher itself. Its interpreter must retain
      # the runtime PATH too, including when launched directly by an MCP client.
      mkdir -p "$out/libexec"
      makeWrapper ${nodejs}/bin/node "$out/libexec/rea-node" \
        --prefix PATH : ${lib.makeBinPath [ nodejs procps ]}
      dispatcher="$out/lib/node_modules/rea-agents/scripts/rea.mjs"
      sed -i "1c#!$out/libexec/rea-node" "$dispatcher"
      chmod +x "$dispatcher"
      rm -f "$out/bin/rea" "$out/bin/rea-agents"
      ln -s "$dispatcher" "$out/bin/rea"
      ln -s "$dispatcher" "$out/bin/rea-agents"
    '';

    passthru.tests.installed-cli = runCommand "rea-installed-cli" {
      nativeBuildInputs = [ rea ];
    } ''
      export XDG_CONFIG_HOME="$TMPDIR/config"
      export XDG_CACHE_HOME="$TMPDIR/cache"
      rea --help > "$TMPDIR/help"
      rea-agents --version > "$TMPDIR/version"
      grep -q '${package.version}' "$TMPDIR/version"
      # Exercise the entry point that setup will register, with an empty PATH.
      PATH= ${rea}/lib/node_modules/rea-agents/scripts/rea.mjs --help > "$TMPDIR/direct-help"
      cmp "$TMPDIR/help" "$TMPDIR/direct-help"
      test -s ${rea}/lib/node_modules/rea-agents/skills/reverse-engineer-anything/SKILL.md
      test -s ${rea}/lib/node_modules/rea-agents/bridge/ghidra/ReaGhidraReconstructionStore.java
      ${nodejs}/bin/node --input-type=module -e '
        const frida = await import("${rea}/lib/node_modules/rea-agents/node_modules/frida/build/src/frida.js");
        if (typeof frida.getDeviceManager !== "function") throw new Error("Frida binding missing");
      '
      mkdir "$out"
      cp "$TMPDIR/version" "$out/version"
    '';

    meta = {
      description = "Reverse engineering CLI and MCP server with persistent Ghidra reconstruction";
      homepage = "https://github.com/Undercoverer/rea";
      license = lib.licenses.mit;
      mainProgram = "rea";
      platforms = [ "x86_64-linux" "aarch64-linux" ];
    };
  };
in rea
