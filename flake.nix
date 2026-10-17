{
  description = "REA fork with the upstream CLI and setup workflow";

  # Pin the package set even before a consumer generates flake.lock.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/55bfb4d7437bd4e09ab7cba58a43bd68eb310044";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          rea = pkgs.callPackage ./nix/package.nix { src = self; };
        in {
          inherit rea;
          default = rea;
        });
      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.rea}/bin/rea";
          meta.description = "REA command line and MCP server";
        };
        rea = self.apps.${system}.default;
      });
      checks = forAllSystems (system: {
        package = self.packages.${system}.rea;
        installed-cli = self.packages.${system}.rea.tests.installed-cli;
      });
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.mkShell {
          packages = [ self.packages.${system}.rea pkgs.nodejs_24 pkgs.python3 pkgs.procps ];
        }; });
    };
}
