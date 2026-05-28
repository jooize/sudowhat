{
  description = "sudowhat - sudo approval plugin for macOS that shows the exact command in the Touch ID prompt";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }: let
    systems = [ "aarch64-darwin" "x86_64-darwin" ];
    forAllSystems = nixpkgs.lib.genAttrs systems;
    pkgsFor = system: nixpkgs.legacyPackages.${system};
  in {
    packages = forAllSystems (system: {
      default = (pkgsFor system).callPackage ./nix/package.nix { };
    });

    overlays.default = final: _prev: {
      sudowhat = final.callPackage ./nix/package.nix { };
    };

    # Usage from a nix-darwin flake:
    #
    #   inputs.sudowhat.url = "github:jooize/sudowhat";
    #
    #   darwinConfigurations.<host> = nix-darwin.lib.darwinSystem {
    #     modules = [
    #       inputs.sudowhat.darwinModules.default
    #       { services.sudowhat.enable = true; }
    #     ];
    #   };
    #
    # To audit before depending, pin to a local clone or a reviewed sha:
    #   inputs.sudowhat.url = "git+file:///path/to/clone";
    #   inputs.sudowhat.url = "github:jooize/sudowhat/<sha>";
    darwinModules.default = import ./nix/module.nix { inherit self; };

    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
    in {
      default = pkgs.mkShell {
        nativeBuildInputs = [ pkgs.darwin.sigtool ];
        buildInputs = [
          pkgs.apple-sdk_15
          (pkgs.darwinMinVersionHook "15.0")
          pkgs.openpam
        ];
      };
    });
  };
}
