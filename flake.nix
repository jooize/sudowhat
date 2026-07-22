{
  description = "sudowhat - sudo plugin that shows the exact command before you authenticate (Touch ID on macOS, terminal display on Linux)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }: let
    darwinSystems = [ "aarch64-darwin" "x86_64-darwin" ];
    linuxSystems = [ "x86_64-linux" "aarch64-linux" ];
    allSystems = darwinSystems ++ linuxSystems;
    forAllSystems = nixpkgs.lib.genAttrs allSystems;
    pkgsFor = system: nixpkgs.legacyPackages.${system};
    isDarwin = system: nixpkgs.lib.hasSuffix "darwin" system;

    # macOS builds the full three-bundle set (approval + pam + audit) via
    # nix/package.nix; Linux builds the display-only audit cdylib via
    # nix/package-linux.nix. The two derivations are deliberately separate — the
    # platforms share only the escape_core display core, not auth or trust (see
    # docs/design-linux-port.md).
    packageFor = system:
      if isDarwin system
      then (pkgsFor system).callPackage ./nix/package.nix { }
      else (pkgsFor system).callPackage ./nix/package-linux.nix { };
  in {
    packages = forAllSystems (system: {
      default = packageFor system;
    });

    overlays.default = final: _prev: {
      sudowhat =
        if final.stdenv.hostPlatform.isDarwin
        then final.callPackage ./nix/package.nix { }
        else final.callPackage ./nix/package-linux.nix { };
    };

    # Usage from a nix-darwin flake (macOS):
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

    # Usage from a NixOS flake (Linux — display-only, no biometric/PAM/signing):
    #
    #   nixosConfigurations.<host> = nixpkgs.lib.nixosSystem {
    #     modules = [
    #       inputs.sudowhat.nixosModules.default
    #       { services.sudowhat.enable = true; }
    #     ];
    #   };
    nixosModules.default = import ./nix/nixos-module.nix { inherit self; };

    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
    in {
      default =
        if isDarwin system
        then pkgs.mkShell {
          nativeBuildInputs = [ pkgs.darwin.sigtool ];
          buildInputs = [
            pkgs.apple-sdk_15
            (pkgs.darwinMinVersionHook "15.0")
            pkgs.openpam
          ];
        }
        else pkgs.mkShell {
          # Linux: the audit cdylib is pure Rust with no external deps, so cargo
          # + rustc are all that is needed.
          nativeBuildInputs = [ pkgs.cargo pkgs.rustc ];
        };
    });
  };
}
