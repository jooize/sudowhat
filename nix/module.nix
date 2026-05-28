{ self }:
{ config, pkgs, lib, ... }:

let
  cfg = config.services.sudowhat;
in {
  options.services.sudowhat = {
    enable = lib.mkEnableOption "sudowhat — sudo approval plugin for macOS";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression
        "sudowhat.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = ''
        The sudowhat package providing the .so bundles. The binaries embed
        their own store path at compile time for mutual signature
        verification; overriding this option means the /etc files
        managed by this module will reference the override's store path,
        not the default flake output.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # The store-path approach: binaries live in /nix/store, /etc files
    # reference them by full path. nix-darwin owns these three /etc files
    # declaratively, so darwin-rebuild rotates the whole set atomically
    # with the package — no drift between /etc/sudo.conf and the bundle
    # it points at.

    environment.etc."sudo.conf".text = ''
      # Managed by the sudowhat nix-darwin module. Disable the module to
      # restore stock /etc/sudo.conf (which on macOS does not exist by
      # default).
      Plugin sudowhat_approval_plugin ${cfg.package}/libexec/sudo/sudowhat_approval.so
    '';

    environment.etc."sudoers.d/sudowhat" = {
      mode = "0440";
      text = ''
        # Managed by the sudowhat nix-darwin module.
        # Disable sudo's auth cache so every invocation re-prompts via sudowhat.
        Defaults timestamp_timeout=0
      '';
    };

    environment.etc."pam.d/sudo_local".text = ''
      # Managed by the sudowhat nix-darwin module.
      #
      # sudowhat: integrity-check PAM module. The Touch ID prompt itself is
      # rendered post-PAM by the sudo approval plugin loaded from
      # /etc/sudo.conf.
      #
      # Apple's openpam fork does not parse the Linux-PAM bracket-list syntax
      # `[success=done default=die]`, so the same fail-closed semantics are
      # expressed with two simple-flag lines:
      #
      #   requisite  pam_sudowhat.so   - failure aborts sudo immediately
      #   sufficient pam_permit.so     - success terminates the auth chain so the
      #                                  parent /etc/pam.d/sudo never falls back
      #                                  to pam_smartcard / pam_opendirectory
      auth    requisite     ${cfg.package}/lib/pam/pam_sudowhat.so
      auth    sufficient    pam_permit.so
    '';
  };
}
