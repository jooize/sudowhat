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

    allowNonConsole = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Allow non-console callers — SSH sessions, unattended automation — to
        use sudo. When false (the default), only the local, physically present
        console (GUI) user may sudo; every non-console caller is denied without
        a prompt.

        When true, the `sudo_local` gate variant is installed: the local
        console user is still gated by the approval plugin's Touch ID prompt
        (no password), while a non-console caller is routed to sudo's native
        password / smartcard factor on their OWN terminal — never a biometric
        sheet on the console — and the approval plugin steps aside for them
        once sudo has authenticated them.

        This grants no new authority: sudoers still decides who may run what.
        It only changes whether an already-authorized non-console caller is
        permitted to authenticate at all. The classification is by the caller's
        security session (local GUI vs. remote/headless), not by uid, so an SSH
        session running as the same user as the console login is correctly
        treated as non-console.
      '';
    };

    timestampTimeout = lib.mkOption {
      type = lib.types.int;
      default = 0;
      description = ''
        Value for sudo's `Defaults timestamp_timeout` (minutes). 0 (the
        default) disables the credential cache, so every privileged command
        re-prompts. A positive value re-enables sudo's normal per-tty grace
        period; under the default per-tty scope a cached credential is only
        ever reused on the same terminal that already authenticated a real
        factor. The module never sets `timestamp_type=global` — the one mode
        that would let a console credential be reused by a same-uid remote
        session.
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

    # nix-darwin's environment.etc has no `mode` attribute (unlike NixOS).
    # The default symlink target in /nix/store is mode 0444 — not group/world
    # writable, which is sudo's only hard requirement for sudoers.d files.
    # The 0440 convention is convention, not enforcement.
    environment.etc."sudoers.d/sudowhat".text = ''
      # Managed by the sudowhat nix-darwin module.
      # timestamp_timeout is services.sudowhat.timestampTimeout (default 0 =
      # cache disabled, every invocation re-prompts). timestamp_type is left at
      # sudo's default (per-tty) and never set to global.
      Defaults timestamp_timeout=${toString cfg.timestampTimeout}
    '';

    # /etc/pam.d/sudo_local — two variants. Apple's openpam fork does not parse
    # the Linux-PAM bracket-list syntax `[success=done default=die]`, so the
    # fail-closed semantics are expressed with simple control flags.
    #
    # The module path is the FULL store path, never a bare name: pam_sudowhat.so
    # is not in openpam's /usr/lib/pam search dir, and a `sufficient` line whose
    # module fails to load does not succeed — so a bare name would silently
    # break the console short-circuit. The approval plugin checks for this exact
    # path (SUDOWHAT_PAM_PATH, baked from the same package) before stepping
    # aside, so the two always reference one store path.
    environment.etc."pam.d/sudo_local".text =
      if cfg.allowNonConsole then ''
        # Managed by the sudowhat nix-darwin module (allowNonConsole = true).
        #
        #   requisite  pam_sudowhat.so                - integrity; aborts sudo on tamper
        #   sufficient pam_sudowhat.so console-gate    - PAM_SUCCESS iff the caller is the
        #                                                local console (GUI) user, so the
        #                                                console user is never asked for a
        #                                                password (Touch ID gates them in the
        #                                                approval plugin). For a non-console
        #                                                caller it fails, so the parent
        #                                                /etc/pam.d/sudo chain falls through to
        #                                                pam_smartcard / pam_opendirectory on
        #                                                the caller's own terminal.
        auth    requisite     ${cfg.package}/lib/pam/pam_sudowhat.so
        auth    sufficient    ${cfg.package}/lib/pam/pam_sudowhat.so console-gate
      '' else ''
        # Managed by the sudowhat nix-darwin module.
        #
        #   requisite  pam_sudowhat.so   - integrity; failure aborts sudo immediately
        #   sufficient pam_permit.so     - success terminates the auth chain so the
        #                                  parent /etc/pam.d/sudo never falls back
        #                                  to pam_smartcard / pam_opendirectory.
        #                                  Non-console callers are denied by the
        #                                  approval plugin (no password path here).
        auth    requisite     ${cfg.package}/lib/pam/pam_sudowhat.so
        auth    sufficient    pam_permit.so
      '';
  };
}
