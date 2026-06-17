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

    verifyStyle = lib.mkOption {
      type = lib.types.enum [
        "plain" "bold" "red" "green" "yellow" "blue" "magenta" "cyan"
      ];
      default = "bold";
      description = ''
        Emphasis applied to the verify code echoed to the controlling
        terminal (the out-of-band code the user matches against the Touch ID
        sheet). Each color is bold-plus-color, so the emphasis still carries
        on a terminal theme where the color washes out; `bold` (the default)
        is a background-independent emphasis with no color; `plain` emits no
        escape sequence at all (a build-time equivalent of `NO_COLOR`).

        This is purely cosmetic and never a trust signal: the anchor is the
        code matching the system-rendered Touch ID sheet, which cannot be
        colored. The value is baked into the signed bundle at build time and
        selects from a fixed, reviewed set of SGR sequences, never a free-form
        string, so no escape-injection surface is added. The runtime opt-outs
        still apply: NO_COLOR or TERM=dumb in the invoking environment, a
        non-tty target, or the stderr fallback always render plain regardless
        of this setting.
      '';
    };
  };

  config = lib.mkIf cfg.enable (let
    # Bake the chosen emphasis into the bundle. The default verifyStyle ("bold")
    # reproduces the package's own default, so default users get the same store
    # path with no rebuild; any other value produces a distinct derivation whose
    # embedded path and the /etc references below stay consistent (both come from
    # `pkg`), preserving mutual signature verification.
    pkg = cfg.package.override { inherit (cfg) verifyStyle; };
  in {
    # The store-path approach: binaries live in /nix/store, /etc files
    # reference them by full path. nix-darwin owns these three /etc files
    # declaratively, so darwin-rebuild rotates the whole set atomically
    # with the package — no drift between /etc/sudo.conf and the bundle
    # it points at.

    environment.etc."sudo.conf".text = ''
      # Managed by the sudowhat nix-darwin module. Disable the module to
      # restore stock /etc/sudo.conf (which on macOS does not exist by
      # default).
      Plugin sudowhat_approval_plugin ${pkg}/libexec/sudo/sudowhat_approval.so
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
        auth    requisite     ${pkg}/lib/pam/pam_sudowhat.so
        auth    sufficient    ${pkg}/lib/pam/pam_sudowhat.so console-gate
      '' else ''
        # Managed by the sudowhat nix-darwin module.
        #
        #   requisite  pam_sudowhat.so   - integrity; failure aborts sudo immediately
        #   sufficient pam_permit.so     - success terminates the auth chain so the
        #                                  parent /etc/pam.d/sudo never falls back
        #                                  to pam_smartcard / pam_opendirectory.
        #                                  Non-console callers are denied by the
        #                                  approval plugin (no password path here).
        auth    requisite     ${pkg}/lib/pam/pam_sudowhat.so
        auth    sufficient    pam_permit.so
      '';
  });
}
