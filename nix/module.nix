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

    nonConsole = lib.mkOption {
      type = lib.types.enum [ "password" "deny" ];
      default = "password";
      description = ''
        What a non-console caller — an SSH session, unattended automation, any
        non-GUI-login security session — may do with sudo. A non-console caller
        is NEVER shown a Touch ID / Authorization Services sheet (that would
        render on the console user's screen — the reflexive-approval hole this
        tool exists to close); this option only chooses between password and
        denial.

        - `password` (the default): the `sudo_local` gate variant is installed.
          The local console user is still gated by the approval plugin's Touch
          ID prompt (no password), while a non-console caller falls through to
          sudo's native password / smartcard factor on their OWN terminal, and
          the approval plugin steps aside for them once sudo has authenticated
          them. This is stock sudo behaviour for remote callers, kept intact —
          sudowhat adds trustworthy console Touch ID without taking it away.
        - `deny`: the console-only variant is installed. Only the local,
          physically present console (GUI) user may sudo; every non-console
          caller is denied without a prompt. Choose this to harden the machine
          so a stolen password alone cannot escalate remotely — at the cost of
          breaking remote / headless sudo (root-context automation stays exempt).

        Neither value grants new authority: sudoers still decides who may run
        what. The classification is by the caller's security session (local GUI
        vs. remote/headless), not by uid, so an SSH session running as the same
        user as the console login is correctly treated as non-console.
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
        "plain" "bold" "red" "green" "yellow" "blue" "magenta" "cyan" "random"
      ];
      default = "bold";
      description = ''
        Emphasis applied to the verify code echoed to the controlling
        terminal (the out-of-band code the user matches against the Touch ID
        sheet). Each color is bold-plus-color, so the emphasis still carries
        on a terminal theme where the color washes out; `bold` (the default)
        is a background-independent emphasis with no color; `plain` emits no
        escape sequence at all (a build-time equivalent of `NO_COLOR`);
        `random` picks a different color per invocation from a curated subset
        (red, green, magenta, cyan) — purely cosmetic novelty, and the only
        style resolved at runtime rather than baked.

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

    auditDisplay = lib.mkOption {
      type = lib.types.enum [ "on" "off" ];
      default = "on";
      description = ''
        Whether sudowhat shows the command on the controlling terminal before
        authentication, via a sudo audit plugin.

        - `on` (the default): the audit plugin prints `user`, `path` (the
          working directory), and the `command` as typed to the controlling
          terminal on EVERY path — the local console (before the Touch ID sheet
          and its verify code) and non-console / SSH sessions (before sudo's
          native password prompt). This closes the gap where a non-console sudo
          used to step aside silently, showing a bare `Password:` with no
          command.
        - `off`: the audit plugin loads but displays nothing.

        The display is disclosure, never a trust signal: any process that can
        write your terminal can forge the same bytes, so the anchor stays the
        verify code matching the system-rendered sheet (biometric path) or
        sudo's own PAM (terminal path). It is written to /dev/tty only — never to
        sudo's stderr — so it cannot be captured by a `2>file` redirect, and it
        is skipped when there is no controlling terminal (headless). Every token
        is shell-quoted and control-character escaped by the memory-safe Rust
        core, so it carries no raw escape sequences. Baked into the signed bundle
        at build time.

        The audit plugin joins the mutual-signature web: a present-but-tampered
        audit bundle makes the approval plugin and `pam_sudowhat` fail closed. It
        is optional, though — an absent bundle disables terminal display without
        affecting authentication (tamper-evident in place, not removal-proof).
      '';
    };

    echoColor = lib.mkOption {
      type = lib.types.enum [ "off" "anomalies" ];
      default = "anomalies";
      description = ''
        Whether the audit plugin's terminal command display (see `auditDisplay`)
        is coloured to draw the eye to the bytes that matter.

        - `off` emits the display with no colour at all.
        - `anomalies` (the default) wraps only anomaly spans in a fixed,
          reviewed palette:
          deceptive Unicode escapes (`\uNNNN` — bidi, zero-width, homoglyphs)
          in red, control-byte escapes (`\n \r \t \0 \xNN`) in magenta, shell
          metacharacters (`'` `"` `` ` `` and the escaped backslash) in cyan,
          and notable whitespace runs (leading, trailing, or doubled spaces)
          shown on a grey background. Ordinary command structure is left
          uncoloured.

        NOTE: the colouriser is a fast-follow — the escape_core port of the
        anomaly colourer is not done yet — so `anomalies` is accepted but the
        display currently renders plain regardless. Once it lands it is emphasis
        only, never a trust signal (the anchor stays the verify code matching the
        system-rendered sheet), and the runtime opt-outs still force plain:
        NO_COLOR or TERM=dumb in the invoking environment, or a non-tty target.
        Baked into the signed bundle at build time.
      '';
    };

    policyDeference = lib.mkOption {
      type = lib.types.enum [ "on" "off" ];
      default = "on";
      description = ''
        Whether sudowhat defers to sudoers' own authentication decision for the
        local console user.

        - `on` (the default): when sudoers itself waived authentication for an
          invocation — a `NOPASSWD` rule, `Defaults !authenticate`, or a valid
          credential in the timestamp cache — the console user's Touch ID prompt
          is **skipped** and the command just runs. sudo runs the PAM auth stack
          (where `pam_sudowhat` sets a process-local marker) only when it
          requires authentication, so an absent marker — with `pam_sudowhat`
          still wired into `sudo_local` — is the signal that sudoers waived it.
        - `off`: the console user is always prompted, exactly as before this
          option existed; the marker is not consulted.

        This grants no new authority: sudoers still decides who may run what and
        whether authentication is required. It only stops sudowhat from
        re-gating, with a biometric prompt, a command sudoers already chose to
        run without authentication. The decision is fail-safe in every uncertain
        direction — a present marker, an unverifiable chain, or this option off
        all result in a prompt, never a silent skip. A caller cannot suppress
        the prompt by manipulating its environment (pre-setting the marker only
        *forces* a prompt); suppressing it would require editing the root-owned
        `sudo_local` / `sudo` PAM files, which is outside the threat model.

        Note the timestamp-cache interaction: with `on` and a non-zero
        `timestampTimeout`, a second command within the grace window on the same
        terminal is treated as deferred and runs with no sheet — sudo's normal
        grace after the first real factor on that terminal. Keep
        `timestampTimeout = 0` (the default) for a Touch ID sheet on every
        command. Baked into the signed bundle at build time.
      '';
    };

  };

  config = lib.mkIf cfg.enable (let
    # Bake the chosen build-time presets into the bundle. The defaults
    # (verifyStyle "bold", echoColor "anomalies", policyDeference "on",
    # auditDisplay "on") reproduce the package's own defaults, so default users get the same
    # store path with no rebuild; any other value produces a distinct derivation
    # whose embedded paths and the /etc references below stay consistent (both
    # come from `pkg`), preserving mutual signature verification.
    pkg = cfg.package.override {
      inherit (cfg) verifyStyle echoColor policyDeference auditDisplay;
    };
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
      #
      # The audit plugin owns terminal command display; its open() runs before
      # the approval plugin and before PAM, so the command is shown first on
      # every path. Line order here is cosmetic — sudo runs audit open() before
      # other plugins by type, not by file position.
      Plugin sudowhat_audit_plugin ${pkg}/libexec/sudo/sudowhat_audit.so
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
      if cfg.nonConsole == "password" then ''
        # Managed by the sudowhat nix-darwin module (nonConsole = "password").
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
        # Managed by the sudowhat nix-darwin module (nonConsole = "deny").
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
