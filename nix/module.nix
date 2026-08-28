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
        is NEVER shown a Touch ID / Authorization Services dialog (that would
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

    authCacheMinutes = lib.mkOption {
      type = lib.types.either lib.types.int (lib.types.enum [ "defer" ]);
      default = 0;
      description = ''
        Value for sudo's `Defaults timestamp_timeout` (minutes). 0 (the
        default) disables the credential cache, so every privileged command
        re-prompts. A positive value re-enables sudo's normal per-tty grace
        period; under the default per-tty scope a cached credential is only
        ever reused on the same terminal that already authenticated a real
        factor. `"defer"` defers entirely: the module writes no
        `/etc/sudoers.d/sudowhat` and no `timestamp_timeout` line, so whatever
        your sudoers already configures (or sudo's stock default, 5 minutes)
        stays in effect. The module never sets `timestamp_type=global` — the
        one mode that would let a console credential be reused by a same-uid
        remote session.
      '';
    };

    auditDisplay = lib.mkOption {
      type = lib.types.enum [ "on" "off" ];
      default = "on";
      description = ''
        Whether sudowhat shows the command on the controlling terminal before
        authentication, via a sudo audit plugin.

        - `on` (the default): the audit plugin prints `user:`, `directory:` (the
          working directory), `input:` (the command as typed) and — when the
          typed command is a bare name — `path:` to the controlling terminal on
          EVERY path — the local console (before the Touch ID dialog and its
          verify code) and non-console / SSH sessions (before sudo's native
          password prompt). This closes the gap where a non-console sudo used to
          step aside silently, showing a bare `Password:` with no command.
        - `off`: the audit plugin loads but displays nothing.

        The `input:` label states its own epistemic status: at audit-plugin time
        sudo has not resolved the command yet, so this line can only show what
        the user asked for. The resolved absolute path is shown separately, by
        the approval plugin, on the `execute:` line.

        The `path:` row is shown only for a bare command name — an absolute or
        relative path never consults `PATH`, so there would be nothing to
        qualify. It shows the caller's `PATH` exactly as handed to sudo: the
        attacker-influenceable surface that steers how a bare name resolves. It
        is deliberately *not* a claim about the final resolution `PATH` — a
        sudoers `secure_path` may override it entirely — and sudowhat never
        walks the list or says which entry would win; `execute:` still shows
        the outcome. What the row buys is disclosure *before* the gate, on the
        password path, where `execute:` cannot appear until the password has
        already been spent. It is printed on every path that shows the block:
        the plugin cannot know pre-authentication which mode this invocation
        will take, so the slight redundancy on a biometric console (where
        `execute:` also appears before the dialog) is accepted rather than
        guessed at. macOS only for now — the Linux plugin has its own roadmap.

        The display is disclosure, never a trust signal: any process that can
        write your terminal can forge the same bytes, so the anchor stays the
        verify code matching the system-rendered dialog (biometric path) or
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

    execDisplay = lib.mkOption {
      type = lib.types.enum [ "on" "off" ];
      default = "on";
      description = ''
        Whether sudowhat shows the resolved command — the `execute:` line — on
        the controlling terminal, via the approval plugin. The companion to
        `auditDisplay`: that one governs the pre-authentication block, this one
        governs the single line printed once sudo has resolved what it will
        actually execute (the absolute path out of sudo's own `command_info`,
        never resolved plugin-side).

        - `on` (the default): the line is printed on every path that reaches it
          — before the Touch ID dialog in biometric mode (pre-decision), after
          sudo's own password on the non-console terminal path (a last look),
          on a `policyDeference` skip, and on the root-initiated bypass, whose
          line is the unpadded solo form.
        - `off`: none of those print. The approval plugin still loads, still
          verifies its siblings' signatures, and still gates exactly as it did
          — it simply narrates nothing, the same shape `auditDisplay = "off"`
          gives the other bundle.

        One exception, and it is deliberate: with `execConfirm = "on"` the
        confirmation ceremony still prints the resolved line before its
        `run? [y/N]`. A yes/no about a command sudowhat refuses to show would be
        an empty ceremony, so the question keeps its subject. Set `execConfirm`
        to `"off"` as well if the terminal should stay silent altogether.

        The runtime gates are unchanged in both settings: the line goes to
        /dev/tty only — never sudo's stderr, so no `2>file` redirect can capture
        it — and it is skipped when there is no controlling terminal. Turning
        this off removes disclosure, not a gate: what sudowhat authorizes, and
        how, is identical either way. Baked into the signed bundle at build
        time. macOS only — the Linux port ships the display plugin without an
        approval plugin.
      '';
    };

    echoColor = lib.mkOption {
      type = lib.types.enum [ "off" "on" ];
      default = "on";
      description = ''
        Whether the terminal command display is coloured to draw the eye to the
        bytes that matter. It governs the two command VALUES — the audit
        plugin's `input:` line (see `auditDisplay`) and the approval plugin's
        resolved `execute:` line — together, because a reader sees them as one
        display.

        - `off` renders both command lines plain.
        - `on` (the default) highlights `execute:` by role — the program's
          directory part in plain cyan and its basename in bold cyan, option
          flags bold blue, every other token plain — and wraps anomaly spans in
          a fixed, reviewed palette on top:
          deceptive Unicode escapes (`\uNNNN` — bidi, zero-width, homoglyphs)
          in red, control-byte escapes (`\n \r \t \0 \xNN`) in magenta, shell
          metacharacters (`'` `"` `` ` `` and the escaped backslash) in cyan,
          and notable whitespace runs (leading, trailing, or doubled spaces)
          shown on a grey background IN THE PROGRAM TOKEN ONLY -- the path that
          will execve, where invisible padding changes what runs. Argument
          tokens do not take that mark: a script passed as one argument would
          turn every escaped newline's indentation into a grey block, and those
          bytes render escaped and quoted either way.

          The `input:` value takes the same anomaly palette over a QUIET base:
          its routine tokens — program, flags and values alike — all render
          dim, so the pre-resolution line reads under the resolved one and an
          anomaly span is the only coloured thing on that row. `input:` quiet,
          `execute:` loud, anomalies at full strength on both. Both lines come
          out of one shared walk over one token list — the weights are two base
          palettes, not two renderers — so they can never disagree on a token.

        What it does NOT govern: the frame around those values — the label
        gutter, the bold labels, the `user:` and `directory:` lines, the
        `verify:` code emphasis (fixed bold magenta, with no option of its own).
        Those are sudowhat's own fixed chrome rather than a rendering of
        untrusted argv, so they follow the runtime gates alone — NO_COLOR,
        TERM absent/empty/`dumb`, or a non-tty target — and stay put at `off`.

        The command stays one logical line: the colour goes around tokens that
        are already escaped and quoted, so it never splits, elides or reorders
        anything, and stripping it returns the plain line byte for byte. It is
        emphasis only, never a trust signal (the anchor stays the verify code
        matching the system-rendered dialog), the runtime opt-outs still force
        plain — NO_COLOR or TERM=dumb in the invoking environment, or a non-tty
        target — and any colouriser failure falls back to the plain line rather
        than showing nothing. Baked into both signed bundles at build time.
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

        Note the timestamp-cache interaction: with `on` and a credential cache
        in effect (`authCacheMinutes` non-zero, or `"defer"` with a
        non-zero sudoers timeout), a second command within the grace window on
        the same terminal is treated as deferred and runs with no dialog — sudo's normal
        grace after the first real factor on that terminal. Keep
        `authCacheMinutes = 0` (the default) for a Touch ID dialog on every
        command. Baked into the signed bundle at build time.
      '';
    };

    execConfirm = lib.mkOption {
      type = lib.types.enum [ "on" "off" ];
      default = "off";
      description = ''
        Whether the terminal-password path asks one `run? [y/N]` after showing
        the resolved `execute:` line.

        Background: sudo resolves the command inside the same policy step that
        collects the password, and no plugin hook exists between resolution and
        authentication. In biometric mode that does not matter — the dialog *is*
        the decision, sudowhat raises it, and the resolved `execute:` line is
        printed before it. In terminal-password mode the password is already
        spent by the time sudowhat sees the resolved path, so `execute:` can
        only be a last-look.

        - `off` (the default): the resolved line prints and the command runs.
          The one existing decision — the dialog, or sudo's own password — stays
          the only decision.
        - `on`: after sudo's own authentication has succeeded, the approval
          plugin prints `execute:` and asks one `run? [y/N]` on the terminal via
          sudo's conversation API. The decision then completes *after* the
          resolved path is visible, which is the guarantee biometric mode gives,
          split into authenticate-then-confirm.

        No password ever touches plugin code: this is a yes/no on a caller sudo
        has already authenticated and sudoers has already authorized, so it can
        only ever withhold an allow, never grant one. Declining is a quiet abort
        — nothing is wedged or cached, and the command can simply be re-run.

        Tty-gated: with no controlling terminal there is no prompt and behaviour
        is identical to `off`, so piped and automated invocations can never newly
        block.

        Authenticate-*then*-confirm, literally: the question is asked only when
        sudo actually collected a factor for **this** invocation. That is
        detected with the same in-process PAM marker `policyDeference` uses —
        `pam_sudowhat` sets it whenever sudo runs the auth stack, in-process and
        after the caller's own environment was captured, so a caller can add the
        marker but never remove it. Runs where sudoers waived authentication — a
        `NOPASSWD` rule, `Defaults !authenticate` — leave the marker absent and
        are **never** asked, terminal or not: re-gating what sudoers explicitly
        waived would contradict the deference `policyDeference` applies on the
        console path. The timestamp cache follows the same rule, which is worth
        stating: within a live credential-cache window (`authCacheMinutes`
        non-zero, or `"defer"` deferring to sudoers) a cached credential
        also skips the auth stack, so the follow-up command is treated as waived
        and is not asked either. At the module default of 0 every command
        authenticates, and so every command is asked.

        The prompt applies to the terminal-password path only; the root exemption and
        `policyDeference` skips are untouched, and the biometric
        path already decides after resolution. Baked into the signed bundle at
        build time. macOS only — the Linux port ships the display plugin without
        an approval plugin.
      '';
    };

  };

  config = lib.mkIf cfg.enable (let
    # Bake the chosen build-time presets into the bundle. The defaults
    # (echoColor "on", policyDeference "on",
    # auditDisplay "on", execDisplay "on", execConfirm "off") reproduce the
    # package's own defaults, so default users get the same store path with no
    # rebuild; any other value produces a distinct derivation whose embedded
    # paths and the /etc references below stay consistent (both come from
    # `pkg`), preserving mutual signature verification.
    pkg = cfg.package.override {
      inherit (cfg)
        echoColor policyDeference auditDisplay execDisplay execConfirm;
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
    #
    # authCacheMinutes = "defer" means full deference: no file at all, so an
    # existing sudoers timestamp_timeout (or sudo's stock default) governs.
    environment.etc."sudoers.d/sudowhat" =
      lib.mkIf (cfg.authCacheMinutes != "defer") {
        text = ''
          # Managed by the sudowhat nix-darwin module.
          # timestamp_timeout is services.sudowhat.authCacheMinutes (default 0 =
          # cache disabled, every invocation re-prompts). timestamp_type is left
          # at sudo's default (per-tty) and never set to global.
          Defaults timestamp_timeout=${toString cfg.authCacheMinutes}
        '';
      };

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
