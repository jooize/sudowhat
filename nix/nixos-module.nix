{ self }:
{ config, pkgs, lib, ... }:

let
  cfg = config.services.sudowhat;
in {
  options.services.sudowhat = {
    enable = lib.mkEnableOption "sudowhat — terminal command display for sudo (Linux)";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression
        "sudowhat.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = ''
        The sudowhat package providing the audit-plugin `.so`. Overriding this
        means the `/etc/sudo.conf` line written below references the override's
        store path.
      '';
    };

    auditDisplay = lib.mkOption {
      type = lib.types.enum [ "on" "off" ];
      default = "on";
      description = ''
        Whether sudowhat shows the command on the controlling terminal before
        authentication, via a sudo audit plugin.

        - `on` (the default): the audit plugin prints `user:`, `directory:` (the
          invoking working directory), and `input:` (the command as typed) to
          the controlling terminal before sudo's native `pam_unix` password
          prompt, on every path.
        - `off`: the audit plugin loads but displays nothing.

        The `input:` label states its own epistemic status: at audit-plugin time
        sudo has not resolved the command yet, so this line can only show what
        the user asked for. On macOS the resolved absolute path follows on an
        `execute:` line from the approval plugin; there is no approval plugin on
        Linux, so `input:` is the whole display here.

        The display is disclosure, never a trust signal: any process that can
        write your terminal can forge the same bytes. On Linux there is no
        biometric to bind a verify code to, and no code-signing anchor — the
        trust model is entirely sudo's own root-owned + non-writable enforcement
        on the `.so` and `sudo.conf` (fail-closed). The block is written to
        /dev/tty only — never to sudo's stderr — so a `2>file` redirect cannot
        capture it, and it is skipped when there is no controlling terminal
        (headless). Every token is shell-quoted and control-character escaped by
        the memory-safe Rust core, so it carries no raw escape sequences. Baked
        into the plugin at build time.
      '';
    };

    echoColor = lib.mkOption {
      type = lib.types.enum [ "off" "anomalies" ];
      default = "anomalies";
      description = ''
        Whether the terminal command display (see `auditDisplay`) is coloured to
        draw the eye to the bytes that matter.

        - `off` emits the display with no colour at all.
        - `anomalies` (the default) is intended to wrap only anomaly spans
          (deceptive Unicode escapes, control-byte escapes, shell metacharacters,
          notable whitespace) in a fixed reviewed palette.

        NOTE: the colouriser is a fast-follow — the escape_core port of the
        anomaly colourer is not done yet — so `anomalies` is accepted but the
        display currently renders plain regardless (the bold label emphasis is
        governed separately, by the NO_COLOR / TERM environment gates and the
        tty `isatty()` check). This mirrors the macOS bundle exactly. Baked into
        the plugin at build time.
      '';
    };
  };

  config = lib.mkIf cfg.enable (let
    # Bake the chosen build-time presets into the plugin. The defaults
    # (auditDisplay "on", echoColor "anomalies") reproduce the package's own
    # defaults, so default users get the same store path with no rebuild; any
    # other value produces a distinct derivation whose /etc/sudo.conf reference
    # below stays consistent (both come from `pkg`).
    pkg = cfg.package.override {
      inherit (cfg) auditDisplay echoColor;
    };
  in {
    # /etc/sudo.conf, written whole (sudo.conf has no include directive).
    #
    # CRITICAL: once /etc/sudo.conf contains ANY Plugin line, sudo no longer
    # auto-loads its default sudoers policy (sudo.conf(5): the defaults apply
    # only when there are no Plugin lines). So the three stock sudoers plugins
    # MUST be re-declared here alongside ours, or sudo loses its policy entirely
    # and every `sudo` fails. Bare `sudoers.so` resolves relative to sudo's own
    # plugin directory, so no absolute path is needed for those. (Unlike macOS,
    # whose Apple sudo keeps sudoers built-in — verify on hardware that this
    # host's sudo finds sudoers.so in its default plugin dir.)
    #
    # The store path is root-owned and mode 0444 (not group/world writable),
    # which satisfies sudo's fail-closed requirement for sudo.conf and the
    # plugin — that enforcement IS the Linux trust model; there is no
    # code-signing anchor here.
    environment.etc."sudo.conf".text = ''
      # Managed by the sudowhat NixOS module. Disable the module to restore the
      # stock /etc/sudo.conf (which on NixOS does not exist by default, so sudo
      # falls back to its built-in sudoers auto-load).
      Plugin sudoers_policy sudoers.so
      Plugin sudoers_io     sudoers.so
      Plugin sudoers_audit  sudoers.so
      Plugin sudowhat_audit_plugin ${pkg}/libexec/sudo/sudowhat_audit.so
    '';
  });
}
