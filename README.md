# sudowhat

A sudo approval plugin for macOS that displays the **exact command** sudo will run — inside the system Touch ID prompt — before you authorize it.

```
$ sudo /bin/echo hello
        ┌──────────────────────────────────┐
        │  🔒  Run as root:                │
        │                                  │
        │      /bin/echo hello             │
        │                                  │
        │      [ Touch ID  /  Watch  /     │
        │        Use Password ]            │
        └──────────────────────────────────┘
hello
```

## Why

Stock macOS sudo with `pam_tid.so` shows a generic "sudo wants permission" Touch ID prompt. The prompt does not show *what command* is being authorized.

A compromised user shell — or a typo, a malicious `npm install` postinstall, an alias planted by a copy-pasted snippet — can hide an attack behind that generic prompt:

```sh
alias unlock='sudo chown attacker:wheel /etc/sudoers'
```

You think you're unlocking your own file. The prompt looks identical. You biometrically approve a sudoers takeover.

**sudowhat closes that wedge.** The system-trusted Touch ID dialog displays the resolved command path and arguments — the same bytes sudo will pass to `execve` — *before* you authorize. Argv tokens are shell-quoted; backslashes and control characters are escaped (named — `\n`, `\r`, `\t`, `\0`, `\\` — or hex — `\xNN`, `\uNNNN`) so the rendered prompt is unambiguous about its source bytes. An attacker cannot smuggle hidden lines into the prompt, nor can a literal `\n` in argv pose as a real newline.

## Standalone by design

sudowhat is a standalone tool that benefits **every** `sudo` invocation on the host, whatever launched it — a shell, a Makefile, a package manager, a bespoke ceremony. It is not a component of any one workflow and takes no direction from its callers.

The corollary matters for anyone building on top of it: **no tool may assume sudowhat is installed.** A program that shells out to `sudo` must display what it is about to run, and must be safe and complete, entirely on its own — sudowhat is defense in depth *layered over* that, never a dependency it can lean on. Concretely, a caller must not drop its own pre-elevation command display on the assumption that sudowhat will show one; on a host without the plugin, that display would simply vanish.

The relationship is deliberately one-way and unsuppressable in both directions: callers cannot rely on sudowhat (it may be absent), and sudowhat does not rely on — or obey — callers (its disclosure is unconditional, with no caller-settable knob to silence it; see [Console vs. non-console callers](#console-vs-non-console-callers)). Each stands alone.

## Authentication methods

A single dialog accepts any of the following:

- **Touch ID** — fingerprint sensor on the keyboard or external Magic Keyboard.
- **Apple Watch** — double-click the side button while wearing an unlocked, paired watch.
- **iPhone** (companion?) — `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion` is documented to cover iPhone-as-companion since macOS 15, but I have not seen the prompt actually appear on a paired iPhone in testing. Watch is the verified case; iPhone is "the policy theoretically supports it, no evidence it fires."
- **Password fallback** — clicking "Use Password" opens an Authorization Services prompt (the classic lock-icon dialog) with the same command shown, accepting your account password.

The prompt binds to *your* user account, not "System Administrator", so your password works in the fallback. (sudo runs as root by the time the plugin executes; sudowhat drops EUID to your user around the auth call so biometric and password both resolve against your enrollment.)

## Quick start

Build, sign, install. Requires macOS 15 or later — the prompt uses a LocalAuthentication policy (`…BiometricsOrCompanion`) added in macOS 15 — and the Xcode Command Line Tools.

> [!WARNING]
> **Installing this edits sudo's own configuration — do it deliberately.** It
> writes `/etc/sudo.conf`, `/etc/pam.d/sudo_local`, and `/etc/sudoers.d/sudowhat`
> (on Linux, the audit plugin needs `/etc/sudo.conf`). A malformed sudo/PAM
> config can make `sudo` refuse to run — and you may need `sudo` to fix it. The
> installer validates its edits and rolls back on failure, but before you run it,
> **keep a separate root shell open** (`sudo -s` in another terminal, or a root
> console / VM snapshot) so a broken `sudo` is always recoverable. On Linux in
> particular, adding *any* `Plugin` line to `/etc/sudo.conf` disables sudo's
> default sudoers auto-load, so the file must re-declare the stock `sudoers.so`
> plugins or every `sudo` fails — the Nix module and the sample config do this;
> a hand-edited file must too.

```sh
git clone https://github.com/jooize/sudowhat
cd sudowhat
make sign           # ad-hoc-signs the bundles for personal use
sudo make install   # drops bundles into /usr/local, edits /etc/sudo.conf,
                    # /etc/pam.d/sudo_local, /etc/sudoers.d/sudowhat;
                    # rolls back on any failure
```

Verify:

```sh
sudo -k && sudo /bin/echo hello
```

A Touch ID dialog should pop up reading `Run as root:` followed by `/bin/echo hello`. Approve to run; cancel to deny — sudo prints `sudowhat: authorization denied: ...` and exits non-zero.

To remove:

```sh
sudo make uninstall
```

This restores stock sudo behavior, reverting everything the install added — the two `.so` bundles, the two `/etc` files it creates (`/etc/sudoers.d/sudowhat`, `/etc/pam.d/sudo_local`), and the one line it appends to `/etc/sudo.conf`.

### nix-darwin

If you manage your Mac with nix-darwin, install everything declaratively — the binaries live in the Nix store, and the three `/etc` files are owned by nix-darwin, rotated atomically with the package. Add the flake to your darwin configuration:

```nix
{
  inputs.sudowhat.url = "github:jooize/sudowhat";

  outputs = { self, nixpkgs, nix-darwin, sudowhat, ... }: {
    darwinConfigurations."<host>" = nix-darwin.lib.darwinSystem {
      modules = [
        sudowhat.darwinModules.default
        {
          services.sudowhat.enable = true;
          # What non-console callers (SSH, unattended) may do: "password" (the
          # default — native password on their own terminal, stock sudo) or
          # "deny" (console-only lockdown). See "Console vs. non-console callers".
          # services.sudowhat.nonConsole = "deny";
          # Re-enable sudo's per-tty credential cache, in minutes (default 0 =
          # cache off, so every command re-prompts). Never sets
          # timestamp_type=global. See "How it works".
          # services.sudowhat.timestampTimeout = 5;
          # Emphasis on the verify code echoed to the terminal (default
          # "bold"; "plain" disables it; colors are bold+color; "random"
          # rotates colors per invocation). Cosmetic only.
          # services.sudowhat.verifyStyle = "cyan";
          # Show user/path/command on the terminal before auth, via the audit
          # plugin ("on", the default) or not ("off"). See "How it works".
          # services.sudowhat.auditDisplay = "off";
          # Defer to sudoers' own auth decision: skip the console Touch ID
          # prompt when sudoers waived auth (a NOPASSWD rule, !authenticate, or
          # a cached credential), so a NOPASSWD command just runs. Default "on";
          # "off" always prompts. See "How it works".
          # services.sudowhat.policyDeference = "off";
        }
      ];
    };
  };
}
```

To audit before depending, pin to a local clone (`git+file:///path/to/clone`) or a reviewed commit (`github:jooize/sudowhat/<sha>`).

### Other configuration managers

If you manage `/etc` with something else (home-manager, Ansible, Chef), use:

```sh
sudo make install-binaries       # installs only the .so bundles to /usr/local
make print-install-binaries      # prints what install-binaries would do plus
                                 # the /etc snippets you need to add yourself
```

`install.bash` refuses to overwrite `/etc` files that are symlinks into `/nix/store` (nix-darwin's signature), pointing you at one of the above flows. Override with `make install-force` if you really mean to clobber them.

## How it works

Three signed Mach-O bundles loaded into sudo's process — a PAM module, an approval plugin, and an audit plugin — mutually verifying each other's code signature. No daemon, no agent, no IPC.

```
sudo /usr/bin/foo bar
  │
  ▼  sudo runs the audit plugin's open() FIRST, before any auth
/etc/sudo.conf
  └── Plugin sudowhat_audit_plugin /usr/local/libexec/sudo/sudowhat_audit.so
      • SecStaticCodeCheckValidity on pam_sudowhat.so + the approval plugin
      • writes user / path / command (as typed) to /dev/tty — every path,
        before the password prompt or Touch ID sheet; escaping done in the
        memory-safe Rust escape_core. tty-only, skipped when headless.
  │
  ▼  PAM auth chain
/etc/pam.d/sudo
  └── auth include sudo_local
      └── /etc/pam.d/sudo_local
          ├── auth requisite  /usr/local/lib/pam/pam_sudowhat.so
          │     • parses /etc/sudo.conf, confirms our Plugin line is present
          │     • SecStaticCodeCheckValidity on the approval + audit bundles
          │     • returns PAM_SUCCESS (-> sufficient pam_permit -> done)
          │              or PAM_AUTH_ERR (-> sudo aborts)
          └── auth sufficient pam_permit.so
  │
  ▼  sudo loads approval plugin
/etc/sudo.conf
  └── Plugin sudowhat_approval_plugin /usr/local/libexec/sudo/sudowhat_approval.so
      • SecStaticCodeCheckValidity on pam_sudowhat.so + the audit plugin (mutual)
      • uid 0 (root) caller: exempt — system automation, not escalation
      • else: caller must be the LOCAL CONSOLE session — SessionGetInfo()
        reports graphic access and is not remote, and the console UID equals
        the invoking UID. A non-console caller never reaches this sheet: it is
        sent to a native password (nonConsole="password", default) or denied
        (nonConsole="deny") — see below.
      • formats the command with shell-quoting and control-char escapes
      • seteuid drops to the user
      • LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometricsOrCompanion)
      • on fallback: AuthorizationCreate with system.privilege.admin and
        kAuthorizationEnvironmentPrompt = command string
      • seteuid restores to root
      • re-stat target binary; deny if (dev,inode) changed during auth
      • returns 1 = allow, 0 = deny, -1 = error
  │
  ▼  sudo execve("/usr/bin/foo", ["bar"], ...)
```

The default (`nonConsole = "password"`) installs the gate variant: the second
`sudo_local` line is `auth sufficient pam_sudowhat.so console-gate`. That
console-gate succeeds (no password) **only** for the local console user, and
fails for everyone else — so a non-console caller falls through the parent
`/etc/pam.d/sudo` chain to sudo's native `pam_smartcard` / `pam_opendirectory`
password on the caller's *own* terminal, and the approval plugin steps aside for
them (no sheet) once sudo has authenticated them. Set `nonConsole = "deny"` to
install `auth sufficient pam_permit.so` instead, which terminates the chain with
no password path, so the approval plugin denies every non-console caller.

**Trust root:** Apple Developer ID code signing. In a release build, `SignatureVerifier` enforces the team-identifier requirement `anchor apple generic and certificate leaf[subject.OU] = "<TEAM_ID>"`. Forging the integrity check requires forging your developer signature.

**Fail-closed:** any failure of either component aborts sudo. No path leads to `pam_opendirectory`-style permissive defaults. Apple's stock `pam_tid.so` is the broken behavior we're fixing — falling back to it would be regression, not recovery.

**Non-console defense (SSH, automation).** sudowhat's core job is to show you what will run and prove it came from your terminal; because it sits in the auth path, it *also* decides *where* a caller may authenticate. It classifies the caller by its **security session**, not by uid: a local GUI login has graphic access and is not remote, whereas an SSH session is remote and a non-graphical (system-daemon) session lacks graphic access (`SessionGetInfo`). A uid comparison alone cannot tell them apart — the same user, logged in at the Mac and over SSH, shares one uid — and a same-uid SSH session could otherwise render a Touch ID sheet on the console screen.

**A non-console caller is never shown the biometric / Authorization Services sheet — this is structural, not a setting, and deliberately not configurable.** A Touch ID sheet raised for a remote or background caller renders on the *console* user's screen, and that user reflexively approves a command they never initiated. That reflexive approval is the exact hole sudowhat exists to close, so there is no option to permit it: the code returns before the `LAContext` call for any non-console caller (with a maintainer tripwire forbidding its reordering). It could not do anything useful anyway — the remote human isn't at the sensor, so a local sheet can never represent *them* authenticating; whoever is at the console would be approving on the remote caller's behalf. The only honest remote factor is a password *they* know on *their* terminal. (Genuine remote biometric would need an out-of-band push to the caller's own device — a daemon design this project rejected.)

So a non-console caller authenticates, if at all, through sudo's own machinery on its own session. By default (`nonConsole = "password"`) that is sudo's native password / smartcard factor — stock sudo behaviour, kept intact. Set `nonConsole = "deny"` to refuse non-console callers entirely (a stolen password alone then can't escalate remotely, at the cost of remote / headless sudo). This split separates *local-GUI* callers from *remote/headless* ones; it does **not** separate the human from another process inside the same GUI login (a background gui-domain agent is treated as console — see [Known limitations](#known-limitations)). See [Console vs. non-console callers](#console-vs-non-console-callers).

**Root callers are exempt — by design.** sudowhat gates *escalation*: an unprivileged principal reaching for root. A caller that is already root (uid 0) is not escalating, and a sudo plugin loaded inside a root process cannot meaningfully constrain root anyway — root can run the command directly, rewrite `/etc/sudo.conf`, or unload the plugin. Gating root would add no security while breaking legitimate root-context automation that shells out through sudo: nix-darwin / home-manager per-user activation runs as root and invokes `launchctl asuser <uid> sudo -u <user>` (invoking uid 0); the same pattern appears in launchd jobs and installer postinstall scripts, and these are non-interactive (no human to answer a prompt). So a uid-0 caller is allowed without a prompt, and the bypass is logged to the auth log (`syslog`/`LOG_AUTHPRIV`) so it is auditable rather than silent. The console gate still applies to every non-root caller — which is the entire population the gate can actually defend against.

**Policy deference (console NOPASSWD skip).** The approval plugin runs on *every* `sudo` that sudoers authorizes — `NOPASSWD` does not bypass it — so without this, the console user would get a Touch ID sheet even for a command sudoers authorized `NOPASSWD`. sudowhat instead **defers to sudoers' own authentication decision**: sudo runs the PAM auth stack (where `pam_sudowhat` sets a process-local marker) only when it requires authentication, so an *absent* marker means sudoers waived it — a `NOPASSWD` rule, `Defaults !authenticate`, a root invoker, or a valid credential in the timestamp cache. On an absent marker (with `pam_sudowhat` still wired into `sudo_local`, which the plugin re-checks), the console user's prompt is **skipped and the command just runs**. This is an authorization-trust decision that inherits sudoers' choice rather than re-implementing it — no command allowlist, no drift. It is fail-safe in every uncertain direction: a present marker, an unverifiable chain, or `policyDeference = "off"` all result in a prompt, and a caller can only ever *force* a prompt by manipulating its environment, never suppress one. Even on a skipped run the audit plugin has already shown user/path/command on the terminal (it runs before this decision), so a `NOPASSWD` command is still disclosed. Turn the whole behavior off with `services.sudowhat.policyDeference = "off"`.

**Per-command auth:** `Defaults timestamp_timeout=0` in `/etc/sudoers.d/sudowhat` disables sudo's auth cache, so every privileged command re-prompts. The value is configurable via `services.sudowhat.timestampTimeout`; the module never sets `timestamp_type=global`. Note this composes with policy deference: with a non-zero timeout, a second command within the window on the same terminal has a cached credential (auth stack skipped, marker absent) and so runs with no sheet — sudo's normal grace after the first real factor. Keep the default `0` for a Touch ID sheet on every command.

**Verify-code emphasis:** the code echoed to the controlling terminal is bold by default; `services.sudowhat.verifyStyle` selects a different emphasis (`plain`, `bold`, a bold-plus-color — `red`, `green`, `yellow`, `blue`, `magenta`, `cyan` — or `random`, which rotates among a curated color subset per invocation) baked into the signed bundle at build time. It is purely cosmetic — never a trust signal, since the anchor is the code matching the system-rendered Touch ID sheet — and the value selects from a fixed, reviewed set of escape sequences rather than a free-form string, so it adds no injection surface. `NO_COLOR` or `TERM=dumb` in the invoking environment still force plain at runtime regardless of the build-time setting.

**Terminal command display (audit plugin):** the [audit plugin](#how-it-works) shows the command on the controlling terminal **before authentication, on every path** — the local console (before the Touch ID sheet and its verify code) and non-console / SSH sessions (before sudo's native password prompt). This closes the gap where a non-console sudo used to step aside silently, showing a bare `Password:` with no command. It prints `user`, `path` (the working directory), and the `command` as typed, each shell-quoted and control-character escaped by the memory-safe Rust `escape_core` (so no raw control byte reaches the terminal). It is written to `/dev/tty` only — never sudo's stderr — so a `2>file` redirect cannot capture it, and it is skipped when there is no controlling terminal (headless). Because the full command is already on the terminal, when the Touch ID sheet has to replace an over-long item (past its ~480-char budget) with a `(see terminal)` marker, the marker always points at something. The display is disclosure only, never a trust signal: any process that can write your terminal can forge the same bytes, so the anchor stays the verify code matching the system-rendered sheet (biometric) or sudo's own PAM (terminal). Turn it off with `services.sudowhat.auditDisplay = "off"`.

Every row shares one label gutter, so `user`, `directory`, `command` and the verify code all start in the same column. The `command:` value is **highlighted by role** so the token worth reading is not buried in the wrap: the program's directory part in plain cyan and its **basename in bold cyan**, every other token plain, the quotes sudowhat itself added dim, with anomalous spans in the palette above them — deceptive Unicode escapes red, control-byte escapes magenta, shell metacharacters cyan, notable whitespace runs on a grey background. A hostile argument spelled like one of sudowhat's own lines (`'sudowhat: user: evil'`) therefore lands quoted and colored as data, visibly not a real display line. Option flags carry no color of their own: "starts with a dash" is a guess about someone else's command grammar (wrong after `--`, blind to `dd if=...`), and on a display about what happens as root, `--no-preserve-root` must not be the faintest thing on the line. Dim therefore means exactly one thing everywhere: *these bytes are sudowhat's, not the command's*. The `directory:` value takes the same dirname/basename split as the program path, and the `user:` value turns yellow when the target is not `root`.

The highlight is **layout, never content**. It stays one logical line, which your terminal soft-wraps: nothing is split into per-option lines, nothing is elided, nothing is reordered — a disclosure tool that abbreviates is worthless. The color sequences go only *around* tokens that `escape_core` has already escaped and quoted, so stripping them returns the plain line byte for byte, and the highlight can neither add nor hide a byte of the command you are about to authorize. Emphasis is not a trust signal (any process that can write your terminal can forge the same bytes), so it is safe to color attacker-influenced content. Select `services.sudowhat.echoColor = "off"` to bake a plain display into the bundle; `NO_COLOR`, `TERM=dumb`, or a non-terminal destination force plain at runtime regardless. There is deliberately **no caller-settable knob** here — see [Standalone by design](#standalone-by-design) — and any failure inside the colorizer falls back to the same line in plain, never to showing nothing.

The audit plugin joins the mutual-signature web — a present-but-tampered audit bundle makes the approval plugin and `pam_sudowhat` fail closed — but it is optional: an absent bundle disables terminal display without affecting authentication (tamper-evident in place, not removal-proof).

## Console vs. non-console callers

sudowhat decides *where* a caller may authenticate by its security session — a local GUI login versus a remote or headless one — not by uid. A caller running as the same user as the console login but over SSH is still treated as non-console.

| Caller | `nonConsole = "password"` (default) | `nonConsole = "deny"` |
|---|---|---|
| Local console (GUI) user | Touch ID prompt showing the command¹ | Touch ID prompt showing the command¹ |
| Interactive remote session (e.g. SSH) | Password / smartcard on the caller's own terminal; no prompt on the console | Denied without a prompt |
| Unattended job (launchd / cron, no GUI) | Runs if a sudoers rule authorizes it (e.g. `NOPASSWD`); no prompt on the console | Denied without a prompt |
| Root (uid 0) | Allowed, logged to the auth log | Allowed, logged to the auth log |

¹ Skipped when sudoers waived authentication for the command — a `NOPASSWD` rule, `Defaults !authenticate`, or a cached credential — so the command just runs (policy deference, on by default; see "How it works"). Turn off with `services.sudowhat.policyDeference = "off"`.

In every case a non-console caller authenticates (if at all) through sudo's own machinery on its own session — it is never shown a biometric / Authorization Services sheet, which would render on the console user's screen (that impossibility is not configurable; see "Non-console defense" above). `nonConsole` grants no authority on its own: sudoers still decides who may run what.

"Non-console" here means a *remote or non-graphical* session. A background process inside your **local GUI login** — e.g. a gui-domain `LaunchAgent` — shares that login's session and is classified as **console**, so it can raise a Touch ID sheet like any process in your session; see [Known limitations](#known-limitations).

## What gets installed

| Path | Purpose |
|------|---------|
| `/usr/local/libexec/sudo/sudowhat_approval.so` | Sudo approval plugin |
| `/usr/local/lib/pam/pam_sudowhat.so` | PAM auth module |
| `/etc/sudo.conf` (one line appended) | Tells sudo to load the approval plugin |
| `/etc/sudoers.d/sudowhat` | Disables sudo's auth cache |
| `/etc/pam.d/sudo_local` | Wires the PAM module into sudo's auth chain |

Apple's stock `/etc/pam.d/sudo` already includes `auth include sudo_local`, so the install survives system updates that touch `/etc/pam.d/sudo`.

## Build modes

**Dev / ad-hoc** (default — no Apple Developer account required):

```sh
make sign
```

Bundles are ad-hoc-signed. `SignatureVerifier` validates that signatures are intact (`kSecCSBasicValidateOnly`) but does not enforce a team-identifier requirement. Tampered or replaced binaries with broken signatures still fail; substitution with a different validly-signed binary is **not** detected. Suitable for personal use.

**Release** (Apple Developer ID, full authorship enforcement):

```sh
make SUDOWHAT_TEAM_ID=XXXXXXXXXX DEVELOPER_NAME="Your Name" sign
```

Bundles are signed with your Developer ID Application certificate. The team-identifier requirement is enforced at runtime: tampering breaks the signature, and replacement with a differently-signed binary is detected.

## Linux (terminal command display)

Linux has no Touch ID, so it gets the **display**, not the biometric. A sudo
**audit plugin** — a single pure-Rust `.so` reusing the same anti-spoofing core
as macOS — prints `user / directory / command` to your terminal *before* sudo's
native `pam_unix` password prompt, so you read the exact command before you type
your password:

```
$ sudo systemctl restart nginx
sudowhat: user: root
sudowhat: directory: /etc/nginx
sudowhat: command: systemctl restart nginx
[sudo] password for alice:
```

**Display-only, by design.** There is no verify code (no GUI sheet to bind one
to), no approval plugin, and no PAM module — sudo's own authentication is
untouched. The trust model is **sudo's own** enforcement: it refuses to load a
plugin, or read `/etc/sudo.conf`, that is not owned by root and writable only by
root (`sudo.conf(5)`), fail-closed. There is **no code-signing anchor and no
tamper-evidence** on Linux (an attacker with root can swap the plugin) — Linux
gets the UX, not the tamper-evidence. The plugin fails soft: no terminal, no
command, or bad input means it shows nothing and never breaks sudo. Every token
is shell-quoted and control-character escaped, written to `/dev/tty` only (never
stderr), and the root invoker is exempt.

**NixOS:**

```nix
{
  inputs.sudowhat.url = "github:jooize/sudowhat";
  # in your configuration:
  imports = [ inputs.sudowhat.nixosModules.default ];
  services.sudowhat.enable = true;
}
```

The module writes `/etc/sudo.conf`. **Important:** on Linux, adding any `Plugin`
line to `sudo.conf` stops sudo from auto-loading its default sudoers policy, so
the file must re-declare the stock `sudoers.so` plugins alongside ours — the
module (and `config/linux/sudo.conf.sample`) does this for you.

**Manual install:**

```sh
make build-linux                 # builds linux/sudowhat_audit → a cdylib .so
sudo make install-linux          # installs the .so, prints the /etc/sudo.conf to write
```

Then write `/etc/sudo.conf` from the printed snippet (or
`config/linux/sudo.conf.sample`). Uninstall with `sudo make uninstall-linux`.

This is Phase 2 (in progress); see `docs/design-linux-port.md`. It has not yet
been exercised on a Linux host — the crate builds, its logic is unit-tested for
byte-for-byte parity with the macOS display, and the on-hardware smoke tests are
listed in the design note.

## Status

| | |
|---|---|
| Latest release | `v0.10.0` |
| Tested on | macOS Tahoe (Darwin 25.4–25.5) |
| Architecture | Apple silicon (arm64) |
| Linux | Phase 2 in progress — audit-plugin display, native PAM password, no tamper-evidence (`docs/design-linux-port.md`) |
| Signing | ad-hoc dev mode shipped; Developer ID release planned |

## Known limitations

These are documented design trade-offs, not bugs.

**A background process in your own GUI login can still prompt.** sudowhat classifies callers by their security session (local-GUI vs. remote / non-graphical), which keeps SSH and system-daemon callers off the console biometric. It cannot, from inside one process, distinguish *you at the keyboard* from another process running inside the *same* GUI login — a gui-domain `LaunchAgent`, a `nohup`/`setsid` job, or a helper of a compromised app all inherit the login session's attributes and are classified as console. Such a process can raise a Touch ID sheet on your screen. The defense against approving one you did not initiate is sudowhat's core design, not the session guard: the prompt shows the **exact command**, and a **verification code** is printed to the terminal that launched sudo — a prompt you did not start shows a command you do not expect and a code on no terminal you can see, so you can reject it. This is the reflexive-approval surface inherent to any in-session biometric; sudowhat narrows it (remote and headless callers are excluded outright) but does not eliminate it.

**The verification code is shown on the controlling terminal.** The code is written directly to `/dev/tty` — the same channel `sudo` uses for its own `Password:` prompt — so no redirection of the command's I/O can hide it: a shell only rewires fds 0–2, leaving the controlling terminal untouched, so `sudo cmd > file`, the `sudo tee file > /dev/null` heredoc idiom, `2>/dev/null`, and `&>` / `>&` all still display the code. It is absent only when the invoking process has **no controlling terminal at all** — an in-session process launched by something other than a shell (the Dock, Spotlight, a GUI agent, or a tool like Claude Code) — in which case the code is simply not printed: it goes to `/dev/tty` or nowhere, never to stderr, so it can neither clutter a captured error stream nor be slurped into a `2>file`. The exact-command display inside the Touch ID sheet is, as always, the redirect-proof primary signal. So treat the code as *positive confirmation* (a matching code means the prompt is the sudo you just launched), never as a gate: a missing code is a cue to read the command in the sheet, not to approve reflexively. For legibility the code is rendered in **bold** on an interactive terminal — bold rather than a color so it survives any terminal theme — but this is emphasis only, never a trust cue: any process that can write the terminal can forge the same bytes, so the anchor stays the code matching the sheet (which is system-rendered and cannot be colored). Set `NO_COLOR` (any value, per [no-color.org](https://no-color.org)) or run with an unset or `dumb` `TERM` to disable it; the echo is always plain when the destination is not a real terminal.

**TOCTOU between approval and execve.** A residual window exists between sudowhat returning "approved" and sudo's `execve` of the resolved binary path. The plugin opens the file before the prompt, re-stats it after, and denies if the `(dev, inode)` pair changed — but a swap occurring after the final stat and before sudo's exec cannot be detected from inside a plugin. macOS lacks `fexecve`, so eliminating this window completely requires patching sudo itself. For binaries on root-only paths (`/bin`, `/usr/bin`, `/usr/sbin`), an attacker capable of writing there already has root and doesn't need TOCTOU.

**Ad-hoc dev mode integrity-only.** In dev mode, any validly signed bundle passes the integrity check. Tampering with content is detected; substitution with a different signed bundle (e.g., an Apple-signed `/bin/ls`) is not. Use a Developer ID release build for any deployment outside personal local use.

**`sudo bash`, interactive editors.** Approving a shell or editor opens unbounded post-approval risk. This is inherent to all sudo-likes; sudowhat shows the program being launched so the user can refuse, but cannot constrain what happens inside it.

**GUI session detached.** `LAContext.evaluatePolicy` may fail when the user's GUI session has been fast-user-switched out. The plugin denies in that case — fail-closed by design.

**Generic icon on the Watch / companion confirmation.** macOS sources the icon shown in the Touch ID prompt and the Apple Watch confirmation notification from the **calling process's** main bundle. The calling process is `sudo` — a CLI binary with no app bundle and no `CFBundleIcon` — so the system falls back to a generic document icon. `LAContext` exposes no public API to override it, and adding an icon to the plugin bundle has no effect (the system queries `sudo`, not the loaded `.so`). Customizing the icon would require shipping a separate signed helper `.app` and IPC'ing the prompt to it, which would reintroduce the agent dependency the current architecture deliberately removes. Trade-off accepted.

**Prompt budget measured in English only.** The prompt formatter keeps its rendered text under a conservative budget (480 chars, ~30 below the ~510-char limit at which `LAContext` silently truncates `localizedReason`). That limit was observed only with the English system prefix (`"sudo" is trying to …`). sudowhat's own prompt text is not localized, so its length is locale-invariant — but it has not been verified whether macOS caps our reason string alone or the *total* sheet text including a longer localized prefix. If you run macOS in another language, sanity-check that a near-maximal command's trailer is not clipped in the Touch ID sheet; if it is, the budget needs lowering. Whenever the sheet does truncate, the full command is already on the controlling terminal from the audit plugin (`services.sudowhat.auditDisplay`, on by default), so the clipped tail stays available regardless of how conservative the budget is.

## Verification matrix

After install, smoke-test the security properties:

```sh
sudo -k && sudo /bin/echo hello                  # happy path
sudo -k && sudo /bin/echo hello                  # cancel; expect "sudowhat: authorization denied"
sudo -k && sudo /bin/echo $'hidden\nsudoers'    # control chars escape literally
sudo /bin/echo first; sudo /bin/echo second      # no auth caching; two prompts
ssh localhost 'sudo -n /bin/echo from-ssh' 2>&1 # SSH attacker guard
sudo -k && sudo sudo /bin/echo nested-root      # inner sudo (caller=root) exempt: one prompt, then logged bypass
sudo make uninstall                              # stock sudo behavior restored
```

See `project_trusted_sudo_prompt.md` for the original design notes and full test matrix.

## Roadmap

- Apple Developer ID release build with notarization.
- Homebrew tap / formula.
- Optional: a small `sudowhat status` CLI for users to inspect install state.

## Disclaimer

sudowhat is an independent project. It is not affiliated with, authorized by, sponsored by, or otherwise approved by Apple Inc.

## License

MIT — see `LICENSE`.
