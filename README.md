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

## Authentication methods

A single dialog accepts any of the following:

- **Touch ID** — fingerprint sensor on the keyboard or external Magic Keyboard.
- **Apple Watch** — double-click the side button while wearing an unlocked, paired watch.
- **iPhone** (companion?) — `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion` is documented to cover iPhone-as-companion since macOS 15, but I have not seen the prompt actually appear on a paired iPhone in testing. Watch is the verified case; iPhone is "the policy theoretically supports it, no evidence it fires."
- **Password fallback** — clicking "Use Password" opens an Authorization Services prompt (the classic lock-icon dialog) with the same command shown, accepting your account password.

The prompt binds to *your* user account, not "System Administrator", so your password works in the fallback. (sudo runs as root by the time the plugin executes; sudowhat drops EUID to your user around the auth call so biometric and password both resolve against your enrollment.)

## Quick start

Build, sign, install. Requires macOS with Xcode Command Line Tools.

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

This restores stock sudo behavior, removing all four files sudowhat installs.

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
          # Let SSH / unattended callers sudo via a password on their own
          # terminal (default false = local console Touch ID only). See
          # "Console vs. non-console callers".
          # services.sudowhat.allowNonConsole = true;
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

`install.sh` refuses to overwrite `/etc` files that are symlinks into `/nix/store` (nix-darwin's signature), pointing you at one of the above flows. Override with `make install-force` if you really mean to clobber them.

## How it works

Two signed Mach-O bundles loaded into sudo's process, mutually verifying each other's code signature. No daemon, no agent, no IPC.

```
sudo /usr/bin/foo bar
  │
  ▼  PAM auth chain
/etc/pam.d/sudo
  └── auth include sudo_local
      └── /etc/pam.d/sudo_local
          ├── auth requisite  /usr/local/lib/pam/pam_sudowhat.so
          │     • parses /etc/sudo.conf, confirms our Plugin line is present
          │     • SecStaticCodeCheckValidity on the approval plugin bundle
          │     • returns PAM_SUCCESS (-> sufficient pam_permit -> done)
          │              or PAM_AUTH_ERR (-> sudo aborts)
          └── auth sufficient pam_permit.so
  │
  ▼  sudo loads approval plugin
/etc/sudo.conf
  └── Plugin sudowhat_approval_plugin /usr/local/libexec/sudo/sudowhat_approval.so
      • SecStaticCodeCheckValidity on pam_sudowhat.so (mutual)
      • uid 0 (root) caller: exempt — system automation, not escalation
      • else: caller must be the LOCAL CONSOLE session — SessionGetInfo()
        reports graphic access and is not remote, and the console UID equals
        the invoking UID. A non-console caller is denied (or, with
        allowNonConsole, allowed without a sheet — see below).
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

With `services.sudowhat.allowNonConsole` enabled, the second `sudo_local` line
becomes `auth sufficient pam_sudowhat.so console-gate` instead of `pam_permit.so`.
That console-gate succeeds (no password) **only** for the local console user, and
fails for everyone else — so a non-console caller falls through the parent
`/etc/pam.d/sudo` chain to sudo's native `pam_smartcard` / `pam_opendirectory`
password on the caller's *own* terminal, and the approval plugin steps aside for
them (no sheet) once sudo has authenticated them.

**Trust root:** Apple Developer ID code signing. In a release build, `SignatureVerifier` enforces the team-identifier requirement `anchor apple generic and certificate leaf[subject.OU] = "<TEAM_ID>"`. Forging the integrity check requires forging your developer signature.

**Fail-closed:** any failure of either component aborts sudo. No path leads to `pam_opendirectory`-style permissive defaults. Apple's stock `pam_tid.so` is the broken behavior we're fixing — falling back to it would be regression, not recovery.

**Non-console defense (SSH, automation).** Before prompting, the plugin classifies the caller by its **security session**, not by uid: a local GUI login has graphic access and is not remote, whereas an SSH session is remote and a non-graphical (system-daemon) session lacks graphic access (`SessionGetInfo`). A uid comparison alone cannot tell them apart — the same user, logged in at the Mac and over SSH, shares one uid — and a same-uid SSH session can otherwise render a Touch ID sheet on the console screen. A non-console caller therefore never reaches the biometric / Authorization Services path. By default it is **denied without a prompt**. With `services.sudowhat.allowNonConsole` enabled it is instead routed to sudo's own password / smartcard factor on the caller's *own* terminal — never a sheet on the console — and the plugin steps aside once sudo has authenticated it. This separates *local-GUI* callers from *remote/headless* ones; it does **not** separate the human from another process inside the same GUI login (a background gui-domain agent is treated as console — see [Known limitations](#known-limitations)). See [Console vs. non-console callers](#console-vs-non-console-callers).

**Root callers are exempt — by design.** sudowhat gates *escalation*: an unprivileged principal reaching for root. A caller that is already root (uid 0) is not escalating, and a sudo plugin loaded inside a root process cannot meaningfully constrain root anyway — root can run the command directly, rewrite `/etc/sudo.conf`, or unload the plugin. Gating root would add no security while breaking legitimate root-context automation that shells out through sudo: nix-darwin / home-manager per-user activation runs as root and invokes `launchctl asuser <uid> sudo -u <user>` (invoking uid 0); the same pattern appears in launchd jobs and installer postinstall scripts, and these are non-interactive (no human to answer a prompt). So a uid-0 caller is allowed without a prompt, and the bypass is logged to the auth log (`syslog`/`LOG_AUTHPRIV`) so it is auditable rather than silent. The console gate still applies to every non-root caller — which is the entire population the gate can actually defend against.

**Per-command auth:** `Defaults timestamp_timeout=0` in `/etc/sudoers.d/sudowhat` disables sudo's auth cache, so every privileged command re-prompts. The value is configurable via `services.sudowhat.timestampTimeout`; the module never sets `timestamp_type=global`.

## Console vs. non-console callers

sudowhat decides *where* a caller may authenticate by its security session — a local GUI login versus a remote or headless one — not by uid. A caller running as the same user as the console login but over SSH is still treated as non-console.

| Caller | Default (`allowNonConsole = false`) | With `allowNonConsole = true` |
|---|---|---|
| Local console (GUI) user | Touch ID prompt showing the command | Touch ID prompt showing the command |
| Interactive remote session (e.g. SSH) | Denied without a prompt | Password / smartcard on the caller's own terminal; no prompt on the console |
| Unattended job (launchd / cron, no GUI) | Denied without a prompt | Runs if a sudoers rule authorizes it (e.g. `NOPASSWD`); no prompt on the console |
| Root (uid 0) | Allowed, logged to the auth log | Allowed, logged to the auth log |

In every case a non-console caller authenticates (if at all) through sudo's own machinery on its own session — it is never shown a biometric / Authorization Services sheet, which would render on the console user's screen. `allowNonConsole` grants no authority on its own: sudoers still decides who may run what.

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

## Status

| | |
|---|---|
| Latest release | `v0.5.2` |
| Tested on | macOS Tahoe (Darwin 25.4) |
| Architecture | Apple silicon (arm64) |
| Signing | ad-hoc dev mode shipped; Developer ID release planned |

## Known limitations

These are documented design trade-offs, not bugs.

**A background process in your own GUI login can still prompt.** sudowhat classifies callers by their security session (local-GUI vs. remote / non-graphical), which keeps SSH and system-daemon callers off the console biometric. It cannot, from inside one process, distinguish *you at the keyboard* from another process running inside the *same* GUI login — a gui-domain `LaunchAgent`, a `nohup`/`setsid` job, or a helper of a compromised app all inherit the login session's attributes and are classified as console. Such a process can raise a Touch ID sheet on your screen. The defense against approving one you did not initiate is sudowhat's core design, not the session guard: the prompt shows the **exact command**, and a **verification code** is printed to the terminal that launched sudo — a prompt you did not start shows a command you do not expect and a code on no terminal you can see, so you can reject it. This is the reflexive-approval surface inherent to any in-session biometric; sudowhat narrows it (remote and headless callers are excluded outright) but does not eliminate it.

**The verification code is shown on the controlling terminal.** The code is written directly to `/dev/tty` — the same channel `sudo` uses for its own `Password:` prompt — so no redirection of the command's I/O can hide it: a shell only rewires fds 0–2, leaving the controlling terminal untouched, so `sudo cmd > file`, the `sudo tee file > /dev/null` heredoc idiom, `2>/dev/null`, and `&>` / `>&` all still display the code. It is absent only when the invoking process has **no controlling terminal at all** — an in-session process launched by something other than a shell (the Dock, Spotlight, a GUI agent) — in which case it falls back to sudo's stderr. The exact-command display inside the Touch ID sheet is, as always, the redirect-proof primary signal. So treat the code as *positive confirmation* (a matching code means the prompt is the sudo you just launched), never as a gate: a missing code is a cue to read the command in the sheet, not to approve reflexively.

**TOCTOU between approval and execve.** A residual window exists between sudowhat returning "approved" and sudo's `execve` of the resolved binary path. The plugin opens the file before the prompt, re-stats it after, and denies if the `(dev, inode)` pair changed — but a swap occurring after the final stat and before sudo's exec cannot be detected from inside a plugin. macOS lacks `fexecve`, so eliminating this window completely requires patching sudo itself. For binaries on root-only paths (`/bin`, `/usr/bin`, `/usr/sbin`), an attacker capable of writing there already has root and doesn't need TOCTOU.

**Ad-hoc dev mode integrity-only.** In dev mode, any validly signed bundle passes the integrity check. Tampering with content is detected; substitution with a different signed bundle (e.g., an Apple-signed `/bin/ls`) is not. Use a Developer ID release build for any deployment outside personal local use.

**`sudo bash`, interactive editors.** Approving a shell or editor opens unbounded post-approval risk. This is inherent to all sudo-likes; sudowhat shows the program being launched so the user can refuse, but cannot constrain what happens inside it.

**GUI session detached.** `LAContext.evaluatePolicy` may fail when the user's GUI session has been fast-user-switched out. The plugin denies in that case — fail-closed by design.

**Generic icon on the Watch / companion confirmation.** macOS sources the icon shown in the Touch ID prompt and the Apple Watch confirmation notification from the **calling process's** main bundle. The calling process is `sudo` — a CLI binary with no app bundle and no `CFBundleIcon` — so the system falls back to a generic document icon. `LAContext` exposes no public API to override it, and adding an icon to the plugin bundle has no effect (the system queries `sudo`, not the loaded `.so`). Customizing the icon would require shipping a separate signed helper `.app` and IPC'ing the prompt to it, which would reintroduce the agent dependency the current architecture deliberately removes. Trade-off accepted.

**Prompt budget measured in English only.** The prompt formatter keeps its rendered text under a conservative budget (480 chars, ~30 below the ~510-char limit at which `LAContext` silently truncates `localizedReason`). That limit was observed only with the English system prefix (`"sudo" is trying to …`). sudowhat's own prompt text is not localized, so its length is locale-invariant — but it has not been verified whether macOS caps our reason string alone or the *total* sheet text including a longer localized prefix. If you run macOS in another language, sanity-check that a near-maximal command's trailer is not clipped in the Touch ID sheet; if it is, the budget needs lowering.

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
