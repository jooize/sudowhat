# Security design

The full security rationale for sudowhat: the trust chain, the caller
classification, the policy-deference decision, the terminal ceremony, and the
limits of each. The [README](../README.md) summarizes; this document is the
argument. Individual decisions have their own design docs under `docs/`
(non-console handling in `design-noncon-sudo.md`, the resolved `execute:` line
in `design-resolved-exec.md`, the Linux port in `design-linux-port.md`);
this file is the connected overview.

## Architecture

Three signed Mach-O bundles loaded into sudo's own process — a PAM module, an
approval plugin, and an audit plugin — mutually verifying each other's code
signature. No daemon, no agent, no IPC. Everything below happens inside one
`sudo` invocation.

The audit plugin joins the mutual-signature web (a present-but-tampered audit
bundle makes the approval plugin and `pam_sudowhat` fail closed), but it is
optional: an absent bundle disables terminal display without affecting
authentication (tamper-evident in place, not removal-proof).

## The pipeline

```
sudo /usr/bin/foo bar
  │
  ▼  sudo runs the audit plugin's open() FIRST, before any auth
/etc/sudo.conf
  └── Plugin sudowhat_audit_plugin /usr/local/libexec/sudo/sudowhat_audit.so
      • SecStaticCodeCheckValidity on pam_sudowhat.so + the approval plugin
      • writes run as / directory / input to /dev/tty -- every path,
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
      • uid 0 (root) caller: exempt -- system automation, not escalation
      • else: caller must be the LOCAL CONSOLE session -- SessionGetInfo()
        reports graphic access and is not remote, and the console UID equals
        the invoking UID. A non-console caller never reaches this sheet: it is
        sent to a native password (nonConsole="password", default) or denied
        (nonConsole="deny") -- see below.
      • formats the command with shell-quoting and control-char escapes
      • writes the verify code and the resolved execute: line to /dev/tty --
        before the sheet in biometric mode; execute: after the password on
        the terminal path
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
fails for everyone else, so a non-console caller falls through the parent
`/etc/pam.d/sudo` chain to sudo's native `pam_smartcard` / `pam_opendirectory`
password on the caller's *own* terminal, and the approval plugin steps aside for
them (no sheet) once sudo has authenticated them. Set `nonConsole = "deny"` to
install `auth sufficient pam_permit.so` instead, which terminates the chain with
no password path, so the approval plugin denies every non-console caller.

## Trust root

Apple Developer ID code signing. In a release build the team ID is compiled
into each bundle, and `SignatureVerifier` enforces this requirement on every
peer it checks:

```
anchor apple generic                                     -- chains to Apple's root
and certificate 1[field.1.2.840.113635.100.6.2.6]        -- via the Developer ID CA
and certificate leaf[field.1.2.840.113635.100.6.1.13]    -- to a Developer ID Application leaf
and certificate leaf[subject.OU] = "<TEAM_ID>"           -- issued to YOUR team
and identifier "<bundle>"                                -- signed as THIS bundle
```

So a valid signature from another developer fails (wrong team), a same-team
Apple *Development* certificate fails (wrong certificate flavor; those are
mintable by any team member), and a different binary your own team signed fails
(wrong identifier). Defeating the check needs a Developer ID certificate Apple
issued to your team, signing an impostor under this bundle's exact identifier.
This is a release-build property only: the default dev build validates
signature integrity but enforces no requirement, so any intact signature passes
there (see the README's Build modes). In all builds the check is tamper
*evidence* inside the mutual-signature web, not a barrier against root:
replacing a root-owned bundle already requires root, which could equally
disable the check.

## Fail-closed

Any failure of either component aborts sudo. No path leads to
`pam_opendirectory`-style permissive defaults. Apple's stock `pam_tid.so` is
the broken behavior we're fixing: falling back to it would be regression, not
recovery.

## Non-console defense (SSH, automation)

sudowhat's core job is to show you what will run and prove it came from your
terminal; because it sits in the auth path, it *also* decides *where* a caller
may authenticate. It classifies the caller by its **security session**, not by
uid: a local GUI login has graphic access and is not remote, whereas an SSH
session is remote and a non-graphical (system-daemon) session lacks graphic
access (`SessionGetInfo`). A uid comparison alone cannot tell them apart (the
same user, logged in at the Mac and over SSH, shares one uid), and a same-uid
SSH session could otherwise render a Touch ID sheet on the console screen.

**A non-console caller is never shown the biometric / Authorization Services
sheet. This is structural, not a setting, and deliberately not configurable.**
A Touch ID sheet raised for a remote or background caller renders on the
*console* user's screen, and that user reflexively approves a command they
never initiated. That reflexive approval is the exact hole sudowhat exists to
close, so there is no option to permit it: the code returns before the
`LAContext` call for any non-console caller (with a maintainer tripwire
forbidding its reordering). It could not do anything useful anyway: the remote
human isn't at the sensor, so a local sheet can never represent *them*
authenticating; whoever is at the console would be approving on the remote
caller's behalf. The only honest remote factor is a password *they* know on
*their* terminal. (Genuine remote biometric would need an out-of-band push to
the caller's own device, a daemon design this project rejected.)

So a non-console caller authenticates, if at all, through sudo's own machinery
on its own session. By default (`nonConsole = "password"`) that is sudo's
native password / smartcard factor: stock sudo behaviour, kept intact. Set
`nonConsole = "deny"` to refuse non-console callers entirely (a stolen password
alone then can't escalate remotely, at the cost of remote / headless sudo).
This split separates *local-GUI* callers from *remote/headless* ones; it does
**not** separate the human from another process inside the same GUI login (a
background gui-domain agent is treated as console; see
[Limitations](#limitations)).

## Root callers are exempt by design

sudowhat gates *escalation*: an unprivileged principal reaching for root. A
caller that is already root (uid 0) is not escalating, and a sudo plugin loaded
inside a root process cannot meaningfully constrain root anyway: root can run
the command directly, rewrite `/etc/sudo.conf`, or unload the plugin. Gating
root would add no security while breaking legitimate root-context automation
that shells out through sudo: nix-darwin / home-manager per-user activation
runs as root and invokes `launchctl asuser <uid> sudo -u <user>` (invoking uid
0); the same pattern appears in launchd jobs and installer postinstall scripts,
and these are non-interactive (no human to answer a prompt). So a uid-0 caller
is allowed without a prompt, and the bypass is logged to the auth log
(`syslog`/`LOG_AUTHPRIV`) so it is auditable rather than silent. The console
gate still applies to every non-root caller, which is the entire population
the gate can actually defend against.

## Policy deference (console NOPASSWD skip)

The approval plugin runs on *every* `sudo` that sudoers authorizes (`NOPASSWD`
does not bypass it), so without this, the console user would get a Touch ID
sheet even for a command sudoers authorized `NOPASSWD`. sudowhat instead
**defers to sudoers' own authentication decision**: sudo runs the PAM auth
stack (where `pam_sudowhat` sets a process-local marker) only when it requires
authentication, so an *absent* marker means sudoers waived it (a `NOPASSWD`
rule, `Defaults !authenticate`, a root invoker, or a valid credential in the
timestamp cache). On an absent marker (with `pam_sudowhat` still wired into
`sudo_local`, which the plugin re-checks), the console user's prompt is
**skipped and the command just runs**. This is an authorization-trust decision
that inherits sudoers' choice rather than re-implementing it: no command
allowlist, no drift. It is fail-safe in every uncertain direction: a present
marker, an unverifiable chain, or `policyDeference = "off"` all result in a
prompt, and a caller can only ever *force* a prompt by manipulating its
environment, never suppress one. Even on a skipped run the audit plugin has
already shown run as / directory / input on the terminal (it runs before this
decision), so a `NOPASSWD` command is still disclosed. Turn the whole behavior
off with `services.sudowhat.policyDeference = "off"`.

## Per-command auth

`Defaults timestamp_timeout=0` in `/etc/sudoers.d/sudowhat` disables sudo's
auth cache, so every privileged command re-prompts. The value is configurable
via `services.sudowhat.timestampTimeout`; the module never sets
`timestamp_type=global`. Note this composes with policy deference: with a
non-zero timeout, a second command within the window on the same terminal has a
cached credential (auth stack skipped, marker absent) and so runs with no
sheet, sudo's normal grace after the first real factor. Keep the default `0`
for a Touch ID sheet on every command.

## The terminal ceremony

### Verify-code emphasis

The code echoed to the controlling terminal is **bold magenta**, fixed: there
is no setting for it. One reviewed escape sequence is the only one that can
reach your terminal on this line, so there is nothing to misconfigure, and the
emphasis is cosmetic in the first place: never a trust signal, since the anchor
is the code matching the system-rendered Touch ID sheet, which cannot be
colored. The runtime opt-outs are unchanged: `NO_COLOR` or `TERM`
absent/empty/`dumb` in the invoking environment, a non-terminal destination, or
the stderr fallback all render the line plain.

### Terminal command display (audit plugin)

The audit plugin shows the command on the controlling terminal **before
authentication, on every path**: the local console (before the Touch ID sheet
and its verify code) and non-console / SSH sessions (before sudo's native
password prompt). This closes the gap where a non-console sudo used to step
aside silently, showing a bare `Password:` with no command. It prints
`run as:`, `directory:` (the working directory), and `input:` (the command
exactly as you typed it), each shell-quoted and control-character escaped by
the memory-safe Rust `escape_core`, so no raw control byte reaches the
terminal. When the command you typed is a **bare name**, one more row follows
it: `path:`, the `PATH` your shell handed sudo. That list is the
attacker-influenceable surface that steers how a bare name resolves. It is not
a claim about the *final* resolution `PATH` (a sudoers `secure_path` can
override it) and sudowhat never walks the list or says which entry would win;
`execute:` below still shows the outcome. What the row buys is disclosure
**before the gate** on the password path, where `execute:` cannot appear until
your password is already spent, so it prints wherever the block prints, at the
cost of being mildly redundant on a biometric console, where `execute:` already
appears before the sheet. Type an absolute or relative path and the row is
absent, because `PATH` decided nothing. It is written to `/dev/tty` only
(never sudo's stderr), so a `2>file` redirect cannot capture it, and it is
skipped when there is no controlling terminal (headless). Once sudo has
resolved the command, the approval plugin adds one more row, `execute:`. It is
the absolute path sudo will actually execute, read out of sudo's own
`command_info` and never resolved plugin-side. In biometric mode it prints
*before* the Touch ID sheet is raised; on the terminal-password path (where
the password happens inside sudo's policy step) it prints after auth, as a
last look. `input:` states what was asked for and `execute:` what sudo found,
so a bare name shadowed by an unexpected `PATH` entry shows up as the two
simply disagreeing, with no heuristic to tune. Because the full command is
already on the terminal, when the Touch ID sheet has to replace an over-long
item (past its ~480-char budget) with a `(see terminal)` marker, the marker
always points at something, including the resolved path the sheet could not
fit. The display is disclosure only, never a trust signal: any process that
can write your terminal can forge the same bytes, so the anchor stays the
verify code matching the system-rendered sheet (biometric) or sudo's own PAM
(terminal). Turn it off with `services.sudowhat.auditDisplay = "off"`. The
`execute:` row has its own switch, `services.sudowhat.execDisplay` (`"on"` by
default). The two display settings map one per line family: `auditDisplay` for
the pre-auth block, `execDisplay` for the resolved line. Setting it to `"off"`
silences `execute:` everywhere it appears, the root-initiated solo line
included; the plugin still loads and gates exactly as before, it just stops
narrating. The one deliberate exception is the `execConfirm` ceremony below,
which keeps printing the line it is asking about.

### The label gutter and role highlighting

Every row shares one label gutter, so `run as`, `directory`, `input`, `path`,
`execute` and the verify code all start in the same column. One line is
deliberately outside it: a root-initiated sudo gets no `input:` block (uid 0 is
exempt from the audit display) and no verify code, so its lone `execute:` line
drops the padding rather than aligning against a column of one. The `execute:`
value is **highlighted by role** so the token worth reading is not buried in
the wrap: the program's directory part in plain cyan and its basename in bold
cyan, option flags bold blue, every other token plain, the quotes sudowhat
itself added dim. Anomalous spans take the palette above them: deceptive
Unicode escapes red, control-byte escapes magenta, shell metacharacters cyan,
and notable whitespace runs (leading, trailing, or doubled spaces) on a grey
background **inside the program token only**. That last mark is scoped to the
thing that will execute, because that is where invisible padding changes the
outcome; on argument tokens it was drowning the line: a script passed as one
argument (`sh -c '…'`) turned every escaped newline's indentation into a grey
block. Those bytes still render escaped and quoted with or without it. The
`input:` value goes through the same renderer with one difference: its
**routine tokens all render dim** (program, flags and values alike), and only
the anomalous spans keep full strength. `input:` quiet, `execute:` loud,
anomalies at full strength on both: the resolved line is the one that says
what actually happens as root, the pre-resolution line sits under it, and
against that flat dim base an anomaly is the only colored thing on the row. A
hostile argument spelled like one of sudowhat's own lines
(`'sudowhat: run as: evil'`) still lands quoted and colored as data on either
line, visibly not a real display line. Option flags (a rendered token starting
with `-`) are bold blue on `execute:`, a lexical mark, deliberately without
judgement: "starts with a dash" says nothing about which flag matters (`-rf`
looks like a flag, `if=/dev/zero` does not), so every flag takes the same
colour and none renders dimmer than the command it modifies; hostile input
cannot borrow the look, because a token that needed quoting renders as `'...'`:
leading quote, not dash. On the `execute:` line dim still means exactly one
thing: *these bytes are sudowhat's, not the command's*. On `input:` the whole
routine content is dim, so the quotes there no longer stand out from what they
wrap; quote attribution stays legible on the `execute:` line, which renders
the same tokens through the same walk. The `directory:` value takes the same
dirname/basename split as the program path, and the `run as:` value turns
yellow when the target is not `root`. The `path:` value renders plain: it is
one opaque string rather than a token walk, and the colors the frame spends
elsewhere already mean specific things.

The highlight is **layout, never content**. It stays one logical line, which
your terminal soft-wraps: nothing is split into per-option lines, nothing is
elided, nothing is reordered: a disclosure tool that abbreviates is worthless.
The color sequences go only *around* tokens that `escape_core` has already
escaped and quoted, so stripping them returns the plain line byte for byte, and
the highlight can neither add nor hide a byte of the command you are about to
authorize. Both values come out of **one shared walk** over one token list
(the two weights are two base palettes, not two renderers), so `input:` and
`execute:` can never disagree about which tokens the command has or how a token
is spelled; a difference you see between the two lines is a real difference in
the command. Emphasis is not a trust signal (any process that can write your
terminal can forge the same bytes), so it is safe to color
attacker-influenced content. Select `services.sudowhat.echoColor = "off"` to
bake plain command lines into the bundles. It governs both `input:` and
`execute:`, since they are one display to a reader, and leaves the frame around
them (labels, gutter, the verify code's emphasis) alone; `NO_COLOR`,
`TERM=dumb`, or a non-terminal destination force plain at runtime regardless.
There is deliberately **no caller-settable knob** here (see the README's
"Standalone by design"), and any failure inside the colorizer falls back to the
same line in plain, never to showing nothing.

### Confirm after the resolved line (`execConfirm`, off by default)

In biometric mode the decision already completes with the resolved path in
view: `execute:` prints before the sheet is raised. The terminal-password path
cannot do that (sudo resolves the command inside the same policy step that
collects the password), so there `execute:` is a last look rather than a
preview. Setting `services.sudowhat.execConfirm = "on"` closes the asymmetry by
splitting the decision in two: after sudo has authenticated you, the approval
plugin prints `execute:` and asks one `sudowhat: run? [y/N] ` on your terminal,
so the last word is given with the resolved path on screen. No password ever
touches plugin code: this is a confirmation, not an authentication. The prompt
is tty-gated: no controlling terminal means no prompt, so piped and unattended
invocations behave identically with the setting on or off. The name is
literal: the question follows *your* authentication, so it is asked only when
sudo actually collected a factor for that invocation, detected through the
same in-process PAM marker policy deference uses (a caller can add the marker
but never remove it, so its absence cannot be forged). A run sudoers waived
authentication for is therefore never re-gated (a `NOPASSWD` rule,
`Defaults !authenticate`, or, within a non-zero
`services.sudowhat.timestampTimeout` window, a still-cached credential),
terminal or not; at the default timeout of `0` every command authenticates and
so every command is asked. Declining is a quiet abort (nothing wedges; re-run
at will). It applies to the terminal-password path only, it is baked into the
signed bundle at build time like every other sudowhat setting, and the default
`"off"` keeps the plain last look.

## Limitations

These are documented design trade-offs, not bugs. The README carries the short
form; this is the full argument for each.

**A background process in your own GUI login can still prompt.** sudowhat
classifies callers by their security session (local-GUI vs. remote /
non-graphical), which keeps SSH and system-daemon callers off the console
biometric. It cannot, from inside one process, distinguish *you at the
keyboard* from another process running inside the *same* GUI login: a
gui-domain `LaunchAgent`, a `nohup`/`setsid` job, or a helper of a compromised
app all inherit the login session's attributes and are classified as console.
Such a process can raise a Touch ID sheet on your screen. The defense against
approving one you did not initiate is sudowhat's core design, not the session
guard: the prompt shows the **exact command**, and a **verification code** is
printed to the terminal that launched sudo. A prompt you did not start shows a
command you do not expect and a code on no terminal you can see, so you can
reject it. This is the reflexive-approval surface inherent to any in-session
biometric; sudowhat narrows it (remote and headless callers are excluded
outright) but does not eliminate it.

**The verification code is shown on the controlling terminal.** The code is
written directly to `/dev/tty` (the same channel `sudo` uses for its own
`Password:` prompt), so no redirection of the command's I/O can hide it: a
shell only rewires fds 0–2, leaving the controlling terminal untouched, so
`sudo cmd > file`, the `sudo tee file > /dev/null` heredoc idiom,
`2>/dev/null`, and `&>` / `>&` all still display the code. It is absent only
when the invoking process has **no controlling terminal at all**: an
in-session process launched by something other than a shell (the Dock,
Spotlight, a GUI agent, or a tool like Claude Code). In that case the code is
simply not printed: it goes to `/dev/tty` or nowhere, never to stderr, so it
can neither clutter a captured error stream nor be slurped into a `2>file`. The
exact-command display inside the Touch ID sheet is, as always, the
redirect-proof primary signal. So treat the code as *positive confirmation* (a
matching code means the prompt is the sudo you just launched), never as a gate:
a missing code is a cue to read the command in the sheet, not to approve
reflexively. For legibility the code is rendered in **bold** on an interactive
terminal (bold rather than a color, so it survives any terminal theme), but
this is emphasis only, never a trust cue: any process that can write the
terminal can forge the same bytes, so the anchor stays the code matching the
sheet (which is system-rendered and cannot be colored). Set `NO_COLOR` (any
value, per [no-color.org](https://no-color.org)) or run with an unset or `dumb`
`TERM` to disable it; the echo is always plain when the destination is not a
real terminal.

**TOCTOU between approval and execve.** A residual window exists between
sudowhat returning "approved" and sudo's `execve` of the resolved binary path.
The plugin opens the file before the prompt, re-stats it after, and denies if
the `(dev, inode)` pair changed, but a swap occurring after the final stat and
before sudo's exec cannot be detected from inside a plugin. macOS lacks
`fexecve`, so eliminating this window completely requires patching sudo itself.
For binaries on root-only paths (`/bin`, `/usr/bin`, `/usr/sbin`), an attacker
capable of writing there already has root and doesn't need TOCTOU.

**Ad-hoc dev mode integrity-only.** In dev mode, any validly signed bundle
passes the integrity check. Tampering with content is detected; substitution
with a different signed bundle (e.g., an Apple-signed `/bin/ls`) is not. Use a
Developer ID release build for any deployment outside personal local use.

**`sudo bash`, interactive editors.** Approving a shell or editor opens
unbounded post-approval risk. This is inherent to all sudo-likes; sudowhat
shows the program being launched so the user can refuse, but cannot constrain
what happens inside it.

**GUI session detached.** `LAContext.evaluatePolicy` may fail when the user's
GUI session has been fast-user-switched out. The plugin denies in that case,
fail-closed by design.

**Generic icon on the Watch / companion confirmation.** macOS sources the icon
shown in the Touch ID prompt and the Apple Watch confirmation notification from
the **calling process's** main bundle. The calling process is `sudo` (a CLI
binary with no app bundle and no `CFBundleIcon`), so the system falls back to a
generic document icon. `LAContext` exposes no public API to override it, and
adding an icon to the plugin bundle has no effect (the system queries `sudo`,
not the loaded `.so`). Customizing the icon would require shipping a separate
signed helper `.app` and IPC'ing the prompt to it, which would reintroduce the
agent dependency the current architecture deliberately removes. Trade-off
accepted.

**Prompt budget measured in English only.** The prompt formatter keeps its
rendered text under a conservative budget (480 chars, ~30 below the ~510-char
limit at which `LAContext` silently truncates `localizedReason`). That limit
was observed only with the English system prefix (`"sudo" is trying to …`).
sudowhat's own prompt text is not localized, so its length is locale-invariant,
but it has not been verified whether macOS caps our reason string alone or
the *total* sheet text including a longer localized prefix. If you run macOS in
another language, sanity-check that a near-maximal command's trailer is not
clipped in the Touch ID sheet; if it is, the budget needs lowering. Whenever
the sheet does truncate, the full command is already on the controlling
terminal from the audit plugin (`services.sudowhat.auditDisplay`, on by
default), so the clipped tail stays available regardless of how conservative
the budget is.
