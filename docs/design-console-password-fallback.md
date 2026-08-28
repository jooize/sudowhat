# Design note: console password fallback (consoleNoBiometric)

**Status: rejected (2026-08-28); kept as the record.** Designed the same
day, then declined on implementation risk: the decision point is
`pam_sudowhat`, and probing LocalAuthentication from PAM context carries the
hazards under "Implementation risk" below — a coreauthd hang there hangs
every sudo on the machine — for a UX preference the GUI password dialog
already serves more defensibly (see "Why the default stays `dialog`"). The
dialog-timeout extension for case 4 was rejected separately, in its own
section. Nothing in this note ships: a biometric-less console keeps today's
behavior, the system password dialog.

## The rejected design

Add `services.sudowhat.consoleNoBiometric = "dialog" | "password"` (default
`"dialog"`). It chooses what the **local console user** gets when biometric
and companion authentication are **unavailable** — no usable Touch ID sensor
and no paired watch, as reported by `canEvaluatePolicy` — as opposed to
failed, locked out, or cancelled:

- `"dialog"` (default; today's behavior): LocalAuthentication tiering falls
  to `LAPolicyDeviceOwnerAuthentication` and the system password dialog
  carries the command and verify code, exactly as now.
- `"password"`: the console-gate declines instead of short-circuiting, the
  caller falls through to sudo's native password stack on their own terminal
  — the same path a non-console caller takes — and the approval plugin steps
  aside once sudo has authenticated them. The full terminal ceremony is
  preserved: the audit block, the resolved `execute:` line, and (if enabled)
  the `execConfirm` post-auth `run? [y/N]`.

Baked into the signed bundles at build time like every other setting.

## Problem

Four scenarios where the console user cannot, or would rather not, complete
the biometric dialog. They split sharply on detectability:

1. **No biometric hardware and no watch** (Mac mini / Studio with a
   third-party keyboard). Today every sudo raises the GUI *password* dialog.
   Some operators prefer typing at the terminal they are already in.
   Detectable: `canEvaluatePolicy` reports availability, not outcome.
2. **Docked laptop, lid closed, third-party keyboard, no watch.** Same as 1
   in every way that matters, and equally detectable.
3. **Fast-user-switched-out or locked session.** The dialog cannot render;
   the plugin denies, fail-closed. Nobody is at that terminal either, so a
   terminal prompt gains nothing. Out of scope; deny stays correct.
4. **SSH, then attach to a tmux/screen server started at the console.** The
   sudo runs in the console security session, so the dialog renders on the
   physical screen — which nobody is watching. Undetectable from inside:
   LocalAuthentication sees a healthy, available GUI session. Not solved
   here; see "Case 4" below.

This option addresses 1 and 2 only.

## Mechanics

Mirrors the non-console flow; no new trust machinery.

- **`pam_sudowhat` console-gate.** Today the gate variant returns
  `PAM_SUCCESS` for the console user, which is what suppresses the native
  password. Under `consoleNoBiometric = "password"` it additionally probes
  availability — an EUID-dropped `canEvaluatePolicy` with the same tiering
  the approval plugin uses — and returns failure when neither biometric nor
  companion is available, so the parent `/etc/pam.d/sudo` chain falls
  through to `pam_smartcard` / `pam_opendirectory` on the caller's terminal.
- **Approval plugin.** Re-derives the availability answer itself — it never
  trusts the PAM module's conclusion — and steps aside only when all three
  hold: the setting is `"password"`, its own probe agrees biometric is
  unavailable, and the in-process PAM marker shows sudo actually ran the
  auth stack for this invocation. Marker, step-aside, and ceremony are the
  existing non-console code paths.
- **Requires `nonConsole = "password"` — plumbing, not policy.** `nonConsole`
  sounds like policy for remote callers, but its values install different
  PAM plumbing: `"password"` installs the gate variant, whose fall-through
  to sudo's native password modules is the rails this feature rides;
  `"deny"` installs the `pam_permit` variant, which ends the chain so
  nobody is ever prompted — that is precisely how "denied without a
  prompt" is achieved, and it leaves no password stack in the chain for
  the console user to fall through to. Building the rails under deny
  semantics is worse than the coupling: SSH callers would be prompted for
  a password that is always discarded afterward — collecting credentials
  that are never honored. The module asserts the pairing at eval time
  rather than install a configuration that can only deny.

## Implementation risk (why this needs a spike)

The console-gate lives in `pam_sudowhat`, so declining at PAM time means
linking LocalAuthentication into the PAM module and calling
`canEvaluatePolicy` inside sudo's setuid-root PAM phase. Three hazards, none
fatal, all spike-gated:

1. **Framework reachability from PAM context.** LocalAuthentication talks
   to `coreauthd` over Mach IPC, and PAM runs early, in a setuid process,
   sometimes under restricted bootstrap contexts (SSH, launchd, early
   boot). A daemon unreachable from there can error oddly — or hang, and a
   hang in PAM hangs every sudo on the machine. Precedent in this repo:
   `design-nonconsole-sudo.md` flagged `SCDynamicStore`-in-PAM as
   configd-reachability-sensitive, the same failure class. Hardware spike
   before trust, as policy-deference got.
2. **Growth of the trusted core.** `pam_sudowhat` is deliberately tiny
   (integrity checks plus the console gate). Linking LocalAuthentication
   pulls that framework and its dependencies into the auth-critical path
   of every sudo, even for configurations that never enable the option.
3. **Two probes that can disagree.** The PAM module and the approval
   plugin probe availability independently (the plugin never trusts the
   module's conclusion). Different moments or contexts can yield different
   answers — "PAM fell through to password but the plugin's probe says
   biometric is available" — and every such state needs a specified,
   fail-closed resolution before this ships.

## Security analysis

**The trigger is availability, never outcome.** Cancel still cancels. A
failed biometric attempt still lands wherever it lands today. Biometry
lockout flips `canEvaluatePolicy` only after repeated *physical* sensor
mismatches, which software alone cannot manufacture; a process spamming
`evaluatePolicy` and cancelling does not accrue failed attempts. So a caller
cannot steer the routing: availability is a property of hardware and
enrollment state, and neither environment variables nor tty state nor sudo
flags enter the predicate.

**Probe failure under `"password"` counts as unavailable.** If the
LocalAuthentication probe itself errors, the dialog path would fail closed
anyway; routing to the terminal still collects a real factor. Under
`"dialog"` nothing changes: today's fail-closed denial stands.

**Why the default stays `"dialog"`.** The GUI password dialog is the
stronger habitat for a password. It is rendered out of process and takes
input through secure event input, so the password never transits the
terminal, the multiplexer, or the shell — the stack a compromised session
reads without effort. And it is spoof-evident: other software can draw a
lookalike window, but the genuine dialog shows the verify code printed on
the caller's terminal, which a spoof that cannot read that terminal cannot
reproduce. A terminal password prompt has neither property; every hop of the
pty stack sees the keystrokes. `"password"` trades that away for UX on
machines where the dialog would only ever be a password box anyway — a
reasonable trade under this project's stated model (biometric is
convenience; the password is the floor; the *disclosure* is the product),
which is why it is offered, and offered opt-in.

**Habit surface.** The biometric console deliberately retires the reflex of
typing your password for sudo, which is what makes fake prompts unrewarding.
`"password"` re-trains that habit on the machines where it applies. On a
biometric-less machine the habit exists regardless (the dialog is already a
password box); this is the argument that the option is acceptable at all.

## Case 4: the attached-from-SSH tmux (not solved; timeout rejected)

A static setting cannot split case 4 from the attended console: the same
session, the same tmux server, differs only in whether a human is at the
screen — a fact no API reports. Per-invocation signals were considered and
rejected: environment variables and `SSH_TTY` are invisible through a tmux
server (the server's environment, not the client's, reaches sudo), spoofable
where visible, and would hand every caller an auth-routing knob.

One extension was explored: **dialog-timeout fallback**. Half of it is easy.
The plugin's `evaluatePolicy` wait is a semaphore; a timed wait plus
`[ctx invalidate]` closes the dialog deterministically after an operator-set
timeout, and the resulting `LAErrorAppCancel` is cleanly distinguishable
from the user's own Cancel (`LAErrorUserCancel`), so an explicit no still
denies. The other half is the blocker: by approval-plugin time sudo's PAM
phase is already over — the console-gate succeeded, which is exactly what
suppressed the native password — and sudo offers no way to re-enter it.
Collecting a terminal password at that point means the plugin running its
own PAM conversation (`pam_start` / `pam_authenticate`, proxied over sudo's
conversation API): possible with openpam, but it puts password bytes through
plugin code, breaking the invariant `execConfirm` was designed around ("no
password ever touches plugin code") and adding real attack surface to the
most sensitive component. That splits the idea into two tiers:

- **Timeout-then-deny** (viable, cheap, safe): a `dialogTimeout` that
  invalidates the dialog and denies with a message pointing at the
  non-console path. For case 4 it only makes the failure fast; it collects
  nothing.
- **Timeout-then-password** (parked): requires the plugin-side PAM
  transaction above. The runtime security story otherwise holds — an
  attacker-spawned hidden sudo gains nothing, since the fallback prompt
  lands on a pty the attacker cannot answer with a password they do not
  have — but it is slow by construction, it teaches that ignoring the
  dialog produces a prompt (eroding "cancel means no"), and its
  implementation price is a standing invariant.

**Rejected (2026-08-28): neither tier ships.** Timeout-then-deny buys
little — case 4 merely fails faster — and timeout-then-password costs a
standing invariant. The workaround stands: run sudo from the plain SSH
shell, outside the console-session tmux, which takes the ordinary
non-console terminal-password path.

## Rejected alternatives

- **Automatic, no knob.** Silently changing console auth UX based on
  hardware probing violates the explicit-settings house style, and an
  operator who prefers the dialog on a biometric-less machine (its secure
  input and spoof-evidence still apply) would have no way back.
- **Downgrade on LA failure or cancel.** Conflates denial with routing. A
  cancelled dialog must stay a denial, or cancelling stops meaning no.
- **Reattach-style session surgery** (cf. `pam_reattach`). Solves rendering
  in detached contexts, not attendance; case 4's dialog renders fine, on a
  screen nobody is watching. Also imports exactly the session-manipulation
  complexity this project has avoided.
