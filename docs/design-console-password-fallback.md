# Design note: console password fallback (consoleNoBiometric)

**Status: designed, not implemented.** Decided 2026-08-28. Adds one module
option; no mechanism is new — every moving part below already exists for the
non-console path (`design-nonconsole-sudo.md`) and is reused, not rebuilt.

## Decision

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
- **`nonConsole = "deny"` composes.** The gate variant is what makes a
  native password path exist at all. With the `pam_permit` (deny) variant
  installed there is no password stack to fall through to, so
  `consoleNoBiometric = "password"` requires `nonConsole = "password"`; the
  module should assert this pairing at eval time rather than install a
  configuration that can only deny.

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

## Case 4: the attached-from-SSH tmux (open, not solved here)

A static setting cannot split case 4 from the attended console: the same
session, the same tmux server, differs only in whether a human is at the
screen — a fact no API reports. Per-invocation signals were considered and
rejected: environment variables and `SSH_TTY` are invisible through a tmux
server (the server's environment, not the client's, reaches sudo), spoofable
where visible, and would hand every caller an auth-routing knob.

One extension was explored and left undecided: **dialog-timeout fallback** —
when the dialog dies of timeout or system cancel (never user cancel), fall
through to the terminal password. The remote user waits out the dialog once
and then types a password; an attacker-spawned hidden sudo gains nothing,
since the fallback prompt lands on a pty the attacker cannot answer with a
password they do not have. Costs: it is slow by construction, and it teaches
that ignoring the dialog produces a prompt, which erodes "cancel means no".
Parked until someone actually wants it. The workaround today is simply to
run sudo from the plain SSH shell, outside the console-session tmux, which
takes the ordinary non-console terminal-password path.

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
