# Design note: terminal mode (no-biometric, cross-platform) via a sudo audit plugin

**Status: Phase 1 SHIPPED (v0.10.0, macOS); Phase 2 (Linux) IN PROGRESS.** The
audit plugin (`plugin/sudowhat_audit.m`) owns terminal command display on every
path, with the escape/quote core ported to Rust (`shared/escape_core/`, a
`staticlib` byte-identical to `PromptFormatter`, guarded by
`tests/test_escape_core.m`). The **Linux `cdylib` port** (Phase 2, ~v0.11.0,
display + native PAM password, no code-signing anchor) is now in progress — a
pure-Rust `cdylib` reusing escape_core, with its own design note at
`docs/design-linux-port.md` (audit-only, trust = sudo's own file perms, the
`sudo.conf`/`sudoers` re-declaration wrinkle). The **`command:` colouriser**
(`echoColor`) has landed on macOS — see "Highlighting the command line" below.
Still future: the **no-biometric terminal password for a console user** (open
decision #1 — dropping the console-gate + approval step-aside), the as-typed vs
resolved split, the resolved-path last-look, and the restyle of the block
*around* the command line (scope (b) below). Original design captured
2026-07-20; sibling to `docs/design-noncon-sudo.md` (non-console + policy
deference, shipped).

## Goal

Let a user **without Touch ID** (or on a headless macOS session, or on Linux)
use sudowhat with a **regular terminal password prompt** that still shows
user / path / command but **no verify code** (there is no GUI sheet to bind, so
the code has nothing to channel-bind). Today such a user gets a macOS GUI
password sheet (LAContext's password fallback) — fine on a Mac with an Aqua
session, useless headless and impossible on Linux.

## The key mechanism: show the command from a sudo AUDIT plugin

The obvious question — "show the command before the password without the plugin
touching the password" — has a clean answer that avoids plugin-side password
handling entirely (which was considered and **rejected**: reading/verifying the
plaintext password in-plugin is complex and dangerous, and unnecessary).

- The PAM **auth module** (`pam_sudowhat`) does **not** receive the command —
  PAM items are user/tty/host, never argv. (This is why `pam_tid` shows no
  command.)
- The sudo **audit plugin** does. Its `open()` receives `submit_argv[]` +
  `submit_optind`, and `sudo_plugin(8)` states *"the audit open() function is run
  before any other sudo plugin API function"* — i.e. **before** the PAM password
  prompt (which happens inside the policy plugin's `check_policy`). So an audit
  plugin displays the command on the tty, then sudo's **native** PAM
  (`pam_opendirectory` / `pam_unix`) collects the password. Nobody but sudo/PAM
  touches the secret.

```
$ sudo systemctl restart nginx
sudowhat: user: root                    <- audit plugin open(), BEFORE auth
sudowhat: directory: /etc/nginx         <- the invoking cwd (user_info["cwd"])
sudowhat: command: systemctl restart nginx  <- as-typed (see "resolved path" below)
Password: ****                          <- sudo's native PAM, on the terminal
sudowhat: will exec /run/.../systemctl restart nginx   <- resolved last-look (optional)
<runs>
```

## The resolved-path timing constraint (and the two-moment answer)

The fully-resolved path (`/run/.../systemctl`) is more useful than the as-typed
command — it catches PATH hijacks and symlink swaps. But sudo does not resolve
the command until `check_policy`, which is the **same step that collects the
password**, and audit `open()` runs before that. So the resolved path *does not
exist yet* pre-password; it first appears at approval `check()` / audit
`accept()`, both **post-password**. Consequences:

- **Biometric (macOS):** the LAContext sheet already shows the **resolved** path
  (the approval plugin has `command_info`), and LAContext *is* the auth (no
  earlier password), so "resolved, before you approve" already holds. Unchanged.
- **Terminal:** the pre-password display is necessarily **as-typed**
  (`submit_argv[submit_optind..]`). The **resolved** path comes back
  post-password, where the approval plugin shows it as a final `will exec: …`
  and can **deny on a suspicious divergence** — so resolved-path protection is a
  last-look + veto rather than a pre-password preview.
- **Do NOT** have the plugin resolve the path itself pre-password to show it
  early: an independent resolution can diverge from what sudo actually runs
  (different PATH, sudoers overrides), i.e. it could display a lie. As-typed
  up front + sudo's own resolved path as the post-password check is the honest
  split.

## Structure: DISPLAY / AUTH / TRUST as separate layers

The audit plugin lets **display** happen once, early, and universally, instead of
being fused into the biometric sheet.

```
  DISPLAY  (shared, cross-platform)
    audit plugin: show user / path / cmd, runs FIRST, before any auth.
    Same sudo audit API on macOS + Linux; reuses PromptFormatter.

  AUTH  (per platform + session)
    macOS console      -> approval plugin + LAContext sheet (resolved cmd)
                          + verify code binding sheet <-> tty
    terminal / no-GUI  -> native PAM password on the tty; approval plugin
    / Linux               approves + does the post-password resolved last-look

  TRUST  (integrity / tamper-evidence)
    PAM module: macOS = mutual code-signing; Linux = file perms only (weaker)
```

- The **verify code stays biometric-only** — it binds a *sheet* to the tty;
  terminal mode has nothing to bind. (See [[project-tty-only-signals]].)
- **Policy deference** (v0.9.0 NOPASSWD skip) stays a biometric-mode concern; in
  terminal mode, NOPASSWD simply means native PAM does not prompt.

## macOS / Linux consolidation — partial, and stated honestly

- **Display consolidates:** the audit plugin + `PromptFormatter` is genuinely one
  shared component across both platforms. This is the real win and the reason to
  build the display layer once.
- **Auth + trust do not, and should not be forced:** biometric vs PAM password is
  inherently platform-specific, and the trust model diverges most here. **Linux
  has no code-signing anchor**, so a Linux sudowhat is "display + PAM password
  with normal root-owned-file trust" — an attacker with root can swap the plugin.
  That is not a flaw to fix but a fact to document: **Linux gets the UX, not the
  tamper-evidence.** Do not imply otherwise.

## What to do better (motivated by the audit plugin existing)

1. **Move command display earlier.** Today the non-console/terminal path steps
   aside *silently* (shows nothing). The audit plugin closes that gap: you judge
   the command before committing, in every mode.
2. **Unify tty command display in one place.** *(Shipped in v0.10.0.)* Before
   v0.10.0 the approval plugin owned both the sheet and the post-auth tty echo
   (`emit_full_context`, `echoCommand`).
   Let the audit plugin own the tty command display (pre-auth); shrink the
   approval plugin to sheet + verify code + resolved last-look. Fewer display
   sites, clearer ownership. (Mind the ordering: the verify code still emits at
   sheet time in the approval plugin, so on the biometric path the tty shows the
   command first (audit), then the code + sheet (approval) — verify on hardware.)

## Highlighting the command line — scope (a), SHIPPED

The `command:` value is the star of the display and the hardest thing to read: a
real invocation runs to several hundred characters and wraps blind, burying the
one token worth reading (the program path) at the front of the wrap. The fix is
**highlight, not split**, and it is deliberately confined to the command line.

**One logical line.** No per-option splitting, no break points, no elision, no
reordering — the terminal soft-wraps and that is enough. Splitting would invent
structure that is not in the bytes and would drift from the caller's own
`display == exact argv` rule (a caller such as `pinned` shows the same argv
before it elevates; two renderings that disagree are worse than one that wraps).
A disclosure tool that abbreviates is worthless.

**Colour is layout over content, never content.** `escape_core` escapes and
quotes first; the SGR sequences go only *around* the finished tokens. Strip the
SGR and the bytes are `sw_full_command_line`'s exactly — the round-trip
invariant, pinned by unit tests on both sides of the FFI. So the highlight can
neither add nor hide a byte, and colouring attacker-influenced content is safe:
emphasis is not a trust signal (the anchor stays the verify code matching the
system-rendered sheet), and the input is already free of raw control bytes, so
no attacker byte can become an escape sequence.

**Role palette** (`sw_full_command_line_colored`, `shared/escape_core`), one
house palette shared with `pinned`'s `prog_disp`:

| role | SGR | note |
|---|---|---|
| program path, directory part | `36` (plain cyan) | |
| program path, basename | `1;36` (bold cyan) | the token worth reading |
| option flag (rendered form starts with `-`) | `2` (dim) | |
| value | none | |
| deceptive Unicode escape `\uNNNN` | `1;31` | anomaly palette, |
| control-byte escape `\n \r \t \0 \xNN` | `1;35` | as already shipped in |
| shell metacharacter (`'`, `"`, backtick, `\\`) | `1;36` | `colorizeEscaped:` |
| notable whitespace run | `100` (grey background) | leading/trailing/doubled |

The role colour is the base for a token; an anomaly span drops it, takes its own
colour, and the role resumes after. A token is treated as a flag only when its
*rendered* form starts with `-`, so a hostile token that needed quoting lands
quoted and coloured as data rather than borrowing a flag's look.

**Gating and fail-soft.** The build-time `echoColor` token (baked into the signed
bundle) plus the existing runtime `NO_COLOR` / `TERM` gate, with `isatty()` in
`sw_audit_write_tty` as the final say. **No new runtime knob** — any knob the
caller can set is a knob a hostile script sets first, and sudowhat's disclosure
is unconditional by construction. Any colouriser failure (allocation, a non-OK
return) falls back to the same line in plain: the plugin picks between the two
`escape_core` renderers, so degrading loses emphasis and nothing else.

## Restyling the block around it — scope (b), NOT DONE

Deliberately a separate round: any plugin change is a signed-bundle rebuild plus
a reinstall ceremony, and these touch every caller.

- label gutter: pad `user:` / `directory:` / `command:` to one column;
- colour roles for the `user:` / `directory:` lines (paths cyan, etc.);
- the blank-line seam — the block fires mid-screen in an arbitrary caller's
  output, so it is a candidate for a single leading blank;
- the verify-code line's phrasing (already build-time styled via `verifyStyle`).

**Boundary: (a) = highlight the `command:` value, one line. (b) = the block
around it.** The Linux port's `display.rs` still renders the command plain —
adopting `colored_command_line` there is part of finishing Phase 2, not of (a).

## Open design decisions (resolve before coding)

1. **Mode selection.** Global build knob `authMode = biometric (default) |
   terminal`, or auto by session (console -> biometric, non-console ->
   terminal), or both? Auto-by-session already half-exists (the non-console
   step-aside uses native PAM). Terminal mode for a *console* user in Terminal.app
   additionally requires NOT short-circuiting the PAM password (drop the
   console-gate for that mode) and the approval plugin stepping aside instead of
   LAContext.
2. **When the audit plugin displays vs stays quiet.** It runs first and does not
   yet know if biometric will be used. Either it displays always (redundant with
   the sheet on the biometric path — extra tty lines) or it re-derives the
   session/biometric decision itself (two places making one decision -> the
   split-brain risk from `docs/design-noncon-sudo.md`; collapse to one source of
   truth if so).
3. **Third signed bundle.** The audit plugin is a display trust surface — if it
   can be suppressed or spoofed, the command can be hidden — so on macOS it must
   join the mutual-signature web (pam <-> approval <-> audit). Extend
   `SignatureVerifier` wiring to a third bundle; more `-DSW_SIGVERIFIER_CLASS`
   plumbing.
4. **PAM reconfig for console terminal mode** (see #1) and how it composes with
   the gate variant + policy-deference marker.
5. **The resolved last-look + deny policy** — what counts as a "suspicious
   divergence" worth denying vs merely displaying.

## Explicitly NOT doing

- **No plugin-internal password reading/verification** (no `ODRecordVerifyPassword`
  on a tty-read password, no in-plugin PAM conversation). sudo's native PAM owns
  the secret. This was considered and rejected as complex/dangerous.
- **No plugin-side command resolution** for the pre-password display (could lie).
- **No claim of tamper-evidence on Linux** (no code-signing anchor there).

## Sequencing

v0.9.0 (policy deference) is orthogonal and complete; the audit plugin is purely
additive. Ship v0.9.0 after its spike, then build this as v0.10.0 — macOS first,
with the display component structured to be the Linux model too. Relates to
[[project-terminal-mode-audit-plugin]], [[project-policy-deference-plan]],
[[project-design-noncon-sudo]].
