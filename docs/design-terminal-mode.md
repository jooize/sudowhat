# Design note: terminal mode (no-biometric, cross-platform) via a sudo audit plugin

**Status: DISPLAY LAYER SHIPPED in v0.10.0 (Phase 1, macOS).** The audit plugin
(`plugin/sudowhat_audit.m`) now owns terminal command display on every path,
with the escape/quote core ported to Rust (`shared/escape_core/`, a `staticlib`
byte-identical to `PromptFormatter`, guarded by `tests/test_escape_core.m`). Two
parts of this note remain future work: the **no-biometric terminal password for
a console user** (open decision #1 — dropping the console-gate + approval
step-aside) and the **Linux `cdylib` port** (Phase 2, ~v0.11.0, display + PAM
password, no code-signing anchor). The as-typed vs resolved split, the
resolved-path last-look, and the anomaly colouriser (echoColor) are also still
future. Original design captured 2026-07-20; sibling to
`docs/design-noncon-sudo.md` (non-console + policy deference, shipped).

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
sudowhat: path: systemctl               <- as-typed (see "resolved path" below)
sudowhat: command: systemctl restart nginx
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
