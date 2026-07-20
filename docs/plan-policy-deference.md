# Plan: policy-deference — NOPASSWD skip, no-biometric password mode, context echo everywhere

> **Status: IMPLEMENTED in code 2026-07-20 (v0.9.0, uncommitted at time of
> writing), pending the hardware spike + hardware verification (steps 0 and 8)
> which require a real terminal and root and cannot run under the agent sandbox.**
> What shipped differs from this plan in two deliberate ways, both to respect the
> existing tty-only invariant and the guest-VM "quiet automation" use case:
> - Mode 2 (no-biometric → terminal password) was already provided by the shipped
>   non-console gate variant + step-aside; no new work. The console-without-
>   biometrics case keeps its existing GUI Authorization Services password dialog
>   (changing it to a terminal password would reopen the passwordless-console
>   concern). This pass did not touch it.
> - The context echo is `off` by default (knob `echoDeferred`), not "everywhere",
>   and `tty` is the only other value — it is tty-or-nothing, with no stderr
>   variant. (An earlier draft had an `always` mode that fell back to stderr for
>   scripted callers; it was cut because a deferred run has no prompt to preview,
>   so stderr disclosure would only duplicate sudo's audit log while breaking
>   tty-or-nothing.) The verify code stays structurally tty-only, unchanged.
> The headline — mode 3 (NOPASSWD → zero prompts) via the PAM marker — shipped as
> designed. See the "Policy deference" section of `docs/design-noncon-sudo.md` for
> the authoritative as-built record.

Status: approved design, ready to implement. Written 2026-07-20 for execution by a
Claude (Opus) session. Read this whole file before editing anything, then read:

- `docs/design-noncon-sudo.md` — the non-console design this plan extends.
- `docs/design-nopasswd-console-allowlist.md` — the design this plan RETIRES.
- `plugin/sudowhat_approval.m`, `pam/pam_sudowhat.m`, `plugin/PromptFormatter.{h,m}`,
  `shared/Constants.h`, `Makefile`, `nix/module.nix`, `tests/`.

## Goal — three user-visible modes

1. **Console session + biometrics available** (today's behavior, unchanged):
   Touch ID / Apple Watch sheet with the command, verify code written to `/dev/tty`
   (tty-or-nothing, structural invariant — do NOT add any fallback for the code).
2. **Authentication required, but no GUI prompt possible** (no biometrics
   configured, or non-console session such as ssh): sudowhat prints the context
   block (user / cwd / command — no verify code, nothing to bind) and returns
   accept; sudo's native PAM password prompt follows in the terminal.
3. **sudoers waived authentication** (NOPASSWD tag, invoking user is root,
   `Defaults !authenticate`, or a live timestamp cache): **no Touch ID sheet, no
   password** — the command just runs. Context block still printed unless the
   admin turns that off.

Mode 3 is detected by the **PAM marker** (below), not by any allowlist. On
completion, `docs/design-nopasswd-console-allowlist.md` is obsolete.

## Mechanism 1: PAM marker (detects "sudoers waived auth")

All of sudo's plugin and PAM machinery runs in the one `sudo` process, in this
order: policy `check_policy()` (sudoers runs the PAM **auth** stack inside it, but
ONLY when it requires authentication) → approval plugin `open()`/`check()`.
NOPASSWD / root / `!authenticate` / valid timestamp cache mean the auth stack is
never invoked at all.

- `pam_sudowhat` gains an auth-phase entry point `pam_sm_authenticate()` that:
  - `setenv("SUDOWHAT_AUTH_RAN", "1", 1);` (process-local; the approval plugin
    reads it later in the same process). Keep the existing integrity work in
    whatever phase it lives in today; this is additive.
  - returns `PAM_IGNORE` — it must express no opinion on auth success/failure.
- `config/pam.d/` template: ensure the sudowhat line participates in the **auth**
  stack (add an `auth optional pam_sudowhat.so` line if its current line is
  another phase). `optional` + `PAM_IGNORE` keeps it outcome-neutral.
- Approval plugin `check()` decision:
  1. `getenv("SUDOWHAT_AUTH_RAN")` — then immediately `unsetenv()` it (hygiene;
     sudo rebuilds the command env anyway, scrub defensively).
  2. Marker **present** → sudoers demanded auth → mode 1 or 2 (below).
  3. Marker **absent** → run the fail-closed gate before skipping:
     verify `/etc/pam.d/sudo` (and the sudo_local variant per the noncon design)
     actually contains the pam_sudowhat auth line AND that the module file on
     disk passes the existing `SignatureVerifier` check. If the chain does not
     contain a verifiable pam_sudowhat auth entry, treat the absent marker as
     untrustworthy: fall back to prompting (mode 1/2), never silently skip.
     Reuse/extend `pam/SudoConfChecker` and the chain-shape verification
     specified in `docs/design-noncon-sudo.md` — do not write a second parser.
  4. Chain intact + marker absent → mode 3: no prompt, optional context echo,
     return accept.

Security analysis (already red-teamed in conversation, record in docs):

- Caller pre-exporting `SUDOWHAT_AUTH_RAN` only *adds* a prompt (fail-safe).
- Suppressing the marker requires editing root-owned `/etc/pam.d/sudo` or
  sudoers — attacker with root has already won; no regression.
- Marker-absent covers exactly: NOPASSWD, root invoker (matches the deliberate
  v0.4.2 root exemption), `Defaults !authenticate`, and valid timestamp cache.
  All are "root-configured policy waived auth". Document all four explicitly,
  with the callout that `!authenticate` and `timestamp_timeout > 0` also silence
  Touch ID (recommend `timestamp_timeout=0` for sheet-every-time semantics).

### Step 0 — REQUIRED spike before building anything

Confirm on macOS's shipped sudo that a `setenv()` made inside a PAM auth module
is visible via `getenv()` in the approval plugin (same-process assumption).

- Build a throwaway PAM module (`pam_sm_authenticate` → setenv + PAM_IGNORE) and
  a throwaway approval plugin (`check()` → log getenv result to a file, accept).
- Install into a TEST pam.d line + sudo.conf on the dev machine (coordinate with
  the user — this touches live sudo config; prepare exact rollback commands
  first, and keep a root shell open during the test).
- Matrix: normal sudo (expect marker), NOPASSWD command (expect none), `sudo -k`
  then sudo (marker), second sudo within timestamp window (none unless
  timeout=0), invocation as root (none).
- If the spike FAILS (e.g. PAM runs in a child process): stop, report. Fallback
  design direction would be a file/fd side channel keyed on sudo's pid — do not
  build that without discussion.

## Mechanism 2: context echo via conversation fallback

Today the context block is `/dev/tty`-or-nothing. New rule:

- **Verify code: unchanged.** `/dev/tty` or nowhere. Structural — no printf
  parameter, no conversation path, ever (see memory/invariant, v0.5.2 rationale).
- **Context block (user / cwd / command):**
  - tty present (`user_info` has `tty=`) → existing direct `/dev/tty` path,
    unchanged (keeps escaping, anomaly coloring, ordering with the code).
  - no tty → emit via the sudo **conversation** function captured in the approval
    plugin's `open()`, msg_type `SUDO_CONV_ERROR_MSG | SUDO_CONV_PREFER_TTY`
    (tty-else-**stderr**; INFO_MSG would fall back to stdout and corrupt piped
    output — use ERROR_MSG deliberately, comment why). Content goes through the
    same PromptFormatter escaping; strip/disable SGR color when falling back
    (no isatty guarantee on the far end — emit the uncolored escaped form).
- This gives visibility when a script runs sudo with no tty: the context lines
  land on stderr adjacent to sudo's own `-S`/askpass prompting behavior.

## Build knobs (follow the existing pattern exactly: Makefile token →
`-DSW_...` define → fail-closed enum mapping in the plugin; mirror in
`nix/module.nix` as `services.sudowhat.*`. See `echoColor` for the template.)

- `SUDOWHAT_ECHO_CONTEXT` / `services.sudowhat.echoContext` =
  `always` | `prompted-only` | `never` (default `always`).
  Controls the context block in mode 3 (`always` prints it even when skipping;
  `prompted-only` prints only when a prompt of either kind is shown).
- `SUDOWHAT_POLICY_DEFERENCE` / `services.sudowhat.policyDeference` =
  `on` | `off` (default `on` is acceptable given fail-closed gating; if in doubt
  ship `off` for one release and let the user flip it in nix-darwin).
  `off` = today's prompt-always behavior. Unknown token → build error
  (fail-closed enum, same as echoColor).

## Implementation order (commit after each green step, SemVer at the end)

1. **Spike** (step 0 above). Scratch code only, nothing committed except notes.
2. **PromptFormatter/plumbing:** factor the context-block rendering so it can be
   produced (a) colored for /dev/tty, (b) plain-escaped for conversation
   fallback, without duplicating the escaping logic. Unit tests first
   (`tests/test_prompt_formatter.m` pattern; run `make test-unit`).
3. **Conversation fallback** in `sudowhat_approval.m`: capture `conversation` in
   `open()`, emit context via ERROR_MSG|PREFER_TTY when no tty. Unit-test the
   mode selection logic (extract it into a testable function; the conversation
   call itself is thin).
4. **pam_sudowhat auth phase + marker**, pam.d template update, and the
   fail-closed chain gate in the approval plugin (reuse SudoConfChecker).
   Unit-test the gate's parsing/decision table exhaustively, including:
   marker present/absent × chain intact/missing/unsigned × deference on/off.
5. **Mode wiring** in `check()`: implement the 3-mode decision tree; mode 2
   (accept + native PAM password) per `docs/design-noncon-sudo.md`'s
   chain-verification requirements — this plan does not relax any of that doc's
   gating for non-console sessions.
6. **Knobs** in Makefile + `nix/module.nix` (+ `nix/package.nix` passthrough if
   needed), README table row per existing knob docs.
7. **Docs:** update `docs/design-noncon-sudo.md` with the marker mechanism and
   the four marker-absent cases; mark `design-nopasswd-console-allowlist.md`
   superseded at the top (keep the file, one-line pointer here); README
   behavior matrix (mode 1/2/3). Em-dashes fine in prose; ASCII in code.
8. **Hardware verification with the user** (cannot be automated; Claude Code has
   no ctty — user must run these in a real terminal):
   - NOPASSWD command → runs with zero prompts, context lines visible.
   - Normal command, console → Touch ID + verify code as today.
   - `ssh localhost sudo -S true` style no-tty → context on stderr, password ok.
   - Root shell `sudo true` → no prompt.
   - Tamper drill: comment out the pam_sudowhat auth line (root) → plugin must
     PROMPT, not skip. Restore after.
9. Release: bump per SemVer (new behavior, backward compatible → minor, v0.9.0),
   tag, then user redeploys via nix-darwin pin (see deploy-workflow memory —
   deployed system uses a local git pin; do not push without being asked).

## Invariants that must survive this change (grep-able checklist)

- Verify code: /dev/tty or nothing. No stderr/stdout/conversation path.
- U+2026 scrubbing + control-char escaping applied to everything printed on any
  channel, including the conversation fallback.
- All new enums fail closed on unknown tokens (build-time error).
- Chain/tamper checks fail toward PROMPTING (or rejecting), never toward skip.
- EUID drop / TOCTOU block in the plugin untouched.
- `make test-unit` green (441+ tests) before every commit.
