# Design note: resolved exec display (`typed:` / `exec:`)

**Status: IMPLEMENTED (v0.13.0, 2026-08-26).** Closes two future items from
`docs/design-terminal-mode.md` ("the as-typed vs resolved split, the
resolved-path last-look") with a concrete shape. Companion decision recorded
here: the writable-target warning considered alongside it is CUT (see "Cut:
the writable-target check").

## Problem

The terminal block prints at audit `open()`, before sudo has resolved the
command, so it can only show the line as typed. The resolved absolute path --
the thing that answers "which binary will actually run" -- appears only on the
biometric sheet. Two concrete failures:

1. **The overflow referral is a broken promise.** When the command exceeds the
   sheet's length budget, the sheet shows `(see terminal)` -- but the terminal
   holds only the as-typed line. In exactly the case where the sheet cannot
   show the command, the resolved path is visible NOWHERE.
2. **Terminal-password mode never shows it at all.** No sheet exists there;
   the human authenticates against the as-typed line only.

And one labeling failure: the field name `command:` over-claims. It reads as
"this is the command" when it is only "this is what you typed"; the resolved
path can differ, and the label hides that such a difference exists.

## Constraint (unchanged from design-terminal-mode.md)

sudo resolves the command inside the policy step that also collects the
password; no plugin hook exists between resolution and auth. So a resolved
pre-PASSWORD display is impossible. But in biometric mode the password is not
the decision -- the SHEET is, it is raised by the approval plugin, the
approval plugin runs after resolution, and it controls its own ordering. A
resolved pre-DECISION display is therefore possible in biometric mode, and
that is the moment that matters.

Do NOT resolve the path plugin-side to show it earlier: an independent
resolution can diverge from what sudo execs, i.e. it could display a lie.
Only sudo's own `command_info["command"]` is ever displayed.

## Design

### 1. `exec:` -- the resolved line

The approval plugin prints one line to the controlling terminal, aligned into
the existing block gutter, rendered through the shared escape core
(`sw_full_command_line_colored` -- same quoting/escaping as `typed:`, so the
two renderings cannot disagree on a token):

    sudowhat: exec:       /run/current-system/sw/bin/pinned deploy

Content: `command_info["command"]` + `run_argv[1..]` (argv[0] dropped when it
duplicates the path/basename, exactly as `commandPartsForPath` does for the
sheet). Printed ALWAYS -- a predictable ceremony beats a clever conditional,
and "only sometimes present" would itself need explaining.

Timing by mode:

- **Biometric:** printed by approval `check()` BEFORE raising the LAContext
  sheet. The human sees the resolved path in the terminal, then approves.
  Pre-decision.
- **Terminal password:** the password happens inside the policy step, so the
  line prints after auth but before exec. A last-look, not a preview -- the
  honest maximum in that mode.
- **No controlling terminal:** the line is skipped (nowhere to print);
  behavior otherwise unchanged. No prompts are added in any mode, so
  non-interactive invocations (agents, scripts) cannot newly block.

This makes the sheet's `(see terminal)` referral truthful: by exec time the
terminal carries the full resolved line in both modes.

### 2. Rename `typed:` -- honest labels

    sudowhat: user:       root
    sudowhat: directory:  /Users/jooize/Projects/claude-code-hardening
    sudowhat: typed:      pinned deploy
    sudowhat: verify:     JL6E  (compare with the prompt)
    <auth>
    sudowhat: exec:       /run/current-system/sw/bin/pinned deploy

`typed:` states what the invoking user asked for; `exec:` states what sudo
will run. Each label carries its own epistemic status; the juxtaposition IS
the anomaly display -- a shadowed bare name shows up as typed/exec
divergence, with no heuristic needed.

Dropping the as-typed line entirely was considered and rejected: in
terminal-password mode it is the only command display that exists before the
password is typed, and without the pair the divergence signal disappears.

The SHEET keeps its `COMMAND` label -- there the value genuinely is the
resolved command that will run.

### 3. Display ownership carve-out

`design-terminal-mode.md` names the audit plugin the single owner of terminal
command display. This round adds a stated carve-out rather than an exception
by accident:

- **audit plugin** owns the PRE-AUTH block (`user:`/`directory:`/`typed:`/
  `verify:`) -- everything that exists before resolution.
- **approval plugin** owns DECISION-ADJACENT display -- the sheet and the
  `exec:` line -- everything that exists only after resolution.

Both render command lines through the shared escape core, so the split cannot
produce two spellings of one command. The seam is commented on both sides.

## Terminal-mode asymmetry, and the `exec_confirm` option

In biometric mode the `exec:` line lands pre-decision; in terminal-password
mode it lands post-password. That asymmetry is forced: the password prompt
runs inside the policy step that resolves the command, PAM modules never
receive the command, and the only component holding the resolved path
pre-auth is sudo's policy plugin itself, which sudowhat deliberately does not
replace. "Resolved before the password" is impossible through any supported
hook.

"Before the password" is not the only place a decision can complete, though.
**`exec_confirm` (config key, DEFAULT OFF):** in terminal-password mode, after
auth, the approval plugin prints `exec:` and then asks one `run? [y/N]` on the
tty via sudo's conversation API. The decision then completes AFTER the
resolved path is visible -- the same guarantee biometric mode gives, split
into authenticate-then-confirm. No password ever touches plugin code; decline
is a quiet abort (nothing wedges; re-run at will). Tty-gated: no controlling
terminal means no prompt, so piped/automated invocations behave identically
with the key on or off. Off (default) keeps the plain last-look.

Realized form: "config key" here means what it means for every other sudowhat
knob — a build-time token baked into the signed bundle, not a runtime config
file. `SUDOWHAT_EXEC_CONFIRM` in the Makefile (`-DSW_EXEC_CONFIRM`), exposed as
`services.sudowhat.execConfirm` in the nix module, alongside `verifyStyle`,
`echoColor`, `policyDeference` and `auditDisplay`. Nothing a caller can set at
runtime, and no file for an attacker to edit.

A divergence-triggered variant (prompt only when typed differs from resolved)
was considered and cut: every bare name "diverges", so it would fire on
essentially every sudo while being less predictable than a mode-wide key.

**Rejected: approval-owned authentication.** Full symmetry is achievable by
having sudoers defer (NOPASSWD) and the approval plugin run its own PAM
conversation post-resolution. Rejected: it reopens plugin-side password
handling (explicitly rejected in design-terminal-mode.md), and it couples
safety to deployment config -- a NOPASSWD rule over an absent or broken
approval plugin fails OPEN.

## Cut: the writable-target check

Considered: warn (on sheet + terminal) when the resolved executable or its
directory is writable by the invoking user, as a portable substitute for
sudoers `secure_path` hygiene. CUT, for habituation, not implementability:

- On Apple Silicon, `/opt/homebrew` is USER-OWNED by default. Single-user
  nix/Lix installs have a user-owned store. On such systems -- i.e. a large
  share of real deployments -- the warning fires on nearly every sudo.
- A warning that almost always fires trains the human to approve through
  warnings. That habituation spends the sheet's alarm authority, which is
  worth more than this check.
- The `exec:` line already carries the actionable fact. A human reading
  `/Users/me/.local/bin/foo` where a system path was expected has the signal;
  writability adds little a human can act on at that moment.
- Philosophy: PATH hygiene (`secure_path`) is the system administrator's
  choice. sudowhat displays truth about what that choice produced; it does
  not police the choice.

Recorded as an OPEN option, not a plan: an opt-in config key (default off)
or a much narrower condition (e.g. world-writable) could revisit this if
field evidence shows the display alone is not enough.

## Not in scope

- No new prompts or denials by default; the only optional addition is the
  off-by-default `exec_confirm` key above. With it off, the one existing
  decision (sheet, or PAM password) stays the only decision.
- No plugin-side PATH resolution, ever.
- Policy deference / NOPASSWD behavior unchanged: where the decision is
  deferred today, only the `exec:` line is added, nothing else.

## Test plan (sketch)

- Line order per mode: `typed:` before auth; `exec:` after resolution and,
  in biometric mode, before the sheet is raised.
- `exec:` content equals `command_info["command"]` + argv rendering,
  byte-compared against the escape-core rendering used by the sheet.
- Overflow case: sheet shows `(see terminal)`; terminal contains the full
  resolved line by exec time.
- No-tty invocation: no `exec:` line, no error, exit behavior unchanged.
- Marker migration: harness/tests asserting on `command:` move to `typed:`.
