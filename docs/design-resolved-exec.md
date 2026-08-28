# Design note: resolved exec display (`input:` / `execute:`)

**Status: IMPLEMENTED (v0.13.0, 2026-08-26).** Closes two future items from
`docs/design-terminal-mode.md` ("the as-typed vs resolved split, the
resolved-path last-look") with a concrete shape. Companion decision recorded
here: the writable-target warning considered alongside it is CUT (see "Cut:
the writable-target check").

## Problem

The terminal block prints at audit `open()`, before sudo has resolved the
command, so it can only show the line as typed. The resolved absolute path --
the thing that answers "which binary will actually run" -- appears only on the
biometric dialog. Two concrete failures:

1. **The overflow referral is a broken promise.** When the command exceeds the
   dialog's length budget, the dialog shows `(see terminal)` -- but the terminal
   holds only the as-typed line. In exactly the case where the dialog cannot
   show the command, the resolved path is visible NOWHERE.
2. **Terminal-password mode never shows it at all.** No dialog exists there;
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

### 1. `execute:` -- the resolved line

The approval plugin prints one line to the controlling terminal, aligned into
the existing block gutter, rendered through the shared escape core
(`sw_full_command_line_colored` -- same walk, same quoting/escaping as
`input:`, so the two renderings cannot disagree on a token; from 2026-08-27
they differ in weight only, see the delta below):

    sudowhat: execute:    /run/current-system/sw/bin/pinned deploy

Content: `command_info["command"]` + `run_argv[1..]` (argv[0] dropped when it
duplicates the path/basename, exactly as `commandPartsForPath` does for the
dialog). Printed ALWAYS -- a predictable ceremony beats a clever conditional,
and "only sometimes present" would itself need explaining.

**Delta (2026-08-27): the root-bypass line is solo.** The gutter above exists
to align siblings — `run as:`, `directory:`, `input:`, `verify:`. On the
root-bypass path there are none: the audit plugin exempts uid 0, so no block
precedes the line, and `verify:` is raised only on the console biometric path,
which that branch returns before reaching. That one emit site therefore prints
the unpadded form, matching the Linux port's block:

    sudowhat: execute: /run/current-system/sw/bin/pinned deploy

Every other emit site keeps the padded form. A label floating four spaces from
its value, with nothing above or below to line up against, reads as a rendering
bug rather than as a column. One accepted edge: a non-root run on a build with
`auditDisplay = "off"` is alone too and still gets the padded form — the
approval bundle cannot see the audit bundle's build token, and that
administrator explicitly chose to strip the block, so the alignment is
vestigial there rather than wrong. Choosing per emit site keeps the decision
compile-time and provable instead of guessing at another bundle's
configuration.

**Delta (2026-08-27): `echoColor` governs the `execute:` value too.** The
build-time colour token was originally passed to the audit bundle alone, so
`echoColor = "off"` silenced `input:`'s role colouring while `execute:` kept
following the runtime gates only — one display, two answers. The token
(`-DSW_ECHO_COLOR`) now sits in the global `CFLAGS` and both bundles carry their
own copy of the token machinery. As in the audit bundle, it governs the command
VALUE only: the frame — provenance prefix, bold label, gutter — and the
`verify:` emphasis still answer to the runtime `NO_COLOR` / `TERM` / `isatty`
gates alone, since that chrome is sudowhat's own rather than a rendering of
untrusted argv.

**Delta (2026-08-27): the two lines render at different weights.** Under
`echoColor = "on"` both lines carried the same command at the same weight, which
left the reader deciding which of two identical-looking rows was authoritative.
`execute:` keeps the full role palette; `input:` now renders every routine token
— program dirname, program basename, flags, values — on a flat dim base
(`sw_full_command_line_colored_dim`). The anomaly spans are identical on both
lines and stay at full strength, so an anomaly reads the same wherever it
appears and, against the dim base, is the only coloured thing on the `input:`
row. Quiet in, loud out: the resolved line is the one that says what happens as
root. It is a base-palette parameter on the ONE shared walk in `escape_core`,
not a second renderer, so "input: and execute: cannot disagree on a token"
survives unchanged — the same token list, the same quoting, the same anomaly
classifier, one different base. See the delta at the end of the colour section
in `docs/design-terminal-mode.md`.

**Delta (2026-08-27): the grey whitespace mark is scoped to the program token.**
On both lines. Marking notable whitespace runs in arguments turned out to fight
the display it was meant to sharpen: a script passed as one argument (`sh -c
'…'`) paints a grey block on every line of indentation after an escaped `\n`,
burying the anomalies that matter. The invisible-padding spoof the mark defends
against lives in the path that will execve, so the mark now lives there too;
argument bytes still render escaped and quoted, which is what makes them read as
data. Escaping, tokenisation and the round-trip invariant are untouched. Full
rationale in the colour section of `docs/design-terminal-mode.md`.

**Delta (2026-08-27): `execDisplay`, a switch for the line itself.** Added at
the owner's request after this round shipped. "Printed ALWAYS" above describes
the default and stays the default; `execDisplay = "off"` is an administrator
opting out of the whole informational echo -- the root-bypass solo line, the
step-aside last-look, the policy-deference skip and the biometric pre-dialog
line together. The plugin loads, verifies and gates identically; it simply
narrates nothing, which is exactly what `auditDisplay = "off"` already means
for the other bundle. The name pairs with `auditDisplay` (the two display
switches, one per line family) rather than joining the `echo*` family, which
names colour.

Precedence against `exec_confirm` is the only interaction: with the confirm
ceremony on, the resolved line is still printed before its `run? [y/N]`, even
under `execDisplay = "off"`. Asking a human to approve a command sudowhat
refuses to show them is the same empty ceremony the missing-`command`-key check
already fails closed on. Mechanically the gate sits inside `emit_exec_line`,
the informational entry point, and the confirm branch calls the tty writer
directly.

An `interactive` level -- print for a human, stay silent for automation -- was
considered and **rejected as undetectable**. Every signal available at that
point is positive in exactly the case it would need to exclude: the
root-initiated batch run that motivated the knob (nix-darwin activation
shelling out through sudo) typically *has* a controlling terminal and a
stdin-isatty, because it was launched from one. A knob that claims to
distinguish human from script while keying off "was there a terminal
somewhere up the tree" would be wrong in the one case it is sold for. Two
honest states beat three, one of which lies.

Timing by mode:

- **Biometric:** printed by approval `check()` BEFORE raising the LAContext
  dialog. The human sees the resolved path in the terminal, then approves.
  Pre-decision.
- **Terminal password:** the password happens inside the policy step, so the
  line prints after auth but before exec. A last-look, not a preview -- the
  honest maximum in that mode.
- **No controlling terminal:** the line is skipped (nowhere to print);
  behavior otherwise unchanged. No prompts are added in any mode, so
  non-interactive invocations (agents, scripts) cannot newly block.

This makes the dialog's `(see terminal)` referral truthful: by exec time the
terminal carries the full resolved line in both modes.

### 2. Honest labels

    sudowhat: run as:     root
    sudowhat: directory:  /Users/jooize/Projects/claude-code-hardening
    sudowhat: input:      pinned deploy
    sudowhat: path:       /run/current-system/sw/bin:/usr/bin:/bin
    sudowhat: verify:     JL6E  (compare with the prompt)
    <auth>
    sudowhat: execute:    /run/current-system/sw/bin/pinned deploy

`input:` states what the invoking user asked for -- the plugin's input, before
resolution; `execute:` states what sudo will run. Each label carries its own
epistemic status, the pair reads as in/out, and the juxtaposition IS the
anomaly display -- a shadowed bare name shows up as input/execute divergence,
with no heuristic needed.

**Label history.** The pre-resolution row was labelled `command:` until
v0.13.0, which over-claimed: it read as "this is the command" when it was only
"this is what you typed". v0.13.0 renamed it `typed:`, and v0.14.0 renamed it
again to `input:` -- script-invoked sudo types nothing, and `input:` /
`execute:` is the honest in/out pair. The resolved row shipped as `exec:` in
v0.13.0 and was spelled out to `execute:` in v0.14.0; the identifiers
(`execDisplay`, `execConfirm`, `sw_exec_*`, `SW_EXEC_*`) keep `exec`.

Dropping the as-typed line entirely was considered and rejected: in
terminal-password mode it is the only command display that exists before the
password is typed, and without the pair the divergence signal disappears.

**The dialog's stacked labels (settled at the v0.14.0 smoke).** They have worn
three spellings: `USER` / `DIRECTORY` / `COMMAND` originally, a lowercase
colon grammar `user:` / `directory:` / `execute:` briefly, and finally
`RUN AS` / `DIRECTORY` / `EXECUTE` -- the caps back, the colons gone. On a
surface with no bold and no colour the caps carry the label-vs-value
distinction better than a trailing colon did, and `RUN AS` names what the
value actually is -- the runas target -- where a bare `USER` read ambiguously
on a two-second glance. `EXECUTE` keeps the referent fix from the colon round:
the dialog is fed `command_info["command"]`, so its value genuinely is the
resolved path that will run, the same referent as the terminal's `execute:`
row. The terminal's own row was renamed `user:` -> `run as:` in the same
round (`run as user:` was considered for greppability and rejected -- at 12
characters it would have widened the shared gutter and shifted every value
right), so the two surfaces still speak one vocabulary for the field where
the name matters most.

Losing the caps costs nothing structurally, because the caps were never the
anti-forgery mechanism. What makes a label unforgeable is its *shape*: a real
label sits alone on its own line, directly after a blank line, with its value
on the line below -- and `escapeControlChars` strips newlines and the Unicode
line/paragraph separators out of every displayed value, so no value can contain
a line break at all. A displayed value may well contain the text `EXECUTE`; it
can never put that text alone on a line of its own after a blank line. The unit
tests pin exactly that (an argv token spelling a fake stacked label leaves the
structural newline count unchanged at 10).

Sheet field order (v0.14.0):

    run a command.

    RUN AS
    root

    DIRECTORY
    /Users/jooize/Projects/claude-code-hardening

    EXECUTE
    /run/current-system/sw/bin/pinned deploy

    Verify Code: JL6E

    Code must match your terminal

The verify code moved from directly under the header to just above the closing
line: read what you are approving, then bind it to the terminal, then act.
The order was A/B'd at the v0.14.0 smoke via a temporary
`-DSW_SHEET_VERIFY_LAST` compile-time switch; code-last won, and the losing
code-first order was deleted along with the switch.

### 3. Display ownership carve-out

`design-terminal-mode.md` names the audit plugin the single owner of terminal
command display. This round adds a stated carve-out rather than an exception
by accident:

- **audit plugin** owns the PRE-AUTH block (`run as:`/`directory:`/`input:`/
  `path:`/`verify:`) -- everything that exists before resolution.
- **approval plugin** owns DECISION-ADJACENT display -- the dialog and the
  `execute:` line -- everything that exists only after resolution.

Both render command lines through the shared escape core, so the split cannot
produce two spellings of one command. The seam is commented on both sides.

**Delta (2026-08-27): `path:`, a pre-gate row for bare names (D8).** The audit
block gains a fourth row, printed directly after `input:` because it qualifies
it. macOS only for now — the Linux port's roadmap is separate.

*What it discloses.* The PATH ENVIRONMENT sudo was handed by the caller: the
attacker-influenceable surface that decides how a bare command name resolves.
The wording rule is load-bearing and applies everywhere the row is described
(code comments, module option, README): it is **not** the final resolution
PATH. A sudoers `secure_path` may override the caller's PATH entirely, and
`execute:` still shows the resolved outcome. What the row buys is disclosure
*before the gate* on the password path, where `execute:` cannot appear until
the password has already been spent — the same asymmetry the `exec_confirm`
section below is about, answered for the one input that most often decides
which binary a bare name reaches.

*Condition (a): bare names only.* The row prints only when the typed command
word (`submit_argv[submit_optind]`) contains no `/` at all. An absolute path
and any relative path carrying a slash are used as given and never consult
PATH, so for those the caller's PATH decides nothing and the row would be
noise. PATH absent or empty is likewise no row: nothing to disclose.

*Invariant, settled: no plugin-side resolution, ever.* The row shows the PATH
string. It never walks the list, never stats an entry, never claims which entry
would win. This is the same invariant "Not in scope" below already states for
the `execute:` line, and it is what keeps the row from becoming a second,
disagreeing answer to a question sudo already answers.

*Condition (b), mode scoping: the sanctioned fallback.* Ideally the row would
print only where `execute:` cannot precede the gate — the password path. It
cannot: the audit bundle deliberately carries **no session classification**.
There is no `SessionGuard` on this target (a third per-target ObjC class would
be needed), even a console session can land on the password path, and the
bundle cannot see the `sudo_local` variant either. So at `open()` the plugin
cannot know which mode this invocation will take. Decision: **print whenever
(a) holds**, accepting mild redundancy on biometric consoles, where `execute:`
also appears pre-dialog. A row that is occasionally redundant beats a row that
is occasionally missing from the one path that needs it, and the alternative
would be a guess dressed as a mode. Recorded in a comment at the row's build
site in `plugin/sudowhat_audit.m`.

*Rendering.* Label `path:` (5 chars) in the existing 12-column gutter, bold
under colour like every other label; the value escaped through the one shared
core (`sw_escape_control`, the same call `run as:` and `directory:` take) and
rendered **plain** — no role colour, no dim. It is one opaque string, not a
token walk, and yellow and cyan already mean specific things in this block.
One logical line; the terminal soft-wraps; nothing truncated. Fail-soft like
the rest of the bundle: any doubt means no row, never a broken block.

## Terminal-mode asymmetry, and the `exec_confirm` option

In biometric mode the `execute:` line lands pre-decision; in terminal-password
mode it lands post-password. That asymmetry is forced: the password prompt
runs inside the policy step that resolves the command, PAM modules never
receive the command, and the only component holding the resolved path
pre-auth is sudo's policy plugin itself, which sudowhat deliberately does not
replace. "Resolved before the password" is impossible through any supported
hook.

"Before the password" is not the only place a decision can complete, though.
**`exec_confirm` (config key, DEFAULT OFF):** in terminal-password mode, after
auth, the approval plugin prints `execute:` and then asks one `run? [y/N]` on
the tty via sudo's conversation API. The decision then completes AFTER the
resolved path is visible -- the same guarantee biometric mode gives, split
into authenticate-then-confirm. No password ever touches plugin code; decline
is a quiet abort (nothing wedges; re-run at will). Tty-gated: no controlling
terminal means no prompt, so piped/automated invocations behave identically
with the key on or off. Off (default) keeps the plain last-look.

Realized form: "config key" here means what it means for every other sudowhat
knob — a build-time token baked into the signed bundle, not a runtime config
file. `SUDOWHAT_EXEC_CONFIRM` in the Makefile (`-DSW_EXEC_CONFIRM`), exposed as
`services.sudowhat.execConfirm` in the nix module, alongside `echoColor`,
`policyDeference` and `auditDisplay`. (This list also named `verifyStyle` when
written; that option was dropped in v0.14.0 — the verify code is fixed bold
magenta.) Nothing a caller can set at runtime, and no file for an attacker to
edit.

**Delta (2026-08-27): the confirm asks only when the auth stack actually ran.**
The blunt tty gate shipped first — knob on plus a controlling terminal — asked
every non-console caller on a live terminal, `NOPASSWD` ones included. That is
the one thing this round said it would not do: "where the decision is deferred
today, nothing else changes". A deploy script in an SSH session calling a
`NOPASSWD` sudo has a controlling terminal, so the blunt gate re-gated exactly
what sudoers had explicitly waived. Refined at the owner's request to be
authenticate-then-confirm literally: the question is asked only when sudo ran
the PAM auth stack for *this* invocation, i.e. when a human just presented a
factor.

Detection reuses the policy-deference marker (`SUDOWHAT_AUTH_MARKER_ENV`, set
in-process by `pam_sudowhat` whenever the auth stack runs, after the caller's own
environment was captured — so a caller can add it but never remove it, and its
absence cannot be forged). Mechanically the marker is now read and cleared once
per `check()`, hoisted above the caller classification, because the two consumers
sit on opposite sides of that fork: the non-console step-aside returns long
before the console path's deference step. The decision itself is a pure
`sw_confirm_decision(confirmOn, haveTty, markerPresent, integrityInstalled)`,
table-tested like `sw_defer_decision`:

| knob | tty | marker | integrity line | result |
|---|---|---|---|---|
| off | — | — | — | no prompt (unchanged default) |
| on | none | — | — | no prompt (automation identical either way) |
| on | yes | present | — | **prompt** — the knob's whole meaning |
| on | yes | absent | wired | no prompt — sudoers waived auth; print `execute:` and allow, exactly as the knob-off branch does |
| on | yes | absent | not verifiable | **prompt** — an absent marker cannot be trusted to mean "waived" if `pam_sudowhat` may be unwired |

The integrity-line read stays lazy everywhere: it happens only when it can change
the answer (knob on, tty present, marker absent), the same laziness the console
deference path already had.

Fail direction: uncertainty **asks**. Note that is the opposite boolean from
`sw_defer_decision`, where uncertainty means "do not skip the Touch ID dialog" —
both fail *toward* the gate, and the shared rule is "when in doubt, put the
question to the human". Here the doubt is cheap to resolve: the knob's owner
opted into confirmation, and one extra y/N costs less than silently re-gating or
silently skipping.

This restores the round's "where the decision is deferred today, nothing else
changes" principle on the non-console path, which is where it had been quietly
broken: with the refinement, a waived run gets the informational `execute:` line
(`execDisplay`-gated, through `emit_exec_line`) and allows, byte-identical to the
knob-off behaviour.

A divergence-triggered variant (prompt only when the input differs from the
resolved path) was considered and cut: every bare name "diverges", so it would
fire on essentially every sudo while being less predictable than a mode-wide
key.

**Rejected: approval-owned authentication.** Full symmetry is achievable by
having sudoers defer (NOPASSWD) and the approval plugin run its own PAM
conversation post-resolution. Rejected: it reopens plugin-side password
handling (explicitly rejected in design-terminal-mode.md), and it couples
safety to deployment config -- a NOPASSWD rule over an absent or broken
approval plugin fails OPEN.

## Cut: the writable-target check

Considered: warn (on dialog + terminal) when the resolved executable or its
directory is writable by the invoking user, as a portable substitute for
sudoers `secure_path` hygiene. CUT, for habituation, not implementability:

- On Apple Silicon, `/opt/homebrew` is USER-OWNED by default. Single-user
  nix/Lix installs have a user-owned store. On such systems -- i.e. a large
  share of real deployments -- the warning fires on nearly every sudo.
- A warning that almost always fires trains the human to approve through
  warnings. That habituation spends the dialog's alarm authority, which is
  worth more than this check.
- The `execute:` line already carries the actionable fact. A human reading
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
  decision (dialog, or PAM password) stays the only decision.
- No plugin-side PATH resolution, ever.
- Policy deference / NOPASSWD behavior unchanged: where the decision is
  deferred today, only the `execute:` line is added, nothing else.

## Test plan (sketch)

- Line order per mode: `input:` before auth; `execute:` after resolution and,
  in biometric mode, before the dialog is raised.
- `execute:` content equals `command_info["command"]` + argv rendering,
  byte-compared against the escape-core rendering used by the dialog.
- Overflow case: dialog shows `(see terminal)`; terminal contains the full
  resolved line by exec time.
- No-tty invocation: no `execute:` line, no error, exit behavior unchanged.
- Marker migration: harness/tests asserting on `command:` move to `typed:`
  (and, from v0.14.0, to `input:`).
