# Design note: terminal mode (no-biometric, cross-platform) via a sudo audit plugin

**Status: Phase 1 SHIPPED (v0.10.0, macOS); Phase 2 (Linux) IN PROGRESS.** The
audit plugin (`plugin/sudowhat_audit.m`) owns terminal command display on every
path, with the escape/quote core ported to Rust (`shared/escape_core/`, a
`staticlib` byte-identical to `PromptFormatter`, guarded by
`tests/test_escape_core.m`). The **Linux `cdylib` port** (Phase 2, ~v0.11.0,
display + native PAM password, no code-signing anchor) is now in progress — a
pure-Rust `cdylib` reusing escape_core, with its own design note at
`docs/design-linux-port.md` (audit-only, trust = sudo's own file perms, the
`sudo.conf`/`sudoers` re-declaration wrinkle). The **`input:` colouriser**
(`echoColor`) has landed on macOS — see "Highlighting the command line" below —
as has the restyle of the block *around* the command line (scope (b) below).
The **as-typed vs resolved split** and the **resolved-path last-look** shipped
in v0.13.0 as the pair now labelled `input:` / `execute:`; see
`docs/design-resolved-exec.md`.
Still future: the **no-biometric terminal password for a console user** (open
decision #1 — dropping the console-gate + approval step-aside). Original design
captured 2026-07-20; sibling to `docs/design-noncon-sudo.md` (non-console + policy
deference, shipped).

## Goal

Let a user **without Touch ID** (or on a headless macOS session, or on Linux)
use sudowhat with a **regular terminal password prompt** that still shows
user / path / command but **no verify code** (there is no GUI dialog to bind, so
the code has nothing to channel-bind). Today such a user gets a macOS GUI
password dialog (LAContext's password fallback) — fine on a Mac with an Aqua
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
sudowhat: run as:     root              <- audit plugin open(), BEFORE auth
sudowhat: directory:  /etc/nginx        <- the invoking cwd (user_info["cwd"])
sudowhat: input:      systemctl restart nginx  <- as typed (see "resolved path" below)
sudowhat: path:       /usr/local/bin:/usr/bin:/bin  <- caller's PATH; bare names only
Password: ****                          <- sudo's native PAM, on the terminal
sudowhat: execute:    /run/.../systemctl restart nginx   <- resolved last-look (shipped v0.13.0)
<runs>
```

*[2026-08-27 — the `path:` row (D8). Added directly after `input:` because it
qualifies it: for a bare command name it discloses the caller's PATH, the
surface that steers how that name resolves, on the one path where `execute:`
cannot precede the gate. Not a claim about the final resolution PATH — sudoers
`secure_path` may override it, and `execute:` still shows the outcome — and
sudowhat never walks the list. Absent for absolute or relative commands, which
never consult PATH. Printed on every path that shows the block, because the
audit bundle carries no session classification and so cannot know pre-auth
which mode it is in; the redundancy on biometric consoles is accepted. Full
rationale in the D8 delta in `docs/design-resolved-exec.md`, section 3. macOS
only for now.]*

## The resolved-path timing constraint (and the two-moment answer)

The fully-resolved path (`/run/.../systemctl`) is more useful than the as-typed
command — it catches PATH hijacks and symlink swaps. But sudo does not resolve
the command until `check_policy`, which is the **same step that collects the
password**, and audit `open()` runs before that. So the resolved path *does not
exist yet* pre-password; it first appears at approval `check()` / audit
`accept()`, both **post-password**. Consequences:

- **Biometric (macOS):** the LAContext dialog already shows the **resolved** path
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

**[2026-08-26 — resolved, see `docs/design-resolved-exec.md`.]** The last-look
shipped in v0.13.0 as the resolved line — labelled `exec:` then, `execute:`
from v0.14.0 — printed by the approval plugin from
sudo's own `command_info["command"]` (never a plugin-side resolution, exactly as
the third bullet insists). One correction to the second bullet above: the
**deny-on-suspicious-divergence** idea was CUT. Divergence heuristics do not
survive contact with reality — every bare name "diverges" from its resolved
absolute path, so the rule would fire on essentially every `sudo` and train the
human to approve through it. What shipped instead is the `input:` / `execute:`
juxtaposition (the pair *is* the anomaly display, judged by the human, with no
heuristic to tune) plus the opt-in `exec_confirm` y/N gate for the
terminal-password path. Biometric mode also improved on the "last-look" framing:
there the `execute:` line prints *before* the dialog is raised, so it is a
pre-decision preview after all — only the terminal-password path is limited to a
last look, and that limit is the constraint this section describes, unchanged.

## Structure: DISPLAY / AUTH / TRUST as separate layers

The audit plugin lets **display** happen once, early, and universally, instead of
being fused into the biometric dialog.

```
  DISPLAY  (shared, cross-platform)
    audit plugin: show user / path / cmd, runs FIRST, before any auth.
    Same sudo audit API on macOS + Linux; reuses PromptFormatter.

  AUTH  (per platform + session)
    macOS console      -> approval plugin + LAContext dialog (resolved cmd)
                          + verify code binding dialog <-> tty
    terminal / no-GUI  -> native PAM password on the tty; approval plugin
    / Linux               approves + does the post-password resolved last-look
                          (shipped v0.13.0 as the execute: line; macOS only)

  TRUST  (integrity / tamper-evidence)
    PAM module: macOS = mutual code-signing; Linux = file perms only (weaker)
```

- The **verify code stays biometric-only** — it binds a *dialog* to the tty;
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
   v0.10.0 the approval plugin owned both the dialog and the post-auth tty echo
   (`emit_full_context`, `echoCommand`).
   Let the audit plugin own the tty command display (pre-auth); shrink the
   approval plugin to dialog + verify code + resolved last-look (that last-look
   shipped in v0.13.0 as the `execute:` line — the ownership carve-out is
   stated in `docs/design-resolved-exec.md`). Fewer display sites, clearer
   ownership.
   (Mind the ordering: the verify code still emits at dialog time in the approval
   plugin, so on the biometric path the tty shows the command first (audit),
   then the code + dialog (approval) — verify on hardware.)

## Highlighting the command line — scope (a), SHIPPED

The `input:` value (labelled `command:` until v0.13.0, `typed:` until v0.14.0)
is the star of the display and the hardest thing to read: a real invocation runs
to several hundred characters and wraps blind, burying the one token worth
reading (the program path) at the front of the wrap. The fix is
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
system-rendered dialog), and the input is already free of raw control bytes, so
no attacker byte can become an escape sequence.

**Role palette** (`sw_full_command_line_colored`, `shared/escape_core`), one
house palette shared with `pinned`'s `prog_disp`:

| role | SGR | note |
|---|---|---|
| program path, directory part | `36` (plain cyan) | |
| program path, basename | `1;36` (bold cyan) | the token worth reading |
| every other token (flag or value alike) | none | see below |
| a single quote *we* added | `2` (dim) | our own chrome |
| deceptive Unicode escape `\uNNNN` | `1;31` | anomaly palette, |
| control-byte escape `\n \r \t \0 \xNN` | `1;35` | as already shipped in |
| shell metacharacter (`"`, backtick, `\\`, a data `'`) | `1;36` | `colorizeEscaped:` |
| notable whitespace run, program token only | `100` (grey background) | leading/trailing/doubled |

The role colour is the base for a token; an anomaly span drops it, takes its own
colour, and the role resumes after.

*[2026-08-27 — the two lines render at different weights. The table above is the
`execute:` line. The `input:` line renders through the same walk with a flat dim
base under every routine token (`sw_full_command_line_colored_dim`) — see the
delta at the end of this section.]*

Colour asserts only what sudowhat KNOWS, which is exactly three things: a
**structural fact** (token[0] is the program, because sudo will execve it), a
**fact about bytes** (control chars, deceptive Unicode, invisible padding —
observations about the data, never readings of it), and **our own chrome** (the
quotes invented to render an argv array as one pasteable line). Anything else
would be a guess about someone else's command grammar.

That is why **option flags carry no colour**. An earlier revision dimmed a token
whose rendered form started with `-`, inherited from `pinned`'s `prog_disp`,
where dim flags are right because that display is about *which program runs*.
Here the display is about *what happens as root*, and `--no-preserve-root` must
not be the faintest thing on the line. "Starts with a dash" was also the one
guess in the palette: lexical, not semantic — wrong by definition after `--`,
blind to `dd if=...` and `tar xvf`. Retiring it leaves dim with exactly one
meaning: *these bytes are ours, not the data's*.

*[2026-08-23 — reversed at the owner's request (`d169403`): flags render bold
blue after all. What survived the reversal is the no-judgement principle — the
mark is openly lexical (any token whose rendered form starts with `-`, so a
quoted hostile token, rendering as `'...'`, never borrows it), it colours every
flag identically rather than guessing which one matters, and dim keeps its one
meaning. The table row above ("none") describes the design as first shipped.]*

**Quote attribution.** Nothing reaching sudo contains a quote — sudo hands the
plugin an argv ARRAY — so every quote on screen is one `quote_token` added,
except those spliced through the POSIX `'\''` idiom, the only way a quote the
argument really contained can be represented. Ours render dim, the data's stay
lit. The rule is decided inside `colorize_escaped`'s left-to-right walk and
nowhere else: the walk consumes `\\` as one unit first, so a lone `\` can only
be the idiom's, and the `'` after it is the data's. As a regex lookbehind over
the finished string the same rule is WRONG — input `\'` renders `\\'\''`, whose
third character is our closing quote and *is* preceded by a backslash. An
attribution-oracle test pins it: for an adversarial token set, the count of lit
quotes equals the count of `'` in `escape_control(input)`, and every other quote
sits in a dim span.

**Gating and fail-soft.** The build-time `echoColor` token (baked into the signed
bundle) plus the existing runtime `NO_COLOR` / `TERM` gate, with `isatty()` in
`sw_audit_write_tty` as the final say. **No new runtime knob** — any knob the
caller can set is a knob a hostile script sets first, and sudowhat's disclosure
is unconditional by construction. Any colouriser failure (allocation, a non-OK
return) falls back to the same line in plain: the plugin picks between the
`escape_core` renderers, so degrading loses emphasis and nothing else.

**Delta (2026-08-27): `input:` renders dim, `execute:` keeps the role palette.**
Once the resolved line joined the block (`docs/design-resolved-exec.md`), two
lines carried the same command at the same weight and the reader had to work out
which one to trust. They are now split by weight rather than by palette:
`input:` renders every routine token — program dirname, program basename, flags,
values — on one flat dim base, while `execute:` keeps the table above. The
anomaly spans are identical on both, at full strength: an anomaly must read the
same wherever it appears, and against the flat dim base it is the only coloured
thing on that row, so the dim base makes anomalies pop *harder*, not softer.

Implemented as a base-palette parameter threaded through the one walk
(`render_command_line(path, argv, RoleBase, out)`), with
`colored_command_line` / `colored_command_line_dim` as thin wrappers and
`sw_full_command_line_colored_dim` as the second FFI export. Deliberately not a
fork: the property that the two lines are built from the same `command_tokens`
list, quoted by the same `quote_token` and coloured by the same
`colorize_escaped` is what makes "the two lines disagree" mean "the command
really differs", and a second renderer would put that at the mercy of two
implementations staying in step. The round-trip invariant holds for the dim
variant too, pinned over the same case table.

One accepted cost: on the `input:` line our chrome quotes (`2`, dim) stop being
distinguishable from the base. Attribution stays legible one row down on
`execute:`, which renders the same tokens through the same walk, so the
information is not lost — only its second, redundant appearance is.

**Delta (2026-08-27): the whitespace mark is scoped to the program token.** The
grey background (`100`) on a notable whitespace run now applies only inside
token[0] — the path sudo will execve — and no longer to flag or argument tokens.
Two reasons, in order. First, the spoof surface the mark was built for is the
program path: a trailing space, or a hidden double space, in the thing that
runs. Second, on arguments it was drowning the display — a multi-line script
passed as one argument (`sh -c '…'`) renders every newline as `\n` and then
paints every line of indentation that follows it as a grey block, so the line
filled with grey and the actual anomalies stopped standing out. Argument bytes
lose nothing by it: they still render escaped and quoted either way, which is
what makes them read as data.

The rule is identical on both variants — inside the program token the mark stays
a full-strength anomaly span under the dim base as under the role palette — and
it changes no byte: escaping is untouched and the round-trip invariant (strip
the SGR, get `sw_full_command_line`'s bytes) holds exactly as before.
Implemented as a `mark_spaces` flag on `colorize_escaped`, passed true for the
program token's two halves and false everywhere else, so it is one walk still.
The pre-existing seam nuance survives inside that token: the span, not the
token, bounds "start/end", so a single space just past the dirname/basename
split starts the basename span and is marked where a token-level walk would call
it interior — more emphasis on invisible padding in the program path, never
less.

## Restyling the block around it — scope (b), DONE

A separate round, because any plugin change is a signed-bundle rebuild plus a
reinstall ceremony, and these touch every caller.

- **Label gutter.** `run as:` / `directory:` / `input:` are padded so every value
  starts in one column: the longest label (`directory:`, 10) plus two spaces,
  measured after the `sudowhat: ` prefix. That prefix stays on every row rather
  than being hoisted into a header — the block lands in the middle of somebody
  else's output, so each line has to carry its own provenance.
- **Colour on the frame rows.** The `directory:` value takes the same
  dirname-plain-cyan / basename-bold-cyan split as the program path (done in the
  plugin, not by routing the cwd through `sw_full_command_line_colored`, which
  would also shell-quote it and make the coloured and plain blocks differ in
  bytes). The `run as:` value is plain for `root` — the expected target earns no
  emphasis — and plain yellow for any other target. The frame stays clear of
  `escape_core`'s anomaly palette (`1;31`, `1;35`, `1;36`, `100`).
- **The seam: flush, no leading blank.** Reversed from the first draft. The
  courtesy-blank exception assumes a program owns both sides of the seam;
  sudowhat owns neither and cannot know what preceded it. Generalization test:
  if every program opened with a courtesy blank, a session would be a column of
  holes. Spacing belongs to the caller — `pinned` or `claude-update-nix` may
  print their own blank before invoking sudo.
- **The verify-code line** became a fourth field in the same gutter:
  `sudowhat: verify:     Z96E  (compare with the prompt)` — label bold like the
  other rows, code carrying the build-time `verifyStyle` emphasis, the trailing
  instruction dim. No attention colour: yellow already means "the target user is
  not root", and spending it here would say something the reader knows and give
  one colour two meanings. Emitted by the APPROVAL plugin at a later stage, not
  by the audit block. (The `execute:` line, added in v0.13.0, joins the same
  gutter from the same plugin — see `docs/design-resolved-exec.md`.)
  `verifyStyle` was dropped in v0.14.0: the code's emphasis is now the
  compile-time constant bold magenta, with no knob. One reviewed SGR, nothing to
  misconfigure, and the emphasis was never a trust signal anyway. Accepted
  imperfection: `escape_core`'s anomaly palette also spends bold magenta on
  control-byte escapes, so a control-byte span in a command value shares the
  verify code's colour — rare, and a control byte in argv is itself an alarm.

Not carried across: the Linux port's `display.rs` still renders the unpadded
block, since it renders the command plain too. Adopting both is part of
finishing Phase 2.

**Boundary: (a) = highlight the `input:` value, one line. (b) = the block
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
   the dialog on the biometric path — extra tty lines) or it re-derives the
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
   *RESOLVED 2026-08-26 (`docs/design-resolved-exec.md`, shipped v0.13.0):*
   display and juxtaposition only — the `input:` / `execute:` pair, no
   divergence-deny (every bare name diverges); the opt-in `exec_confirm` y/N is
   the one gate, off by default.

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
