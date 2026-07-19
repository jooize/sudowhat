# Design note: NOPASSWD and the console prompt (exact-command allowlist)

**Status: proposed, not yet implemented.** Captures the reasoning from a design
discussion so it does not have to be re-derived. The recommendation is an
opt-in, exact-command, signature-covered console allowlist (see "The design"
below). Sibling to `docs/design-noncon-sudo.md`, which covers the *non-console*
NOPASSWD path (already shipped in v0.5.0).

## The problem

For the **active console user**, sudowhat pops the Touch ID sheet on *every*
`sudo`, including commands the operator authorized `NOPASSWD` in sudoers. An
operator who wrote an exact-command `NOPASSWD` rule has made a deliberate
"this command needs no authentication" decision; being biometric-prompted anyway
is friction they did not ask for. We want a way to honor that decision — without
reopening the reflexive-approval hole the console guard exists to close.

Note this is a console-only problem. The non-console path already steps aside
for NOPASSWD (`sudowhat_approval.m:686`, gated on `allowNonConsole`).

## Why it happens (the architectural crux)

sudowhat is a sudo **approval plugin**. The approval phase runs on *every*
`sudo` invocation, after the policy plugin (sudoers) has decided to allow the
command. It is structurally distinct from the **auth phase**:

- **`timestamp_timeout` (credential cache) and `NOPASSWD` are two independent
  reasons sudo skips the auth phase.** Cache = "you authenticated recently";
  NOPASSWD = "the rule says no auth." They are orthogonal. `timeout=0` removes
  the cache bypass and does *nothing* to NOPASSWD.
- **The approval plugin fires regardless of the auth phase entirely** — on cache
  hits and on NOPASSWD alike. So `timestamp_timeout` has no effect on whether
  the plugin prompts. (sudowhat already defaults `timestamp_timeout` to `0`, and
  the console user is still prompted on NOPASSWD — empirical proof the timeout is
  not the lever.) See `docs/design-noncon-sudo.md:329-334`: the "re-prompt every
  command" guarantee comes from the approval plugin, **not** from `timeout=0`.
- **sudo gives no signal to distinguish NOPASSWD from anything else.**
  `command_info[]` has no `nopasswd`, `authenticated`, or `timestamp` key
  (`sudo_plugin(8)`; see `docs/design-noncon-sudo.md:154-162`). A fresh password,
  a cached timestamp, and a NOPASSWD rule are identical at `check()` time. The
  same wall exists at the PAM layer — sudo has no way to tell PAM a NOPASSWD
  command is running (sudo-project issue #415).

So "don't prompt on NOPASSWD commands" cannot be implemented by *detecting*
NOPASSWD. The plugin must learn the exempt command set independently.

## Why sudowhat cannot just be an auth module like `pam_tid`

Tempting shortcut: make sudowhat an auth-phase PAM module (like `pam_tid.so`)
and rely on the operator's `timeout=0` for the re-prompt cadence. Then NOPASSWD
would skip it for free, because NOPASSWD skips the whole auth phase.

This deletes the product. **Auth modules never receive the command.** sudo does
not pass the target command into the PAM conversation, which is exactly why
`pam_tid`'s prompt shows no command. sudowhat's entire reason to exist is to show
the *exact resolved command* (`command_info["command"]` + `run_argv[]`,
`README:3`) — and that data is delivered only to plugins (policy/approval phase),
never to PAM. To show the command you must stand in the approval phase; the
approval phase runs on every command including NOPASSWD. The two are inseparable.

`pam_tid` "doesn't prompt on NOPASSWD" only because it is *also* bypassable by a
cached timestamp — the weaker property sudowhat deliberately did not want.
"Fires on cache hits but not on NOPASSWD" is not obtainable from architecture
alone. Hence an explicit allowlist.

## The design: exact-command console allowlist (recommended)

The operator declares the exact commands that skip the biometric for the console
user — mirroring (a subset of) their sudoers `NOPASSWD` grants.

- **Baked into the signed bundle at build time.** `make` is the real build
  driver; Nix only wraps it with `-D` flags (`Makefile:14-61`). A build step
  generates a `static const` C array from a config file (e.g.
  `config/nopasswd-allowlist`, empty by default = feature off) into a header
  compiled into `sudowhat_approval.o`. Because it is compiled in, the list is
  covered by the bundle's code signature and therefore by the existing mutual
  integrity check (`SecStaticCodeCheckValidity`, `sudowhat_approval.m:618`).
  Tampering the list breaks the signature -> fail-closed. **Non-Nix is
  first-class:** plain `make`; the Nix module option just writes the same config
  file before invoking `make`.
- **Match is exact.** sudo's *resolved* `command_info["command"]` (absolute,
  symlink-resolved) plus the *full* `run_argv[]`. Never `argv[0]` alone, never a
  prefix, no wildcards. (sudoers wildcards are how NOPASSWD rules become
  footguns; the sudowhat allowlist stays strictly exact.)
- **Console-user branch only**, before formatting the prompt: on match, syslog +
  `return 1` with no prompt. Does not touch the non-console path.
- **Fail-safe:** anything not exactly listed prompts as today.
- **Optional (recommended) sha256 pin**, mirroring sudoers' own `sha256:` digest
  spec: the exemption applies only if the on-disk binary's hash matches, so
  swapping the binary revokes the exemption (falls back to prompting). Composes
  with the pre/post-auth TOCTOU stat already done at `sudowhat_approval.m:731`.
- **One real footgun, documented loudly:** do not exempt an interpreter or a
  writable wrapper (`/bin/sh`, `/usr/bin/python3`, a script in a user-writable
  dir) — that turns one exemption into arbitrary silent root. Warn on these in
  the generator; do not hard-block (the operator owns the tradeoff, consistent
  with the "trust the operator's explicit opt-in" thesis).

Changing the list is a deliberate privileged act (`edit -> make -> sudo make
install`), which is correct for something that bypasses biometric — it cannot be
flipped by editing a world-readable runtime file.

## Rejected alternative: `pam_sudowhat` marker + `timeout=0` detection

With the cache **off**, "the auth phase did not run this invocation" would
*uniquely* mean NOPASSWD (no cache hits to confuse it with). `pam_sudowhat` runs
only when real auth happens, so it could leave a per-invocation marker; the
approval plugin could read "no marker + `timeout=0` => NOPASSWD => step aside."
The operator's `timeout=0` instinct does map onto a real detection mechanism.

Rejected because:

1. **Spoofable channel.** The cross-module marker (in-process symbol or on-disk
   file) is the kind of fragile, forgeable signal the design has avoided
   elsewhere (cf. the rejected daemon; SCDynamicStore reachability caveats).
2. **Hard-couples correctness to `timeout=0`.** The moment anyone sets
   `timeout>0`, a cache hit becomes indistinguishable from NOPASSWD, so the
   plugin would silently step aside on *cached* commands too — breaking the
   "prompt every command" guarantee for the console user. A silent regression
   triggered by an unrelated knob.

The explicit allowlist has neither problem: signature-covered, exact, and
independent of the timeout setting.

## Open decision

Require the sha256 pin per entry, or make it optional (recommended-in-docs)?
Requiring it is stricter (lean this way for a v1 security feature); optional is
more ergonomic for fast-changing local scripts.

## References

- `docs/design-noncon-sudo.md` — non-console NOPASSWD path (shipped v0.5.0);
  `command_info` has no auth signal (`:154-162`); console re-prompt comes from
  the approval plugin not `timeout=0` (`:329-334`).
- `sudo_plugin(8)` — approval plugin API; `command_info` keys.
- sudo-project issue #415 — no option to tell PAM a NOPASSWD command is running:
  https://github.com/sudo-project/sudo/issues/415
- Red Hat solution 3320531 — NOPASSWD skips the PAM auth flow:
  https://access.redhat.com/solutions/3320531
