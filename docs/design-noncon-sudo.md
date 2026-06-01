# Design note: legitimate non-console sudo

Status: design recommendation for the project author. Scope: how sudowhat should
let a non-root, non-console caller use sudo without reopening the hole the console
guard exists to close — by **deferring to sudo's own machinery instead of rebuilding
it inside the plugin.**

This note supersedes an earlier draft that proposed a signed grant table and a
plugin-internal PAM password path. Both reinvented mechanisms sudo already ships. The
design below was then adversarially red-teamed against this box (Tahoe / Darwin 25.4.0);
the safety framing in particular changed as a result — see "What the plugin can and
cannot know."

## Problem restated

sudowhat's console guard (`SessionGuard isInvokingUserActiveConsole:`, the deny at
`plugin/sudowhat_approval.m:270`) denies *every* non-root, non-console caller without
prompting. That is correct and safe, but it strands two legitimate populations:

- **Unattended automation.** A LaunchAgent / cron job / service account (e.g. uid 501)
  that needs scoped root while no human is present — possibly with no tty.
- **Remote-interactive admin.** A human SSH'd into their own Mac, at a real PTY,
  who needs per-command root while logged out of (or away from) the GUI.

The hard constraint that governs both: **no auth surface may ever render on the active
console session's screen on behalf of a non-console caller.** That is the entire reason
the guard exists. Two further project invariants bound the solution: no daemon / agent /
IPC / cloud, and every error path fails closed (deny).

## The reframe: stop adding a layer

The original guard treats *every* non-console caller as untrusted because, with the
default PAM config, sudowhat's biometric is the *only* real authentication — sudo's PAM
stack is short-circuited (`sudo_local`: `requisite pam_sudowhat.so` then
`sufficient pam_permit.so`), so PAM authenticates *nobody*. Under that config, letting a
non-console caller past the guard would hand them root with no authentication at all.
The guard is what prevents that.

But sudo already has machinery for exactly these two populations, and it is more battle-
tested than anything sudowhat would write:

- **Unattended automation → a sudoers `NOPASSWD` rule with an exact command.**
  `automation ALL=(root) NOPASSWD: /usr/local/bin/backup --to /vol/snap` already gives
  exact uid + exact path + exact argv + no prompt + authpriv logging. This is what a
  "grant table" would have reinvented, minus the argv[0]/flag-injection footguns that
  come free with sudoers' exact matching. No new sudowhat artifact.

- **Remote-interactive admin → sudo's native `pam_opendirectory` password path.**
  `/etc/pam.d/sudo` on this box already ends with `auth required pam_opendirectory.so`
  — **no `nullok`** — preceded by `auth sufficient pam_smartcard.so`. That is sudo's
  normal, decades-tested tty password conversation. Using it (a) inherits the no-`nullok`
  hardening for free, (b) prompts on the *caller's own* PTY via sudo's native machinery —
  the console user never sees it — and (c) means the plugin never collects the secret, so
  the earlier draft's "can the plugin read a password off the tty/stdin?" blocker simply
  evaporates.

So sudowhat's job shrinks to one thing.

## The one sudowhat-specific problem

For a non-console caller, sudo's own machinery already decides authorization (sudoers)
and (for a password rule) authentication. But **the approval plugin runs on top of that
decision and currently denies non-console regardless.**

A NOPASSWD rule does **not** bypass the plugin. `sudo_plugin(8)` fixes the invocation
order as *policy open → approval open/check/close → command runs*, and states the
approval `check()` runs "after the policy plugin `check_policy()` function" and is called
"if the policy plugin's `check_policy()` function has returned successfully." The trigger
is **policy approval, not authentication.** NOPASSWD only tells sudoers to skip the PAM
password step *inside* `check_policy`; sudoers still returns success, so sudo still calls
the approval plugin. (This is exactly why 0.4.2 needed the root exemption: root-initiated
sudo authenticates nobody either, yet the plugin still ran and denied it.) So the
unattended NOPASSWD case genuinely requires the plugin to step aside.

The only real work is:

> Make the approval plugin **step aside** for a non-console caller that sudo has already
> authorized — returning allow *without ever rendering a GUI/biometric sheet* — but only
> when the configuration guarantees that a non-console caller cannot reach success without
> a real authentication factor on its own session.

Two open questions had to be resolved on real macOS before this was buildable. Both are
answered from the authoritative on-box man pages and the existing shipped PAM behavior.

### (a) Can the plugin tell from `command_info[]` how (or whether) the caller authenticated? — No.

`sudo_plugin(8)` enumerates every `command_info` key sudo recognizes
(`command`, `cwd`, `runas_*`, `noexec`, `iolog_*`, `set_utmp`, `sudoedit*`, `timeout`,
`umask*`, `use_pty`, …). **None carries the authentication decision** — there is no
`nopasswd`, `authenticated`, or `timestamp` key. (The only auth-adjacent keys —
`ignore_ticket`, `update_ticket`, `noninteractive` — live in `settings[]`, which the
approval plugin's `open()` does receive, but they reflect what the *user requested on the
command line* (`-k`/`-N`/`-n`), not what PAM actually did.) So the plugin cannot
distinguish, for a non-console caller: a fresh password, a cached sudo timestamp, or a
NOPASSWD rule. They are identical at `check()` time.

**Consequence — and this reshapes the whole safety argument:** step-aside cannot be an
*authentication*-trust decision (the plugin has no signal that authentication happened
this invocation). It is an **authorization**-trust decision: sudoers authorized the
caller, and the plugin verifies the *configuration* makes a no-authentication success
impossible for a non-console caller — except where the operator deliberately wrote a
NOPASSWD rule. See "What the plugin can and cannot know."

### (b) How does the PAM chain fall through to `pam_opendirectory` for non-console only?

openpam has no Linux-PAM bracket syntax (`[success=done default=die]`) — confirmed:
`pam.conf(5)` documents only the simple control flags `required`, `requisite`,
`sufficient`, `binding`, `optional`. The fall-through is achieved with `sufficient`
alone, using a property of openpam that Linux-PAM does *not* share. `pam.conf(5)` on this
box states for `sufficient`:

> "If this module succeeds, the chain is broken and the result is success. If it fails,
> the rest of the chain still runs, but the final result will be failure **unless a later
> module succeeds**."

That last clause is the lever. Replace today's `sufficient pam_permit.so` with a
`sufficient` **console-gate** that **succeeds iff the caller is the console user** and
**fails otherwise**:

```
# /etc/pam.d/sudo_local  (non-console-enabled variant)
# NOTE: the module path is the FULL store path, never the bare name — pam_sudowhat.so is
# not in openpam's /usr/lib/pam search dir, so a bare "pam_sudowhat.so" line would fail to
# load (and a sufficient line whose module fails to load does not succeed → even console
# users would fall through to a password prompt). The exact string is generated once and
# shared by the installer and the plugin (see "What the plugin can and cannot know").
auth  requisite   /nix/store/<hash>-sudowhat-<ver>/lib/pam/pam_sudowhat.so               # integrity; PAM_SUCCESS, or die on tamper
auth  sufficient  /nix/store/<hash>-sudowhat-<ver>/lib/pam/pam_sudowhat.so  console-gate  # PAM_SUCCESS iff console; PAM_AUTH_ERR iff non-console
```

`/etc/pam.d/sudo` is the OS-managed parent and is **not** sudowhat's file. On this box
(and in Apple's stock template) it reads:

```
auth  include     sudo_local
auth  sufficient  pam_smartcard.so
auth  required    pam_opendirectory.so
```

openpam's `include` splices inline — this is **already proven** by the shipped config,
whose `sufficient pam_permit.so` inside `sudo_local` short-circuits the *parent* chain so
sudo never falls through to `pam_opendirectory` (if it didn't splice inline, today's
console users would be getting a password prompt — they aren't). So the effective auth
chain is:

```
1. requisite   pam_sudowhat.so               (integrity)
2. sufficient  pam_sudowhat.so  console-gate
3. sufficient  pam_smartcard.so
4. required    pam_opendirectory.so
```

- **Tamper:** (1) `requisite` fails → chain broken → sudo aborts. *(fail-closed, unchanged)*
- **Console caller:** (1) ok; (2) succeeds → chain broken, success → never reaches
  smartcard/opendirectory → **no password**. LAContext in the approval plugin is the gate.
  *(behavior unchanged, but see the configd caveat below — a console user MAY be downgraded
  to a password prompt if the gate cannot reach configd to confirm console membership.)*
- **Non-console caller:** (1) ok; (2) **fails** → "rest of the chain still runs". Now
  exactly one of:
  - (3) `sufficient pam_smartcard.so` **succeeds** → chain breaks with **success**;
    `pam_opendirectory` is never reached. This is *not* a fall-through — `sufficient`
    success is itself the terminal authentication, satisfied by the caller's own PIV/token
    + PIN **on the caller's own session**. No console sheet. Acceptable: a smartcard is a
    real factor, no weaker than the console biometric it replaces.
  - (3) smartcard absent/declined → continue; (4) `required pam_opendirectory.so` prompts
    for the **password on the caller's own PTY**. Correct → a later module succeeded →
    overrides the gate's failure → **success**. Wrong/empty → `required` failure → deny.

  The invariant that makes the non-console path safe is therefore not "it always reaches
  the password prompt" but: **every terminal-success path after the failed gate is a
  genuine authentication factor satisfied on the caller's own session, never on the
  console, and never weaker than the console factor.** Both `pam_smartcard` and no-`nullok`
  `pam_opendirectory` meet that; an unauthenticated `sufficient` success (e.g. `pam_permit`)
  does not, which is why the plugin must verify no such line exists (below).

`console-gate` is the same `pam_sudowhat.so`, invoked a second time with a module
argument; `pam_sm_authenticate` branches on `argv[0]`. Integrity must stay a separate
`requisite` line (a single `sufficient` module returning failure-on-tamper would fall
through to `pam_opendirectory` and a known password would defeat the integrity check —
so integrity dies, the gate falls through; two lines, one signed binary).

**Console detection inside the PAM module is a hard prerequisite, not a soft check.** The
gate calls `SCDynamicStoreCopyConsoleUser` — but that call is environment-sensitive:
demonstrated on this box, the *same binary* returns `consoleUid = 501` when configd is
reachable from its bootstrap namespace and `consoleUid = (uid_t)-1` ("no console user")
when it is not, while a uid-501 GUI session is live the whole time. The gate's contract
must therefore be **positive-match-only, failing toward non-console**: return
`PAM_SUCCESS` *only* when `SCDynamicStoreCopyConsoleUser` returns a non-NULL user with a
valid `consoleUid` that is non-zero and equals the invoking uid; on **any** NULL / `-1` /
error, return `PAM_AUTH_ERR` (force the password fall-through). The failure modes:
  - configd unreachable for a genuine console sudo → gate fails → console user is prompted
    for a `pam_opendirectory` password instead of Touch ID. A UX regression, fail-closed.
    (This is why "behavior identical to today" is **not** claimed.)
  - The dangerous direction is a *split-brain* between this read and the plugin's own
    `SessionGuard` read (two independent `SCDynamicStore` calls, two lifecycle phases): if
    the PAM gate sees console (skips password) while the plugin sees non-console (steps
    aside), the caller gets root with neither a password nor a sheet. Within a single sudo
    process the two reads almost certainly see the same configd reachability, but this must
    be **demonstrated on hardware** (open item), and if they can ever disagree the two
    reads must be collapsed to a single source of truth.

## What the plugin can and cannot know

Because `command_info[]` carries no authentication signal (a), the plugin **cannot**
confirm that this invocation authenticated. What it *can* do is verify that the live
configuration makes an unauthenticated non-console success impossible — i.e. that the
whole effective chain still terminates in a real factor. The password module lives in
`/etc/pam.d/sudo`, **not** `sudo_local`, so checking `sudo_local` alone is insufficient
(this was the red-team's blocker). Before stepping aside for a non-console caller, the
plugin must verify the **complete effective chain**:

1. **`/etc/pam.d/sudo_local` is the gate variant** — contains the `requisite … pam_sudowhat.so`
   integrity line and the `sufficient … pam_sudowhat.so console-gate` line, with the **exact
   full store path** (see below). Absence → deny (today's behavior).
2. **`/etc/pam.d/sudo` still has a safe shape** — `auth include sudo_local` appears first,
   then **no unconditional-success `sufficient` module** (`pam_permit`, a `pam_tid`/
   `pam_reattach`-style Touch-ID-over-SSH line, etc.) anywhere after the include, and the
   chain terminates in `auth required pam_opendirectory.so` **without `nullok`**. This is
   the file an admin, MDM profile, or third-party PAM tool is most likely to edit; a stray
   `sufficient pam_permit.so` after the include would let a non-console caller short-circuit
   to success with no factor. Any deviation → deny.
3. **The credential cache is not cross-session** — `timestamp_type` is the default `tty`
   (or `ppid`/`kernel`), **never `global`**. The timeout *value* is the operator's choice
   (see below); only `global` is rejected, because it is the one mode that lets a timestamp
   established in one session (e.g. a console Touch ID) be reused by another (an SSH session
   of the same uid). Verify a root-owned, non-group/world-writable sudoers fragment does not
   set `timestamp_type=global` and that no later-ordered file does either.

If any check fails, is unreadable, or is untrusted → **deny** (fail-closed, == today).

```
sudowhat_check (non-console branch, replacing the deny at :270):
  if NOT effective_chain_is_safe():     # the three checks above
      syslog(LOG_AUTHPRIV) denied uid    # == today
      return deny
  # sudoers authorized this caller, and the configuration guarantees a non-console caller
  # cannot reach success without a real factor on its own session (password / smartcard),
  # OR via an operator-authored NOPASSWD rule. Either way, rendering a sheet here would put
  # it on the console user. Step aside.
  syslog(LOG_AUTHPRIV) non-console allow, uid, tty
  return allow                           # BEFORE any seteuid/LAContext/AS call
```

Step-aside returns *before* the `seteuid(g_inv.uid)` + LAContext/AS block, so
`rendersOnConsoleEver` stays `false` on every non-console path.

### Three corrections this design makes to its own earlier claims

- **Not "drift-proof by construction."** The plugin reads config *text* at `check()`-time;
  PAM ran earlier (policy phase), in a separate read. Text is not proof of what PAM did.
  The chain checks are **defense-in-depth against misconfiguration and composition
  footguns**, not a guarantee. The residual trust is that *root-owned* PAM/sudoers files
  have not been altered by someone with root — which is **out of the threat model** (an
  attacker who can rewrite `/etc/pam.d/sudo` is already root and needs none of this). State
  that boundary explicitly rather than claiming impossibility.

- **The credential cache: `timestamp_type` is the real control, the timeout *value* is the
  operator's choice.** sudo caches credentials for `timestamp_timeout` minutes (default 5);
  a cache hit makes `check_policy()` succeed *without invoking PAM at all* — an
  authentication short-circuit the plugin cannot see (no `command_info` signal). But this is
  **not** a reason to force `timeout=0`; it splits cleanly by path:
  - **Console:** the gate is the *approval plugin* (LAContext), which fires on every
    `check_policy` success — including cache hits *(verify: open item #1)*. The timestamp
    cache only skips the PAM *password*, which the console path doesn't use. So at any
    timeout the console user still Touch-IDs every command; the cache gives console no
    benefit and (if approval fires on cache hits) no harm. The "re-prompt every command"
    guarantee comes from the approval plugin, **not** from `timeout=0`.
  - **Non-console:** under the default `timestamp_type=tty` the record is *per terminal*
    (`sudoers(5)`: "login sessions are authenticated separately"), and the only way
    `check_policy` succeeds — and writes that tty's record — for a non-console caller is by
    passing a **real factor on that tty** (`pam_smartcard`/`pam_opendirectory`). So any later
    cache hit on that tty was always preceded by a real authentication on that same tty: the
    plugin stepping aside on it is exactly stock-sudo grace after a real auth, no weaker than
    stock sudo over SSH. The timeout value is therefore safe to leave to the operator.
  - **The one genuinely unsafe mode is `timestamp_type=global`** ("a single record for all of
    a user's login sessions, regardless of the terminal"): a *console* user authenticates
    (sudo writes a global record), logs out, SSHes back as the same uid — now non-console,
    hits the record, PAM is skipped, plugin steps aside → root with no factor the SSH caller
    ever supplied. So the plugin **rejects `global`** (check 3) and otherwise leaves
    `timestamp_timeout` to the operator. (This corrects the earlier draft, which forced
    `timeout=0`; that conflated the console and non-console cases and denied a legitimate
    convenience.) Cross-session reuse aside, the only no-authentication non-console path that
    remains is a NOPASSWD rule — the operator's explicit exact-command grant.

- **On NOPASSWD, `pam_sudowhat` never runs at all.** For a NOPASSWD rule sudo never enters
  the PAM auth conversation, so *neither* `sudo_local` line executes. The approval plugin's
  own `SecStaticCode` check of the `pam_sudowhat.so` file (`:228`) still runs (the plugin
  always runs), but it only attests the binary on disk is signed — it does **not** attest
  that PAM loaded or executed it. On the NOPASSWD path, sudowhat-side assurance rests
  entirely on (i) sudoers exact-command matching and (ii) the chain checks above, which run
  for every non-console caller including NOPASSWD jobs. Do not cite `:228` as the
  authentication guarantee for NOPASSWD.

### The gate-line string must be one generated source of truth

Claim 5's whole value depends on the plugin's check matching what the installer writes —
and the installer writes the **full store path** (`${cfg.package}/lib/pam/pam_sudowhat.so`,
e.g. `…-sudowhat-0.4.2/…`), which changes on every version/hash bump. A bare-name check
never matches (and a bare-name *config line* won't even load); a hard-coded full-path
check silently stops matching after an upgrade (→ denies all non-console, i.e. it *does*
drift); a loose substring check can be satisfied by a comment or stale file. Fix: derive
the gate line from a single constant in `nix/module.nix` and compile the **same** resolved
string into the plugin at build time (the package already bakes `SUDOWHAT_PAM_PATH`; add a
`SUDOWHAT_GATE_LINE` from the same expression). Add a build-time test asserting the string
the plugin checks for is byte-identical to the line `module.nix` emits. *That* test is what
actually delivers the coupling the safety argument needs.

### Verifying the config files without fooling yourself

- **Content match is the primary, decisive signal** — exactly as the existing
  `SudoConfChecker` does for `/etc/sudo.conf`. Ownership of the *resolved* target is
  **vacuous** under nix-darwin (every `/nix/store` path is `root r--r--r--` by
  construction), so do not lean on it.
- **Path integrity is whole-chain, lstat-based, no dereference.** `/etc/pam.d/sudo_local`
  is a symlink *chain* (here: `→ /etc/static/pam.d/sudo_local → /nix/store/…`, 2 hops, not
  1). `lstat` each hop, require uid 0 and a root-owned, non-group/world-writable *parent
  dir* at every hop, loop until a non-symlink leaf (cap iterations against cycles), and read
  the content from an `O_NOFOLLOW` fd you `fstat` — never `realpath`-then-reopen, never stat
  only the leaf. `SudoConfChecker` as written uses `stringWithContentsOfFile` (follows
  symlinks, no stat at all), so it does **not** provide this — it must be extended.

## Why this is safe (threat walk-throughs)

- **SSH attacker (admin user, non-console), `allowNonConsole` on:** sudoers authorizes
  (they are admin); the gate fails for non-console; the caller authenticates on their own
  PTY via `pam_opendirectory` (password) or `pam_smartcard` (PIV + PIN) — never a console
  sheet. Unknown factor → deny. Known factor → ordinary "an admin who proves a factor can
  sudo over SSH," the stock sudo trust model; the *reflexive-approval* hole (a sheet the
  seated user taps) is never engaged.
- **Same attacker within the grace window:** if the operator runs a non-zero
  `timestamp_timeout`, a second command on the *same tty* within the window skips the
  password — but only after a real first authentication on that tty (default `tty` scope),
  i.e. ordinary stock-sudo grace, not a new hole. The cross-session ride is closed by
  rejecting `timestamp_type=global` (check 3). Operators wanting per-command re-auth set
  `timestamp_timeout=0` (today's default).
- **SSH attacker, `allowNonConsole` off (default):** plugin finds the `pam_permit` variant
  (or any failed chain check) → denies non-console without prompting. Identical to today.
- **Unattended NOPASSWD job (uid 501):** sudoers authorizes via the exact-command NOPASSWD
  rule; PAM is not invoked (operator's explicit no-auth grant); the plugin verifies the
  effective chain is safe and steps aside. No password, no sheet — stock NOPASSWD semantics,
  scoped to one exact command by the operator.
- **Admin adds Touch-ID-over-SSH (`pam_tid`/`pam_reattach`) to `/etc/pam.d/sudo`:** check 2
  detects the unconditional-success `sufficient` line after the include and **denies** the
  non-console step-aside — protecting the admin from a composition that would otherwise be
  passwordless.
- **Reflexive approval (the original threat):** unchanged for console callers (LAContext
  with the command shown). For non-console callers, no LAContext/AS is ever reached.

## What we deliberately will NOT do

- **No grant table.** A sudoers NOPASSWD rule is the grant table, with better matching
  semantics and no new signed artifact, parser, or `sudowhat grant` CLI to attack.
- **No plugin-internal PAM / password collection.** sudo's native `pam_opendirectory`
  conversation does it, on the right tty, with no `nullok`. The plugin never touches the
  secret.
- **No custom no-`nullok` service file.** `/etc/pam.d/sudo`'s native `pam_opendirectory`
  line already has no `nullok`. Do **not** authenticate against stock `/etc/pam.d/checkpw`
  — it carries `nullok`. Nothing in this design touches `checkpw`.
- **No forbidding of `pam_smartcard`.** A PIV/token + PIN on the caller's own session is a
  legitimate non-console factor, no weaker than the console biometric. The design accepts
  it; it does not special-case or block it.
- **No AS / LAContext / biometric / companion sheet for a non-console caller, ever.**
  `BiometricsOrCompanion` is a *same-session* SEP confirmation of a locally rendered
  sheet, **not** an out-of-band push. "Approve on the phone" for a non-console caller
  either fails (no Aqua session) or renders in the *console* user's session — reopening
  the exact hole. True remote approval needs the rejected daemon. Out of scope. Leave a
  code comment at the step-aside site stating this, so no future maintainer reuses
  `seteuid` + LAContext/AS for a non-console uid.
- **No per-command scoping promise on the interactive knob.** With `allowNonConsole` on,
  every command from a non-console caller is elevatable with the admin's factor; that is
  documented, coarse by design, and the reason NOPASSWD rules exist alongside it for the
  fine-grained unattended case.

## Recommended shape (config surface)

A **single** opt-in, because the halves cannot be safely separated: allowing a non-console
*password* rule requires the fall-through PAM variant (otherwise step-aside + short-circuit
= passwordless root), and NOPASSWD rules work regardless. "Unattended-only, no interactive
admin" is not a sudowhat knob — it is achieved in **sudoers** by writing only NOPASSWD
rules for the specific automation and granting no broad sudo to remote users.

- **nix-darwin:** `services.sudowhat.allowNonConsole` (default `false`) selects the gate
  `sudo_local` variant. `timestamp_timeout` stays an independent operator setting (the
  module may keep today's `0` as its *default* but must not force it); the module must never
  emit `timestamp_type=global`. It does **not** manage `/etc/pam.d/sudo` (Apple's stock
  template already provides the safe `include → smartcard → required opendirectory` shape);
  the plugin verifies that file's shape at runtime instead.
- **Approval plugin:** the three-check `effective_chain_is_safe()` gate above, fail-closed.

## Open items to verify on real hardware before shipping

The *mechanism* is grounded in this box's `sudo_plugin(8)` / `pam.conf(5)` and the
already-shipped `include` short-circuit behavior. `sudo` is blocked under the agent
sandbox, so the end-to-end behavior was not exercised here. Before shipping, confirm:

1. **Live console-gate fall-through.** With the gate variant installed: (i) a console
   `sudo` authenticates via LAContext with **no** password prompt; (ii) a non-console `sudo`
   (second `ssh localhost`, logged out of the GUI, or `su - otheradmin` then `sudo`) prompts
   for a password via `pam_opendirectory` **on that session's tty** and nowhere on the
   console; (iii) wrong/empty password denies; (iv) a NOPASSWD rule runs with no prompt;
   (v) the **full-path** gate line actually loads (a misload would silently break the
   console short-circuit too). Pin the sudo version. **(vi) Pivotal — does the approval
   plugin re-run on a timestamp cache hit?** With `timestamp_timeout` non-zero, run
   `sudo cmd1` then `sudo cmd2` within the window on the same tty and confirm the LAContext
   prompt fires for `cmd2`. If it does, the console guarantee is independent of the timeout,
   so `timestamp_timeout` can be an operator knob; if it does **not**, a non-zero timeout
   means later in-window commands run with no prompt at all — so neither of sudowhat's two
   purposes (showing the exact command, and binding the prompt to the origin terminal)
   applies to them — and `timeout=0` must stay for the console path. This determines whether
   the timeout is freely user-configurable.
2. **`pam_smartcard` for a non-console caller.** Confirm `pam_smartcard` matches the
   credential to the **invoking uid**, not merely "a card in the locally attached reader,"
   so a card inserted/unlocked for the console user cannot satisfy a non-console caller; and
   that a non-admin cannot register a CTK/third-party token provider that forges a match.
3. **Credential-cache scope.** Confirm `timestamp_type=global` is absent (no fragment sets
   it, none re-sets it later). Confirm that for non-console under the default `tty` scope a
   cache hit on a tty is always preceded by a real factor on that same tty. The timeout
   *value* is an operator preference, gated by item 1(vi).
4. **Console detection inside the PAM module.** Confirm `SCDynamicStoreCopyConsoleUser`
   returns the correct `consoleUid` from inside `pam_sm_authenticate` under real macOS sudo
   for (i) console login, (ii) SSH, (iii) launchd/cron-spawned sudo — and that the PAM-phase
   read and the approval-phase (`SessionGuard`) read **agree** in all three. If they can
   disagree, collapse them to a single source of truth. Confirm the positive-match-only,
   fail-toward-non-console contract holds when configd is unreachable. (On this box the same
   binary already returns `consoleUid=-1` vs `501` purely by bootstrap-namespace
   reachability — so this is not hypothetical.)
5. **Whole-chain config verification.** Implement and test the three `effective_chain_is_safe()`
   checks, the lstat-per-hop symlink-chain integrity, and the build-time gate-line equality
   test. Verify a `sufficient pam_permit.so` appended to `/etc/pam.d/sudo` after the include
   causes the plugin to **deny** the non-console step-aside.
6. **Audit-log line shape** for the new non-console-allow outcome, consistent with the
   root-exemption line at `:260`.

## Adjacent hygiene (independent of the above)

- A tripwire comment at the step-aside site warning maintainers never to reuse
  `seteuid` + LAContext/AS for a non-console uid (see "What we will NOT do").
- The README (`:38`) and prior-art doc already describe `BiometricsOrCompanion`
  accurately as a same-session / companion-confirmation factor (the prior-art table even
  notes the PAM family "degrades to `pam_opendirectory` password over SSH" — the very
  lever used here). Keep that wording; do not let it drift toward implying an out-of-band
  channel.
