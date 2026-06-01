# Design note: legitimate non-console sudo

Status: design recommendation for the project author. Scope: how sudowhat should
treat a non-root, non-console caller without reopening the hole the console guard exists
to close.

## Problem restated

sudowhat's console guard (`SessionGuard isInvokingUserActiveConsole:`, the deny at
`plugin/sudowhat_approval.m:270-275`) currently denies *every* non-root, non-console
caller without prompting. That is correct and safe, but it strands two legitimate
populations:

- **Case 1 — remote interactive admin.** A human SSH'd into the box, sitting at a real
  controlling tty (the SSH PTY), who needs per-command root. Today: hard deny.
- **Case 2 — unattended automation.** A launchd job, CI runner, cron task, or service
  account with *no human and possibly no tty*, that needs scoped root. Today: hard deny
  (correctly — there is nobody to authenticate).

The hard constraint that governs both: **no auth surface may ever render on the active
console session's screen on behalf of a non-console caller.** That is the entire reason
the guard exists, and nothing below is allowed to weaken it. Two further project
invariants bound the solution space: no daemon, no agent, no IPC, no cloud; and every
error path fails closed (deny).

## The key lever

The load-bearing insight across all four candidate designs is **auth-surface routing by
caller class**: the *deny* in the guard is not a security primitive in itself — it is a
proxy for "do not raise a GUI sheet for this caller." Once you separate *which surface*
authenticates from *whether to authenticate*, the guard can become a fork instead of a
wall.

Why this is sound, grounded in the threat model:

- **Reflexive approval is specifically a GUI-on-console threat.** Both GUI surfaces this
  codebase uses — `LAContext.evaluatePolicy` (`sudowhat_approval.m:434`) and
  `AuthorizationCreate(kAuthorizationFlagInteractionAllowed)` (`:491`) — route through
  SecurityAgent / authd, which draw on the **active foreground GUI session regardless of
  the triggering uid or the `seteuid` in effect** (the `seteuid(g_inv.uid)` at `:392`
  binds the *account* the sheet authenticates, not the *screen* it renders on). So a
  non-console caller that reaches either call can pop a sheet in front of the seated
  user, who taps it out of habit. *That* is the hole.
- **A tty-password surface is safe for a non-console caller.** `SUDO_CONV_PROMPT_ECHO_OFF`
  delivered through sudo's own conversation function is plain terminal I/O on the *sudo
  process's controlling tty* — for an SSH-launched sudo, the SSH PTY, **not** the console
  tty. The console user never sees it and is never asked to approve anything. Design D's
  red-team verified this directly: TIOCSTI is restricted on modern macOS and writing
  another session's PTY needs privilege the attacker lacks, so a non-console caller
  cannot redirect this prompt onto the console user's terminal.
- **The AS / LAContext GUI surface is NOT safe for a non-console caller, and must never
  be used for one.** Design C's analysis is the decisive negative result here: Apple's
  BiometricsOrCompanion (Watch/iPhone) is a *same-session SEP-brokered confirmation of a
  locally rendered sheet*, not an out-of-band push. Any attempt to "approve remotely" via
  LAContext for a non-console caller either fails (no Aqua session) or, if a console
  session happens to exist, renders the sheet **in the console user's session** and lets a
  proximate device confirm it — i.e. it silently degenerates back into the exact reflexive
  case. The companion factor cannot be repurposed as a non-console channel.

Where the red-team *qualified* the lever: it holds structurally (no candidate that keeps
`rendersOnConsoleEver = false` was shown to reopen reflexive approval), but it is not
free. Routing a non-console caller to a tty password **re-introduces a password-handling
path into setuid-root sudo** — the class of code `docs/language-choice.md` calls "the
genuinely dangerous code" — and the safety of *that* path depends entirely on getting the
PAM verification semantics right. Design D's review found two concrete, shipping-blocking
defects in the naive version (see Required fixes). So: the lever is correct, but the
tty-password surface is only as safe as its verification, and the GUI surface is *never*
an option for case 1.

## Recommended design

**Combine surface-routing (Design A/D) for case 1 with a pre-authorization policy table
(Design B) for case 2, both consulted strictly inside the existing would-deny branch,
both fail-closed, both default-off.** Reject Design C's remote-companion channel outright.

The two mechanisms are disjoint and composable, mirroring the existing three-way split
(root / console / else):

```
sudowhat_check:
  1. mutual SecStaticCode integrity of pam_sudowhat.so   (:226-232)  -> fail => deny
  2. if g_inv.uid == 0:  root exemption, syslog, allow   (:254-263)
  3. resolve command + run_argv + pre-stat (dev,inode)   (hoisted above the guard)
  4. if isInvokingUserActiveConsole(g_inv.uid):
         existing GUI path UNCHANGED                      (:277-549)
  5. else  // non-root, non-console: today's hard deny
         // ---- case 2 first: standing consent, no human ----
         d = GrantTable.evaluateForUid(uid, abspath, argv, tty?, preStat)
         if d == GRANT_ALLOW:
             re-stat (dev,inode) == preStat else deny
             syslog(LOG_AUTHPRIV) resolved argv + grant id
             return allow
         // ---- case 1: interactive remote admin ----
         if remote_tty_opt_in_active()  AND g_inv.have_tty  AND g_conv != NULL:
             plugin_printf(resolved command + verify nonce) -> caller's tty
             if verify_admin_group(g_inv.uid)  // authorization, not just identity
                AND verify_tty_password(g_conv, g_inv.uid)  // SUDO_CONV_PROMPT_ECHO_OFF
                                                            // + EUID-dropped PAM authn
                                                            // against a sudowhat-owned
                                                            // service (NOT stock checkpw)
                re-stat (dev,inode) == preStat else deny
                syslog(LOG_AUTHPRIV) success, uid, tty
                return allow
             else:
                syslog(LOG_AUTHPRIV) FAILURE, uid, tty   // brute-force visibility
                rate-limit / backoff; deny
         // ---- everything else ----
         syslog(LOG_AUTHPRIV) denied uid
         return deny   // == today's behavior
```

Grant table is consulted *before* the tty prompt so that a standing, root-authored
capability never forces a human prompt for a flow the operator already declared
unattended.

### Config surface

Two independent, root-owned, default-off opt-ins under `/etc/sudowhat/` (directory
`root:wheel 0755`, provisioned by the installer / nix-darwin module the same way the
existing three `/etc` artifacts are, and store-owned under nix-darwin so it rotates
atomically with the package):

- **Case 1 — `/etc/sudowhat/allow-remote-tty`** (Design D's minimal knob; nix-darwin
  `services.sudowhat.allowRemoteTTY`, default `false`). Presence-and-ownership is the
  entire signal; **no content, no parser, no attack surface.** Integrity check, exactly:
  `lstat` (never `stat`), reject symlink, require `S_ISREG`, require `st_uid == 0`, reject
  `S_IWGRP | S_IWOTH`, **and** apply the same checks to the parent `/etc/sudowhat`
  directory. Any failure -> opt-in treated inactive -> deny.
- **Case 2 — `/etc/sudowhat/policy.d/*.grant`** (Design B). Each grant is an *exact*
  tuple: `uid`, absolute `path`, `argv-sha256` or literal argv array, optional
  `not-before`/`not-after`, `require-tty`, `require-pristine`. Files `root:wheel 0644`,
  dir `root:wheel 0755`; opened with `openat(O_NOFOLLOW)` + `fstat`-after-open (never
  trust a path stat). In **release** builds each grant carries a detached signature (or an
  HMAC manifest under a `root:wheel 0600` key) verified via the existing
  `shared/SignatureVerifier` patterns; integrity failure => the *whole table* is treated
  as empty => deny (never "fall back to perms-only"). **Wildcard / prefix argv matching is
  not offered** — argv[0] and `--flag` injection are exactly the sudoers-NOPASSWD footguns
  this is meant to beat. Authoring a grant runs through the *normal console-gated* sudo
  path, so minting a grant requires a present console user's biometric — the bootstrap is
  closed against an SSH-only attacker.

### Auth surface, per case, and where it renders

- **Case 1:** a masked `SUDO_CONV_PROMPT_ECHO_OFF` prompt on the **caller's own
  controlling tty** (the SSH PTY), with the resolved command + verify nonce echoed there
  immediately above it. No LAContext, no AuthorizationServices, nothing on the console.
  The conversation pointer that `sudowhat_open` currently discards (`(void)conversation;`
  at `:123`) is stashed in a file-scope `g_conv`, mirroring `g_plugin_printf`, and cleared
  in `sudowhat_close`.
- **Case 2:** **no live challenge at all.** The "authentication" happened out-of-band when
  root authored the grant; the only rendering is a `LOG_AUTHPRIV` audit line (always) plus,
  if a tty exists, a one-line `plugin_printf` notice to the caller's own stderr naming the
  matched grant. Nothing is ever drawn on the GUI.

### Required fixes (incorporated, non-negotiable — from the Design D red-team)

These are the difference between a defensible password path and a passwordless-root
regression:

1. **Never use the stock `/etc/pam.d/checkpw` service.** Confirmed on this box it is
   `auth required pam_opendirectory.so use_first_pass nullok` — `nullok` means an account
   with an empty/unset password hash authenticates with an **empty string**. A reachable
   empty-hash account (service account, never-set local account, attacker-created account)
   would yield passwordless non-console root, which strict sudowhat blocks absolutely.
   Ship a dedicated, signed-package, root-owned service file (`/etc/pam.d/sudowhat-tty`:
   `auth required pam_opendirectory.so`, **no `nullok`**), and additionally reject any
   empty supplied password before calling PAM. An empty password must never authenticate.
2. **Feed the password the way the service reads it.** With `use_first_pass`,
   pam_opendirectory reads `PAM_AUTHTOK`, *not* the conversation — so a conversation-only
   implementation can silently fail to check the real password. Call
   `pam_set_item(pamh, PAM_AUTHTOK, collected_pw)` before `pam_authenticate`. Test that a
   wrong password and an empty password both fail.
3. **Verify authorization, not just identity.** `checkpw`-style PAM proves who you are, not
   that you may elevate. The console path inherits admin-gating from sudo's own PAM stack;
   this branch must reproduce it — explicitly verify admin/wheel group membership for
   `g_inv.uid` before accepting the password.
4. **Rate-limit / backoff / lockout** on consecutive failures for a uid, and abort after N.
   A raw PAM loop otherwise hands an attacker full-speed remote brute-force with root as
   the prize; SecurityAgent gives the console path this for free.
5. **Audit both success and failure** via `syslog(LOG_AUTHPRIV)` with uid and source tty,
   so denials and brute-force attempts are visible — not just successes.
6. **Implement the opt-in integrity check exactly as in Config surface above, with a test**
   (lstat, symlink reject, `S_ISREG`, `st_uid==0`, no group/world write, parent-dir check).
   A `stat`-instead-of-`lstat` or a missing parent check reopens a symlink-plant bypass.

### Fail-closed behavior (every path)

Missing/malformed/wrong-owner/symlinked opt-in or grant file => inactive => deny.
Opt-in active but `!g_inv.have_tty` or `g_conv == NULL` => deny with diagnostic (this is
the unattended-no-human guard for case 1). Conversation returns non-zero / NULL reply
(Ctrl-C / EOF / timeout) => deny. PAM anything but `PAM_SUCCESS`, `pam_start` failure, or
OpenDirectory unreachable => deny. Empty supplied password => deny. Not in admin group =>
deny. `seteuid(g_inv.uid)` fails before verification => error; `seteuid(0)` restore fails
after => `_exit(1)`, identical to the existing invariant at `:518-519` — sudo must never
exec with a non-root EUID. Grant integrity failure in release => table empty => deny.
Post-auth `(dev,inode)` re-stat mismatch => deny (shared with the console path's TOCTOU
narrowing, which now wraps *both* new surfaces). The mutual SecStaticCode check (`:226-232`)
and the root exemption (`:254-263`) run before any of this.

## What we deliberately will NOT do

- **No AS / LAContext / biometric / companion sheet for a non-console caller, ever.** This
  is the one rule the whole project is built on; Design C demonstrates that "approve on the
  phone" cannot be done without either rendering on the console session (reopening the hole)
  or building the rejected daemon. `rendersOnConsoleEver` stays `false` on every non-console
  branch, by construction.
- **No daemon, no agent, no XPC helper, no APNs/cloud, no remote-companion approval
  channel.** Out of scope — it requires a resident endpoint to terminate an async channel,
  i.e. the `.trash/agent/` design already cut. A code comment must be left at the guard
  deny site warning future maintainers that BiometricsOrCompanion is *not* an out-of-band
  channel.
- **No wildcard or prefix argv in pre-auth grants.** Exact path + exact-argv-or-argv-hash
  only.
- **No fail-open password fallback and no use of stock `checkpw`.** Every error denies;
  empty passwords never authenticate.
- **No headless credential path for case 2 that isn't a root-authored standing grant.**
  Truly unattended non-root automation that needs ad-hoc root remains punted to the root
  exemption (run it as root via `launchctl asuser <uid> sudo`, audited) — inventing a
  non-interactive secret channel would reopen the unattended-escalation hole.
- **No per-command scoping promise on the case-1 knob.** When `allow-remote-tty` is on,
  every command from a non-console caller becomes elevatable with the admin password; that
  is documented, coarse-by-design, and the reason case 2's fine-grained grants exist
  alongside it.

## Phasing

- **Phase 1 — ship now (Design D, hardened): the minimal remote-tty knob for case 1.**
  Stash `g_conv` at open(); add the sub-branch at `:270`; `allow-remote-tty` presence
  check; `SUDO_CONV_PROMPT_ECHO_OFF` + EUID-dropped PAM against the sudowhat-owned service.
  Must ship *with* all six Required fixes and a prominent default-off + threat-model note.
  This is genuinely a week of work and is the correct minimal answer for interactive remote
  admin.
- **Phase 2 — next release (Design B): the pre-authorization grant table for case 2.**
  Needs `GrantTable.{h,m}`, the signing/HMAC integrity tooling, and the `sudowhat grant`
  CLI built and reviewed first. Do **not** ship the perms-only dev variant as the *only*
  integrity story for a capability that grants passwordless root.
- **Phase 2.5 — optional (Design A refinements over D).** If empirical testing favors it,
  upgrade case 1 from the presence-only knob to A's stronger tty-ownership *proof*
  (`open("/dev/tty", O_NOCTTY)`, `isatty`/`tcgetsid(fd)==getsid(0)`/`st_uid==uid` binding,
  cross-checked against the tty captured at open()) and A's bounded `allow_uids` policy.
  This narrows a leaked-knob from firing in an unexpected session. Treat as a hardening
  delta on Phase 1, not a separate design.
- **Future / out-of-scope (Design C).** Remote-companion approval. Only the second-factor
  *verify-nonce display* sub-idea is ship-now-eligible, as a docs/UX note on the existing
  nonce print (`:351`) — an eyeball aid, explicitly *not* a cryptographically bound
  channel.

## Open questions / things to verify on real hardware (macOS Tahoe)

1. **tty password conversation from an *approval* plugin in `check()`.** The conversation
   pointer is passed to `open()` (currently discarded at `:123`), but whether sudo cleanly
   routes a `SUDO_CONV_PROMPT_ECHO_OFF` issued from the approval plugin's `check()` to the
   controlling tty with proper echo-off termios handling is asserted from the API, not yet
   exercised. **Verify before Phase 1 ships, with a documented sudo version pin.** Fallback
   to verify: whether the password step must instead live in the PAM module (which already
   owns a stack) rather than the approval plugin.
2. **Exactly where AS/LAContext renders for a non-console, `seteuid`'d caller.** We assert
   (and Design D's review confirms by source inspection) that SecurityAgent/authd draw on
   the active GUI session regardless of `seteuid`. Confirm empirically that there is *no*
   configuration in which a non-console seteuid'd caller's sheet renders anywhere the
   triggering remote process can drive — this is the assumption that justifies the entire
   guard, and it should be tested, not just reasoned about.
3. **PAM verification semantics.** Confirm `pam_set_item(PAM_AUTHTOK, ...)` +
   `pam_authenticate` against the no-`nullok` `sudowhat-tty` service rejects both wrong and
   empty passwords, and that the admin-group authorization check matches the privilege the
   console path actually grants.
4. **`tcgetsid(fd) == getsid(0)` session binding under macOS sudo** (only if pursuing the
   Phase 2.5 ownership proof). macOS sudo may detach or re-set the session; the proof must
   be validated against real behavior or it spuriously denies legitimate sessions
   (fail-closed, but a usability regression).
5. **Audit-log format.** Settle the `LOG_AUTHPRIV` line shape for the three new outcomes
   (tty success, tty failure, grant match) so it is greppable and consistent with the
   existing root-exemption line at `:260`.
6. **`require-pristine` staleness** (Phase 2). A content-hash recorded at grant-creation
   goes stale when an OS update replaces the target binary, turning into a silent outage —
   decide whether `require-pristine` defaults off and how operators re-bless after updates.
