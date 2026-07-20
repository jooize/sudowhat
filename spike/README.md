# Policy-deference spike

A self-contained check of the one runtime assumption the console **NOPASSWD skip**
(policy deference) rests on:

> A `setenv()` made inside a PAM auth module is visible via `getenv()` in the
> process that ran `pam_authenticate()`.

In production, `pam_sudowhat`'s auth entry sets `SUDOWHAT_AUTH_RAN`, and the
approval plugin reads it back **in the same `sudo` process** to learn whether
sudo ran the PAM auth stack (i.e. whether sudoers required authentication). If
that read works, an absent marker reliably means "sudoers waived auth"
(NOPASSWD / `!authenticate` / root / cached), and the plugin skips its prompt.

This is near-certain — openpam is an in-process library, and the approval and
policy plugins both run in the main `sudo` process per the `sudo_plugin(8)`
invocation-order contract — and the "PAM does not run on NOPASSWD" half is
already established in `docs/design-noncon-sudo.md`. The spike confirms the
setenv→getenv half end-to-end before anyone relies on it.

## What it does (and does not) touch

- Builds two throwaway binaries: `spike_pam.so` (an auth module that `setenv`s a
  marker) and `spike_driver` (calls `pam_authenticate` then `getenv`).
- Installs an **isolated** PAM service `/etc/pam.d/sudowhat-spike` and removes it
  on exit (one `sudo` to write the file).
- Does **not** touch `sudo`, `/etc/sudo.conf`, `/etc/pam.d/sudo`, or
  `sudo_local`. Grants nothing: the module's `sufficient` success applies only to
  the isolated `sudowhat-spike` service, never to sudo.

## Run it

From a **real terminal** (it needs one `sudo` to write the test service file):

```sh
./spike/run-spike.sh
```

fish shell: `bash ./spike/run-spike.sh`.

- **PASS** (exit 0): `getenv` saw the marker. The production mechanism is sound —
  proceed to deploy and run the hardware verification below.
- **FAIL** (exit 1): the marker was not visible as tested. Do **not** rely on the
  getenv marker; report it. The fallback is a pid-keyed side channel (a file the
  module writes and the plugin reads, keyed on sudo's pid) — the mode-wiring and
  the `sw_defer_decision` gate are independent of how the signal is carried, so
  only the transport would change.

## After the spike passes: hardware verification of the real build

The spike proves the primitive; these confirm the whole feature on real sudo
(cannot be automated — Claude Code has no controlling tty). Deploy the new build
first (for this repo's nix-darwin pin: bump the ref/rev and `darwin-rebuild
switch`), then, in a real terminal:

1. **Console, auth required** → a normal `sudo` still shows Touch ID + the verify
   code on the tty, exactly as before.
2. **Console, NOPASSWD** → add e.g. `you ALL=(root) NOPASSWD: /usr/bin/true` to a
   sudoers fragment; `sudo /usr/bin/true` runs with **no sheet and no password**.
   (With `echoDeferred = "tty"`/`"always"`, the user/path/command lines appear.)
3. **Root** → `sudo -i` then `sudo /usr/bin/true`: no prompt (unchanged root
   exemption; marker absent, consistent).
4. **Tamper drill (the important one)** → as root, comment out the
   `auth requisite …pam_sudowhat.so` line in `/etc/pam.d/sudo_local`, then run a
   NOPASSWD `sudo`. The plugin must **PROMPT** (fail-safe), not skip, because the
   integrity line is no longer wired. Restore the line afterward.
5. **timestamp interaction** (only if you run a non-zero `timestampTimeout`) →
   `sudo cmd1` (prompts), then `sudo cmd2` within the window on the same tty:
   `cmd2` runs with no sheet (cached credential, marker absent). Under the
   default `timestampTimeout = 0` every command prompts.

See the "Policy deference" section of `docs/design-noncon-sudo.md` for the full
rationale, and `docs/plan-policy-deference.md` for the implementation plan.
