# Design note: Linux port (Phase 2) — terminal command display via a sudo audit plugin

**Status: IN PROGRESS (targeting ~v0.11.0).** Phase 1 (v0.10.0, macOS) split
terminal command **display** into a standalone sudo *audit* plugin
(`plugin/sudowhat_audit.m`) whose `open()` runs before any auth, with the
escape/quote logic ported to Rust (`shared/escape_core/`). Phase 2 delivers that
same display on **Linux**, where there is no biometric: a user runs `sudo <cmd>`,
sees `user / directory / command` on the terminal, then gives their password to
sudo's **native `pam_unix`**. No verify code (no GUI sheet to channel-bind), no
approval plugin, no PAM module. Sibling to `docs/design-terminal-mode.md`
(the cross-platform display-layer design) and `docs/design-noncon-sudo.md`.

## What ships

- **One pure-Rust `cdylib`** (`linux/sudowhat_audit/`), a `crate-type =
  ["cdylib"]` that path-depends on `shared/escape_core` and calls its
  escape/quote/command-line functions directly — same language, no FFI
  round-trip, no ObjC, no Foundation/Security. Built offline/reproducibly from a
  committed `Cargo.lock` (zero external dependencies, matching escape_core's
  ethos).
  - `src/display.rs` — pure, host-testable: parse sudo's `key=value` context
    arrays (a `find_kv` twin) and assemble the exact block the macOS plugin
    emits, byte-for-byte, via `escape_core`.
  - `src/tty.rs` — the `/dev/tty` write via hand-declared libc FFI
    (`open`/`write`/`close`/`isatty`), `O_WRONLY|O_NOCTTY|O_CLOEXEC`, `isatty()`
    gate, no stderr fallback.
  - `src/lib.rs` — the FFI shell: the `#[repr(C)]` `struct audit_plugin` layout,
    the `#[no_mangle] pub static sudowhat_audit_plugin`, and `open()` doing
    root-exempt → build block → write → return `1`.
- **NixOS packaging**: `nix/package-linux.nix` (the cdylib derivation),
  `nix/nixos-module.nix` (`services.sudowhat` writing `/etc/sudo.conf`), and the
  multi-platform `flake.nix`.
- **Non-Nix install**: `install/linux/install.bash` /
  `install/linux/uninstall.bash` (install the `.so` to
  `/usr/local/libexec/sudo/`, print the `sudo.conf` to write) and
  `config/linux/sudo.conf.sample`.
- **Makefile**: `build-linux` / `test-linux` / `install-linux` /
  `uninstall-linux`, guarded by `uname` so a macOS `make` is byte-for-byte
  unchanged.

## Resolved design forks (confirmed with the user)

### 1. Audit plugin only — no Linux `pam_sudowhat`

sudo itself already enforces the entire Linux trust model. Per `sudo.conf(5)`
(verified against sudo.ws): *"The file must be owned by user-ID 0 and only
writable by its owner"* — sudo refuses to load a plugin, or read `sudo.conf`,
that fails this, fail-closed. The only thing macOS `pam_sudowhat` adds on top is
**code-signing**, which Linux lacks and which we are told not to rebuild. A Linux
integrity module would merely re-check sudo's own guarantee while forcing an
invasive `/etc/pam.d/sudo` edit (brick risk) for zero net gain. The audit plugin
is display = disclosure, not auth; if it is absent or misconfigured it simply
shows nothing and never weakens auth.

### 2. Always display

There is no biometric path to be redundant with, so no session re-derivation and
no `SessionGuard` — the same unconditional behaviour the macOS audit plugin
already has (root-exempt, needs a command word and a `/dev/tty`).

### 3. Pure-Rust `cdylib`, reusing `escape_core` directly

No ObjC, no FFI round-trip through escape_core's C ABI — `display.rs` calls the
crate's Rust functions (`escape_control`, `quote_token`, `full_command_line`)
directly. escape_core gains a second crate-type (`["staticlib", "lib"]`): the
`.a` still feeds the macOS bundle unchanged; the added rlib is what this crate
links.

### 4. Full NixOS packaging (user chose this)

A multi-platform flake, a Linux package build, and a `nixosModules.default` that
writes `/etc/sudo.conf`.

## Trust model (Linux) — to be documented, not engineered

- Integrity = **sudo's own** root-owned + non-writable enforcement on the plugin
  `.so` and `sudo.conf`. We add nothing here.
- **No** code-signing anchor, **no** tamper-evidence claim (stated plainly — this
  mirrors `docs/design-terminal-mode.md`'s *"Linux gets the UX, not the
  tamper-evidence"*). An attacker with root can swap the plugin; that is a fact
  to document, not a flaw to fix.
- The plugin **fails soft**: any problem (no tty, no command, bad UTF-8) → show
  nothing, never break sudo. `open()` returns `1` (loaded) always, never `-1`
  (a display convenience must not DoS sudo). Unknown API generation → `0`
  (decline cleanly).

## The Linux-specific wrinkle: `sudo.conf` must re-declare the sudoers plugins

Unlike macOS, once `/etc/sudo.conf` contains **any** `Plugin` line, sudo no
longer auto-loads its default `sudoers` policy (`sudo.conf(5)`: the defaults
apply only when there are *no* `Plugin` lines). So the Linux `sudo.conf` we write
MUST include the stock sudoers lines alongside ours, or sudo loses its policy
entirely and every `sudo` fails:

```
Plugin sudoers_policy sudoers.so
Plugin sudoers_io     sudoers.so
Plugin sudoers_audit  sudoers.so
Plugin sudowhat_audit_plugin  /usr/local/libexec/sudo/sudowhat_audit.so
```

Bare `sudoers.so` resolves relative to sudo's own plugin dir (sudo's default), so
no absolute path is needed for the sudoers lines. `sudo.conf` has no include
directive, so the file must be written whole. (macOS did not need this — Apple's
sudo keeps sudoers built-in.) **Flag for the on-hardware check:** confirm this
host's sudo resolves bare `sudoers.so` in its default plugin directory.

## Byte-for-byte parity with macOS

`display.rs` reuses `escape_core`, the same crate the macOS bundle links, so the
anti-spoofing rules (control/bidi/zero-width/homoglyph neutralised, literal `\`
doubled) and the command-line assembly are identical by construction. The block
shape is a direct port:

```
sudowhat: user: <target user>
sudowhat: directory: <invoking cwd>        (omitted when cwd is absent)
sudowhat: input: <command as typed>
```

Bold label emphasis is gated by `NO_COLOR` / `TERM` (env) plus the `isatty()`
final gate — identical to `sw_audit_color_allowed`. The `echoColor` anomaly
colouriser is the same documented fast-follow as on macOS (accepted, renders
plain until `colorizeEscaped:` is ported into escape_core).

## Verification

**On this macOS dev host (what is runnable here):**

- `cd linux/sudowhat_audit && cargo test` — the pure `display.rs` / `tty.rs`
  unit tests assert the block matches the macOS format for plain, quoted, and
  control-char / Unicode-spoof inputs (parity inherited from escape_core).
- `cargo build --release` (host = darwin `.dylib`) — validates the `repr(C)`
  struct, the `#[no_mangle]` static export, and the const-fn-pointer init compile
  cleanly. The artifact is not shippable; it only proves the ABI/code is
  well-formed. The exported symbol is confirmed present (`nm` shows
  `_sudowhat_audit_plugin`; Linux drops the leading `_`).
- `make test-unit` — regression guard that the escape_core `crate-type` change
  did not disturb the macOS build (`test_escape_core` still links the `.a`).

**On a Linux box / CI (cannot run on this darwin host — no Linux linker):**

- Build the cdylib, install to `/usr/local/libexec/sudo/sudowhat_audit.so`, write
  the sample `sudo.conf`, then:
  - `sudo /bin/echo hi` → `sudowhat: user: … / directory: … / input: /bin/echo
    hi` prints **before** `[sudo] password:`; sudo still enforces policy (sudoers
    lines present).
  - `sudo /bin/echo $'a\nb'` → control char escapes literally (`\n`), no raw
    byte.
  - No controlling tty (piped) → nothing printed, sudo unaffected.
  - Root invoker → no display (root-exempt).
  - `chmod o+w` the `.so` → sudo itself refuses to load it (confirms sudo's own
    perms enforcement is the trust anchor).
- NixOS: `nix build .#packages.x86_64-linux.default`; a `nixosTest` asserting the
  module writes `sudo.conf` (with the sudoers lines) and the display appears.

## Explicitly NOT doing (this change)

- No Linux code-signing / tamper-evidence, no Linux PAM module (resolved above).
- No resolved-path last-look / anomaly colouriser (future on both platforms).
- No trim of the macOS mutual-signature web — a separate, macOS-only pass,
  deliberately kept out of the Linux port.

Relates to [[project-terminal-mode-audit-plugin]], [[project-architecture]],
[[idea-full-command-terminal-echo]].
