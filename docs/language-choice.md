# Language choice — Objective-C/C, not Swift

**Decision:** the two loadable bundles (`plugin/` sudo approval plugin and
`pam/` PAM module) stay in Objective-C/C. A Swift rewrite was evaluated and
rejected. Swift is reserved for a *future* standalone `sudowhat status` CLI,
where none of the constraints below apply.

This document records *why*, so it isn't re-litigated.

## Context

The trigger was a sense that the codebase had grown "large." It hasn't: the
two bundles are ~1,369 LOC total, already split into `SignatureVerifier`,
`SessionGuard`, and `PromptFormatter`. What reads as "big" is repo breadth
(`plugin/ pam/ config/ install/ nix/ shared/`) plus the one ~530-line
`plugin/sudowhat_approval.m` — roughly half of which is security-reasoning
comments, not logic. None of that shrinks under a rewrite; the comments would
port verbatim.

## Why Swift is the wrong tool for *these* bundles

1. **A pure-Swift rewrite is impossible.** sudo's approval-plugin ABI requires
   an exported C *global* — `struct approval_plugin sudowhat_approval_plugin`,
   a struct of function pointers at a fixed symbol that sudo resolves with
   `dlsym` (`plugin/sudowhat_approval.m`). Swift's `@_cdecl` — and the official
   `@c` that replaces it (SE-0495) — apply to **functions only, never global
   variables**. The plugin symbol must therefore be defined in a hand-written
   C/Objective-C translation unit regardless. Best case is Swift *plus* a C
   shim: more languages, not fewer.

2. **It injects the Swift runtime into setuid-root sudo and into PAM.** A Swift
   `.so` pulls `libswiftCore` (often `_Concurrency`/`libdispatch` too) into
   whatever `dlopen`s it, and the runtime does eager work at load time
   (scanning `__swift5_proto`, registering conformance callbacks). Apple's
   guidance (Quinn "The Eskimo!", Apple DevRel) is explicit: it is *"not safe
   to create such plug-ins in Swift unless you control all the plug-ins and the
   app loading those plug-ins,"* and two plug-ins each linked to their own
   Swift runtime in one process *"will be Bad."* PAM is exactly a multi-plugin
   `dlopen` host (`pam_tid`, `pam-watchid`, etc. can coexist), so that hazard
   is live. This adds the most code and initialization surface to the *most
   privileged* process in the system, for no functional gain.

   (Note: it is *not* accurate to say "sudo already has the Objective-C runtime
   resident, so libobjc is free." sudo is a lean setuid-root C binary; libobjc
   and Foundation enter its address space only because the plugin links them.
   The honest framing: an Objective-C plugin adds libobjc plus the frameworks
   it calls; a Swift plugin adds all of that *plus* the entire Swift runtime.
   The "larger surface" conclusion holds either way.)

3. **The safety dividend lands where there is no hazard.** The genuinely
   dangerous code — `AuthorizationCreate` with its `AuthorizationItem` /
   `AuthorizationRights` / `AuthorizationEnvironment` C structs, the `seteuid`
   drop/restore, the `open`/`fstat` TOCTOU `(dev, inode)` compare — all forces
   Swift's *unsafe* subset (`UnsafeMutablePointer`, `withUnsafe…`, raw buffers,
   `@convention(c)`). The one part Swift would clean up, `PromptFormatter`'s
   string handling, is already memory-safe via `NSString`/Foundation.

4. **No automated test oracle for the trust-critical path.** `install/self-test.bash`
   checks wiring (the `sudo.conf` line, file modes, PAM config), not the auth /
   EUID / TOCTOU sequence. Reimplementing audited, working security code with
   no equivalence harness is high risk for an aesthetic gain.

5. **Tooling timing.** The C entry points still require `@_cdecl`, an
   underscored/unofficial attribute, until `@c` (SE-0495) ships in Swift 6.3 /
   Xcode 27 (~Sept 2026).

## The honest counterpoint

`PromptFormatter` is the one place a Swift port would genuinely help: it is
hand-rolled `unichar`/`NSUInteger` index arithmetic (surrogate-pair splits,
unsigned-subtraction wrap guards) and it is the anti-spoofing boundary, so
Swift's `String` would erase a bug class. But it is already correct and already
memory-safe through Foundation, and it is unit-testable in Objective-C today
(see `tests/`). The win there is defense-in-depth on already-safe code, not a
fix. Public Swift PAM modules do exist (`pam-watchid`, `pam-touchID`); a Swift
sudo *approval* plugin does not — consistent with point 1.

## What to do instead

- **Refactor within Objective-C** (not rewrite): de-duplicate `SignatureVerifier`
  (currently copied in `plugin/` and `pam/`) into `shared/`; collapse the
  open()-time file-scope globals into one context struct.
- **Keep the EUID-drop → auth → restore → TOCTOU sequence as one linear,
  auditable block** — do not scatter it across helpers; its correctness is
  legible only when read as a single trust window.
- **Add unit tests for the pure helpers** — done: `make test-unit` covers
  `PromptFormatter` (escaping/quoting/truncation), `find_kv`, and the nonce.
- **Reserve Swift for a future `sudowhat status` CLI** (README roadmap) — a
  standalone executable with no setuid context and no C-ABI export constraint.

## Sources

- Swift Evolution SE-0495 (`cdecl` / `@c`):
  https://github.com/swiftlang/swift-evolution/blob/main/proposals/0495-cdecl.md
- Swift underscored attributes (`@_cdecl` "not designed for production"):
  https://github.com/swiftlang/swift/blob/main/docs/ReferenceGuides/UnderscoredAttributes.md
- Apple Developer Forums — Swift in `dlopen`'d / multi-plugin hosts (Quinn):
  https://developer.apple.com/forums/thread/89482
- Swift ABI stability ships with the OS (macOS 10.14.4+):
  https://www.swift.org/blog/abi-stability-and-apple/
- Swift PAM module precedent: https://github.com/biscuitehh/pam-watchid ,
  https://gist.github.com/geofft/257647efe3963f74b20044bd61048ddd
