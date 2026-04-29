---
name: Trusted-prompt sudo wrapper (future project)
description: Idea for a separate project — build a sudo-style wrapper that displays the exact command being authorized in a system-trusted UI before requiring Touch ID, fixing the wedge where a compromised shell can swap commands behind a generic "sudo wants permission" Touch ID prompt.
type: project
originSessionId: 5a5ec67e-ae3c-417f-a39f-754b311e5094
---
User raised this 2026-04-29 while designing the lock/unlock workflow.

**Problem:** macOS sudo + `pam_tid.so` Touch ID prompt doesn't show *what* is being authorized. A compromised shell can `alias unlock='sudo chown /etc/passwd …'` and the user biometrically approves it, thinking they're unlocking their own file.

**Why:** Sudo elevation should bind authentication to the *specific command*, not just "this user is sudo'ing right now."

**How to apply:** Treat as an out-of-scope future project, not a blocker for the current lock/unlock work. Layer B (the `/usr/local/bin/locked` wrapper script) addresses adjacent concerns (input validation, fixed binary path) but doesn't solve the prompt-trust gap. Build the trusted-prompt project separately when there's appetite.

**Implementation sketch:**
- macOS Authorization Services (`AuthorizationCreate`/`AuthorizationCopyRights`) supports custom prompt strings — the Touch ID/password dialog *can* show the exact command if invoked via Authorization Services with environment-supplied prompt.
- Or `LocalAuthentication` framework: `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "<the exact command>", reply:)` — the Touch ID dialog displays `localizedReason` text.
- Combine with a privileged helper (LaunchDaemon as root, communicated via XPC or signed Unix socket) that executes the authorized command as the target user.
- Few hundred lines of Swift. Precedents in the macOS app ecosystem (e.g., `SMJobBless`-style helpers).

**Naming / scope ideas:**
- A general-purpose `tsudo` (trusted sudo) replacing the role of sudo for specific privileged operations.
- Or domain-specific: a `locked` binary that handles only lock/unlock with trusted prompts, no general elevation.
