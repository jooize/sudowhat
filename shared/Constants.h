/*
 * Shared constants for sudowhat_approval (sudo plugin) and pam_sudowhat
 * (PAM module).
 *
 * SUDOWHAT_TEAM_ID is provided at build time via -DSUDOWHAT_TEAM_ID=\"...\".
 * When it equals "-", the build is in ad-hoc / dev mode: SignatureVerifier
 * validates that signatures are intact but does not enforce a
 * team-identifier requirement. In release builds, the team-ID requirement
 * is enforced.
 *
 * SUDOWHAT_PLUGIN_PATH and SUDOWHAT_PAM_PATH default to /usr/local for the
 * stock make/install flow, but can be overridden at build time via
 * -DSUDOWHAT_PLUGIN_PATH=... / -DSUDOWHAT_PAM_PATH=... so a Nix derivation
 * can bake its own $out store paths in. Both bundles must agree on these
 * paths and on the symbol name sudo's dlsym call expects.
 */

#ifndef SUDOWHAT_CONSTANTS_H
#define SUDOWHAT_CONSTANTS_H

#include <string.h>

#ifndef SUDOWHAT_TEAM_ID
#define SUDOWHAT_TEAM_ID "-"
#endif

/* Macro form so callers can embed at compile time. */
#define SUDOWHAT_IS_DEV_BUILD() (strcmp(SUDOWHAT_TEAM_ID, "-") == 0)

#ifndef SUDOWHAT_PLUGIN_PATH
#define SUDOWHAT_PLUGIN_PATH    "/usr/local/libexec/sudo/sudowhat_approval.so"
#endif

#ifndef SUDOWHAT_PAM_PATH
#define SUDOWHAT_PAM_PATH       "/usr/local/lib/pam/pam_sudowhat.so"
#endif

/* The audit plugin owns terminal command display (its open() runs before the
 * PAM password prompt on every path). Overridable at build time like the paths
 * above so a Nix derivation can bake its own $out store path. Optional at
 * runtime: absent -> no terminal display, but auth is unaffected; present-but-
 * tampered -> the approval plugin and pam_sudowhat fail closed (mutual-signature
 * web). See docs/design-terminal-mode.md. */
#ifndef SUDOWHAT_AUDIT_PATH
#define SUDOWHAT_AUDIT_PATH     "/usr/local/libexec/sudo/sudowhat_audit.so"
#endif

#define SUDOWHAT_PLUGIN_SYMBOL  "sudowhat_approval_plugin"
#define SUDOWHAT_AUDIT_SYMBOL   "sudowhat_audit_plugin"
#define SUDOWHAT_SUDO_CONF      "/etc/sudo.conf"
#define SUDOWHAT_SUDO_LOCAL     "/etc/pam.d/sudo_local"

/* Module argument that selects pam_sudowhat's second role, the console-gate
 * (vs. its default integrity role when invoked with no argument). The PAM
 * gate-variant `sudo_local` passes it as
 *   auth sufficient <pam_sudowhat.so> console-gate
 * and the approval plugin looks for this exact token when deciding whether the
 * non-console password path is installed. One definition, three readers
 * (nix module emits it, pam_sudowhat branches on it, the plugin checks it). */
#define SUDOWHAT_GATE_ARG       "console-gate"

/* Policy-deference marker. pam_sudowhat's auth entry (either role) sets this
 * environment variable when it runs, and the approval plugin reads it in
 * check() to learn whether sudo entered the PAM auth conversation for THIS
 * invocation. sudo runs the auth stack only when sudoers requires
 * authentication; NOPASSWD, a root invoker, `Defaults !authenticate`, and a
 * valid timestamp cache all skip it entirely, so the module never runs and the
 * marker stays absent. Absent (with the integrity line still installed) means
 * "sudoers waived authentication" — the signal the approval plugin uses to skip
 * its own Touch ID prompt so a NOPASSWD command just runs.
 *
 * setenv() modifies this sudo process's environ; the approval plugin (same
 * process, later in the same run) reads it with getenv(). It is process-local
 * and never crosses a trust boundary: a caller can pre-set it in sudo's
 * inherited environment, but that only FORCES a prompt (marker present ->
 * prompt), the fail-safe direction — it can never clear the marker once
 * pam_sudowhat has run. One definition, two readers (pam sets it, the plugin
 * reads it). See docs/design-noncon-sudo.md ("policy deference"). */
#define SUDOWHAT_AUTH_MARKER_ENV "SUDOWHAT_AUTH_RAN"

#endif
