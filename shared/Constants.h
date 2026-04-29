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
 * Both bundles must agree on the absolute install paths and the symbol name
 * sudo's dlsym call expects.
 */

#ifndef SUDOWHAT_CONSTANTS_H
#define SUDOWHAT_CONSTANTS_H

#include <string.h>

#ifndef SUDOWHAT_TEAM_ID
#define SUDOWHAT_TEAM_ID "-"
#endif

/* Macro form so callers can embed at compile time. */
#define SUDOWHAT_IS_DEV_BUILD() (strcmp(SUDOWHAT_TEAM_ID, "-") == 0)

#define SUDOWHAT_PLUGIN_PATH    "/usr/local/libexec/sudo/sudowhat_approval.so"
#define SUDOWHAT_PAM_PATH       "/usr/local/lib/pam/pam_sudowhat.so"
#define SUDOWHAT_PLUGIN_SYMBOL  "sudowhat_approval_plugin"
#define SUDOWHAT_SUDO_CONF      "/etc/sudo.conf"

#endif
