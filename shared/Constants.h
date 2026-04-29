/*
 * Shared constants for tsudo_approval (sudo plugin) and pam_tsudo (PAM module).
 *
 * TSUDO_TEAM_ID is provided at build time via -DTSUDO_TEAM_ID=\"...\". When it
 * equals "-", the build is in ad-hoc / dev mode: SignatureVerifier validates
 * that signatures are intact but does not enforce a team-identifier
 * requirement. In release builds, the team-ID requirement is enforced.
 *
 * Both bundles must agree on the absolute install paths and the symbol name
 * sudo's dlsym call expects.
 */

#ifndef TSUDO_CONSTANTS_H
#define TSUDO_CONSTANTS_H

#include <string.h>

#ifndef TSUDO_TEAM_ID
#define TSUDO_TEAM_ID "-"
#endif

/* Macro form so callers can embed at compile time. */
#define TSUDO_IS_DEV_BUILD() (strcmp(TSUDO_TEAM_ID, "-") == 0)

#define TSUDO_PLUGIN_PATH    "/usr/local/libexec/sudo/tsudo_approval.so"
#define TSUDO_PAM_PATH       "/usr/local/lib/pam/pam_tsudo.so"
#define TSUDO_PLUGIN_SYMBOL  "tsudo_approval_plugin"
#define TSUDO_SUDO_CONF      "/etc/sudo.conf"

#endif
