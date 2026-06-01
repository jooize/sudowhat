/*
 * pam_sudowhat — PAM auth module that integrity-checks the sudowhat
 * approval plugin and the sudo.conf entry that loads it. This is a
 * precondition for trusting the Touch ID prompt the plugin will render:
 * if the plugin file has been swapped or the sudo.conf line removed,
 * sudo would either run with no approval gate or load the wrong code.
 *
 * On success returns PAM_SUCCESS; the requisite + sufficient pair in
 * /etc/pam.d/sudo_local terminates the auth chain — no password fallback
 * at the PAM layer (the LAContext / Authorization Services prompt later
 * is the user-facing auth gate). On any failure returns PAM_AUTH_ERR
 * and sudo aborts.
 */

#import <Foundation/Foundation.h>
#include <syslog.h>
#include <string.h>
#include <pwd.h>

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "Constants.h"
#import "SignatureVerifier.h"
#import "SudoConfChecker.h"
#import "SessionGuard.h"

static const char *utf8_or(NSString *s, const char *fallback) {
    const char *p = s.UTF8String;
    return (p && *p) ? p : fallback;
}

/* macOS's pam_appl.h doesn't declare pam_syslog. Use the stdlib syslog
 * directly with a stable tag. */
static void sudowhat_log(int prio, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char buf[512];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    syslog(prio | LOG_AUTHPRIV, "pam_sudowhat: %s", buf);
}

__attribute__((visibility("default")))
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                         int argc, const char *argv[]) {
    (void)flags;

    @autoreleasepool {
        /* Second role — the CONSOLE-GATE. The non-console gate variant of
         * /etc/pam.d/sudo_local invokes this same module a second time as
         *   auth sufficient <pam_sudowhat.so> console-gate
         * Succeed ONLY for the local console (GUI) user: a `sufficient` success
         * breaks the chain so the console user is never asked for a password
         * (the approval plugin's Touch ID is their gate). For ANY non-console
         * caller, fail so the parent /etc/pam.d/sudo chain falls through to
         * sudo's native pam_smartcard / pam_opendirectory password on the
         * caller's OWN tty.
         *
         * Integrity is deliberately NOT re-checked here: it is the separate
         * `requisite` line that runs before this one. Keeping them as two lines
         * (one signed binary) means a tamper still dies at the requisite line
         * rather than falling through to a password that could defeat it. */
        if (argc >= 1 && argv[0] != NULL
            && strcmp(argv[0], SUDOWHAT_GATE_ARG) == 0) {
            const char *userName = NULL;
            if (pam_get_user(pamh, &userName, NULL) != PAM_SUCCESS
                || userName == NULL) {
                sudowhat_log(LOG_ERR,
                             "console-gate: could not determine invoking user");
                return PAM_AUTH_ERR;
            }
            struct passwd *pw = getpwnam(userName);
            if (pw == NULL) {
                sudowhat_log(LOG_ERR,
                             "console-gate: no passwd entry for user '%s'",
                             userName);
                return PAM_AUTH_ERR;
            }
            if ([SudoWhatPamSessionGuard isInvokingUserActiveConsole:pw->pw_uid]) {
                return PAM_SUCCESS;   /* local console: no password here */
            }
            return PAM_AUTH_ERR;      /* non-console: fall through to password */
        }

        /* First role — INTEGRITY (no module argument). */
        NSError *err = nil;
        if (![SudoWhatConfChecker verifyConfPath:@SUDOWHAT_SUDO_CONF
                                  expectedSymbol:@SUDOWHAT_PLUGIN_SYMBOL
                                    expectedPath:@SUDOWHAT_PLUGIN_PATH
                                           error:&err]) {
            sudowhat_log(LOG_ERR, "sudo.conf check failed: %s",
                         utf8_or(err.localizedDescription, "unknown"));
            return PAM_AUTH_ERR;
        }

        if (![SudoWhatPamSigVerifier verifyPath:@SUDOWHAT_PLUGIN_PATH error:&err]) {
            sudowhat_log(LOG_ERR, "approval plugin signature check failed: %s",
                         utf8_or(err.localizedDescription, "unknown"));
            return PAM_AUTH_ERR;
        }

        return PAM_SUCCESS;
    }
}

__attribute__((visibility("default")))
int pam_sm_setcred(pam_handle_t *pamh, int flags,
                    int argc, const char *argv[]) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
