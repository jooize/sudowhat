/*
 * pam_sudowhat — PAM auth module that integrity-checks the sudowhat
 * approval plugin and the sudo.conf entry that loads it. This is a
 * precondition for trusting the Touch ID prompt the plugin will render:
 * if the plugin file has been swapped or the sudo.conf line removed,
 * sudo would either run with no approval gate or load the wrong code.
 *
 * On success returns PAM_SUCCESS; the requisite + sufficient pair in
 * /etc/pam.d/sudo_local terminates the auth chain — no password fallback
 * at the PAM layer (the LAContext prompt later
 * is the user-facing auth gate). On any failure returns PAM_AUTH_ERR
 * and sudo aborts.
 *
 * A module argument selects one of two further roles, each keyed on whether
 * the caller is the local console (GUI) user: `console-gate` (nonConsole =
 * "password") and `console-only` (nonConsole = "nopasswd-only").
 */

#import <Foundation/Foundation.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
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

/* Show one line to the caller through the application's PAM conversation
 * (sudo prints a PAM_ERROR_MSG on the caller's terminal). Best effort: with no
 * conversation, or one that fails, the refusal still stands, unexplained. */
static void sudowhat_conv_error(pam_handle_t *pamh, const char *text) {
    const void *item = NULL;
    if (pam_get_item(pamh, PAM_CONV, &item) != PAM_SUCCESS || item == NULL) {
        return;
    }
    const struct pam_conv *conv = item;
    if (conv->conv == NULL) return;
    /* openpam declares msg as `char *`; neither PAM nor sudo writes through it. */
    struct pam_message msg = { .msg_style = PAM_ERROR_MSG, .msg = (char *)text };
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;
    if (conv->conv(1, &msgp, &resp, conv->appdata_ptr) == PAM_SUCCESS
        && resp != NULL) {
        free(resp->resp);
        free(resp);
    }
}

__attribute__((visibility("default")))
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                         int argc, const char *argv[]) {
    (void)flags;

    @autoreleasepool {
        /* Policy-deference marker. Our auth entry running AT ALL means sudo
         * entered the PAM auth conversation — i.e. sudoers required
         * authentication for this invocation. NOPASSWD, a root invoker,
         * `Defaults !authenticate`, and a valid timestamp cache all skip the
         * auth stack, so this module never runs for them and the marker stays
         * absent; the approval plugin reads that absence to skip its own prompt
         * (a NOPASSWD command just runs). Set for BOTH roles, before any return,
         * so no config ordering can leave it unset when the auth stack ran. The
         * value is not load-bearing — only presence matters, and a caller can
         * forge presence only in the fail-safe direction (forcing a prompt), not
         * clear it once we have run. See SUDOWHAT_AUTH_MARKER_ENV in Constants.h. */
        setenv(SUDOWHAT_AUTH_MARKER_ENV, "1", 1);

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

        /* Third role — CONSOLE-ONLY. The nopasswd-only variant of
         * /etc/pam.d/sudo_local invokes this module as
         *   auth requisite <pam_sudowhat.so> console-only
         * between the integrity line and `sufficient pam_permit.so`. The local
         * console user passes on to pam_permit (Touch ID gates them in the
         * approval plugin). Any other caller reached the auth stack because
         * sudoers requires authentication for this command, and nopasswd-only
         * gives them no way to provide it: say so and stop. Refusing HERE,
         * before pam_permit, is what keeps a non-console caller from ever
         * holding a cached credential, so the approval plugin can read an
         * absent marker as "sudoers waived authentication".
         *
         * PAM_CRED_INSUFFICIENT, not PAM_AUTH_ERR: sudo treats PAM_AUTH_ERR,
         * PAM_PERM_DENIED, PAM_MAXTRIES and PAM_AUTHINFO_UNAVAIL as a wrong
         * password and asks again (passwd_tries times, "Sorry, try again"),
         * which would print this refusal three times. Any other code ends the
         * attempt at once with one "PAM authentication error" line, and
         * "insufficient credentials" is the one that says what happened. */
        if (argc >= 1 && argv[0] != NULL
            && strcmp(argv[0], SUDOWHAT_CONSOLE_ONLY_ARG) == 0) {
            const char *userName = NULL;
            if (pam_get_user(pamh, &userName, NULL) != PAM_SUCCESS
                || userName == NULL) {
                sudowhat_log(LOG_ERR,
                             "console-only: could not determine invoking user");
                return PAM_CRED_INSUFFICIENT;
            }
            struct passwd *pw = getpwnam(userName);
            if (pw == NULL) {
                sudowhat_log(LOG_ERR,
                             "console-only: no passwd entry for user '%s'",
                             userName);
                return PAM_CRED_INSUFFICIENT;
            }
            if ([SudoWhatPamSessionGuard isInvokingUserActiveConsole:pw->pw_uid]) {
                return PAM_SUCCESS;   /* local console: on to pam_permit */
            }
            sudowhat_conv_error(pamh,
                "sudowhat: not in the console's GUI login session, so only "
                "NOPASSWD commands run (nonConsole = nopasswd-only)");
            sudowhat_log(LOG_NOTICE,
                         "console-only: refused non-console caller '%s' "
                         "(uid %u); the command needs authentication",
                         userName, pw->pw_uid);
            return PAM_CRED_INSUFFICIENT;
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

        if (![SudoWhatPamSigVerifier verifyPath:@SUDOWHAT_PLUGIN_PATH
                                     identifier:@SUDOWHAT_PLUGIN_IDENT
                                          error:&err]) {
            sudowhat_log(LOG_ERR, "approval plugin signature check failed: %s",
                         utf8_or(err.localizedDescription, "unknown"));
            return PAM_AUTH_ERR;
        }

        /* The audit plugin owns terminal command display and joins the mutual-
         * signature web. It is OPTIONAL — absent means no terminal display with
         * auth unaffected — but a present-but-tampered bundle could show a false
         * command, so verify it when installed and fail closed on tamper.
         * Removing the bundle needs root, which is outside the threat model:
         * tamper-evident in place, not removal-proof. */
        if ([[NSFileManager defaultManager] fileExistsAtPath:@SUDOWHAT_AUDIT_PATH]
            && ![SudoWhatPamSigVerifier verifyPath:@SUDOWHAT_AUDIT_PATH
                                        identifier:@SUDOWHAT_AUDIT_IDENT
                                             error:&err]) {
            sudowhat_log(LOG_ERR, "audit plugin signature check failed: %s",
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
