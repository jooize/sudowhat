/*
 * pam_tsudo — PAM auth module that integrity-checks the tsudo approval
 * plugin and the sudo.conf entry that loads it. This is a precondition for
 * trusting the Touch ID prompt the plugin will render: if the plugin file
 * has been swapped or the sudo.conf line removed, sudo would either run
 * with no approval gate or load the wrong code.
 *
 * On success returns PAM_SUCCESS and the [success=done default=die] line in
 * /etc/pam.d/sudo_local terminates the auth chain — no password fallback.
 * On any failure returns PAM_AUTH_ERR and sudo aborts.
 */

#import <Foundation/Foundation.h>
#include <syslog.h>

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "Constants.h"
#import "SignatureVerifier.h"
#import "SudoConfChecker.h"

static const char *utf8_or(NSString *s, const char *fallback) {
    const char *p = s.UTF8String;
    return (p && *p) ? p : fallback;
}

/* macOS's pam_appl.h doesn't declare pam_syslog. Use the stdlib syslog
 * directly with a stable tag. */
static void tsudo_log(int prio, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char buf[512];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    syslog(prio | LOG_AUTHPRIV, "pam_tsudo: %s", buf);
}

__attribute__((visibility("default")))
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                         int argc, const char *argv[]) {
    (void)pamh; (void)flags; (void)argc; (void)argv;

    @autoreleasepool {
        NSError *err = nil;
        if (![TSudoSudoConfChecker verifyConfPath:@TSUDO_SUDO_CONF
                                   expectedSymbol:@TSUDO_PLUGIN_SYMBOL
                                     expectedPath:@TSUDO_PLUGIN_PATH
                                            error:&err]) {
            tsudo_log(LOG_ERR, "sudo.conf check failed: %s",
                      utf8_or(err.localizedDescription, "unknown"));
            return PAM_AUTH_ERR;
        }

        if (![TSudoPamSigVerifier verifyPath:@TSUDO_PLUGIN_PATH error:&err]) {
            tsudo_log(LOG_ERR, "approval plugin signature check failed: %s",
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
