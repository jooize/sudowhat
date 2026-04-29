/*
 * tsudo approval plugin (sudo plugin API: SUDO_APPROVAL_PLUGIN, type 4).
 *
 * Loaded by sudo via /etc/sudo.conf after PAM authentication. The bytes shown
 * in the Touch ID prompt are the same bytes sudo will execve(): both come
 * from sudo's resolved command_info["command"] and run_argv[], not from any
 * user-controllable string.
 *
 * Returns 1=allow, 0=deny, -1=error. errstr is set to a static C string on
 * any non-allow return so sudo can print a diagnostic.
 */

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "sudo_plugin.h"
#include "Constants.h"
#import "SignatureVerifier.h"
#import "SessionGuard.h"
#import "PromptFormatter.h"

/* Static errstr buffers — sudo only requires the pointer to remain valid
 * until close(); static storage is simplest and avoids ARC ownership over a
 * char* that the host code reads back. */
static char g_errbuf[512];

/* The sudo plugin API only delivers user_info[] to open(), not to check().
 * Stash what check() needs at open-time. */
static uid_t g_invoking_uid = (uid_t)-1;
static int   g_have_invoking_uid = 0;

/* Apple's sudo on macOS Tahoe does not surface approval-plugin errstr to
 * the terminal: the user sees a silent non-zero exit on deny. Capture the
 * plugin_printf callback at open() and use it from check() so the user
 * always gets a diagnostic line on the same stderr sudo writes its own
 * messages to. */
static sudo_printf_t g_plugin_printf = NULL;

static const char *utf8_or(NSString *s, const char *fallback) {
    const char *p = s.UTF8String;
    return (p && *p) ? p : fallback;
}

static const char *find_kv(char * const arr[], const char *key) {
    if (arr == NULL) return NULL;
    size_t klen = strlen(key);
    for (int i = 0; arr[i] != NULL; i++) {
        if (strncmp(arr[i], key, klen) == 0 && arr[i][klen] == '=') {
            return arr[i] + klen + 1;
        }
    }
    return NULL;
}

static void set_errstr(const char **errstr, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_errbuf, sizeof(g_errbuf), fmt, ap);
    va_end(ap);
    if (errstr) *errstr = g_errbuf;
    /* macOS sudo on Tahoe does not surface approval-plugin errstr to the
     * terminal on its own. Use sudo's plugin_printf if open() captured it
     * (proper channel that respects sudo's output settings); fall back to
     * direct stderr write if it wasn't, so the user always sees a
     * diagnostic. */
    if (g_plugin_printf) {
        g_plugin_printf(SUDO_CONV_ERROR_MSG, "%s\n", g_errbuf);
    } else {
        fprintf(stderr, "%s\n", g_errbuf);
        fflush(stderr);
    }
}

static int tsudo_open(unsigned int version,
                      sudo_conv_t conversation,
                      sudo_printf_t plugin_printf,
                      char * const settings[],
                      char * const user_info[],
                      int submit_optind,
                      char * const submit_argv[],
                      char * const submit_envp[],
                      char * const plugin_options[],
                      const char **errstr) {
    (void)conversation; (void)settings;
    (void)submit_optind; (void)submit_argv;
    (void)submit_envp; (void)plugin_options;

    g_plugin_printf = plugin_printf;

    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR) {
        set_errstr(errstr, "tsudo: unsupported sudo plugin API major version %u",
                   SUDO_API_VERSION_GET_MAJOR(version));
        return -1;
    }

    const char *uidStr = find_kv(user_info, "uid");
    if (uidStr == NULL) {
        set_errstr(errstr, "tsudo: missing uid in user_info");
        return -1;
    }
    g_invoking_uid = (uid_t)strtoul(uidStr, NULL, 10);
    g_have_invoking_uid = 1;
    return 1;
}

static void tsudo_close(void) {
    g_have_invoking_uid = 0;
    g_invoking_uid = (uid_t)-1;
    g_plugin_printf = NULL;
}

static int tsudo_check(char * const command_info[],
                       char * const run_argv[],
                       char * const run_envp[],
                       const char **errstr) {
    (void)run_envp;

    @autoreleasepool {
        /* (1) Mutual integrity check: verify pam_tsudo.so before trusting
         * that the PAM step was actually our module. */
        NSError *sigErr = nil;
        if (![TSudoSignatureVerifier verifyPath:@TSUDO_PAM_PATH error:&sigErr]) {
            set_errstr(errstr, "tsudo: pam_tsudo signature invalid: %s",
                       utf8_or(sigErr.localizedDescription, "unknown"));
            return 0;
        }

        /* (2) Console-UID guard. */
        if (!g_have_invoking_uid) {
            set_errstr(errstr, "tsudo: invoking uid not captured at open()");
            return -1;
        }
        if (![TSudoSessionGuard isInvokingUserActiveConsole:g_invoking_uid]) {
            set_errstr(errstr, "tsudo: not in active GUI session "
                               "(invoking uid %u is not the console user)",
                       g_invoking_uid);
            return 0;
        }

        /* (3) Resolve command. */
        const char *commandC = find_kv(command_info, "command");
        if (commandC == NULL) {
            set_errstr(errstr, "tsudo: missing 'command' in command_info");
            return -1;
        }
        NSString *commandPath = [NSString stringWithUTF8String:commandC];

        const char *runasU = find_kv(command_info, "runas_user");
        NSString *runasUser = runasU ? [NSString stringWithUTF8String:runasU] : @"root";

        NSMutableArray<NSString *> *argv = [NSMutableArray array];
        if (run_argv) {
            for (int i = 0; run_argv[i] != NULL; i++) {
                NSString *tok = [NSString stringWithUTF8String:run_argv[i]];
                if (tok) [argv addObject:tok];
            }
        }

        /* (3a) Pre-prompt stat — capture (dev, inode) so we can detect a
         * binary swap during authorization. Open with O_CLOEXEC so the fd
         * doesn't leak into the execed program. */
        int preFd = open(commandC, O_RDONLY | O_CLOEXEC);
        if (preFd < 0) {
            set_errstr(errstr, "tsudo: cannot open target binary %s: %s",
                       commandC, strerror(errno));
            return 0;
        }
        struct stat preSt;
        if (fstat(preFd, &preSt) != 0) {
            int saved = errno;
            close(preFd);
            set_errstr(errstr, "tsudo: fstat(%s) failed: %s",
                       commandC, strerror(saved));
            return -1;
        }

        /* (4) Format prompt. */
        NSString *promptText =
            [TSudoPromptFormatter formatWithCommandPath:commandPath
                                              runasUser:runasUser
                                                   argv:argv];

        /* (5) LAContext call.
         *
         * sudo invokes us as root (real-uid is the user, effective is 0).
         * Calling LAContext as root makes macOS route to Authorization
         * Services and show a "System Administrator" password dialog
         * because root has no biometric enrollment and the user's own
         * password is not what root accepts. Drop EUID to the invoking
         * user around evaluatePolicy so the dialog binds to that user:
         * Touch ID matches their enrollment, and the password fallback
         * accepts their account password. seteuid is reversible while
         * the saved-set-uid is still 0 (which it is until exec).
         *
         * Policy is LAPolicyDeviceOwnerAuthentication so password
         * fallback is available when biometric isn't (sensor unavailable,
         * lid closed). */
        if (seteuid(g_invoking_uid) != 0) {
            int saved = errno;
            close(preFd);
            set_errstr(errstr, "tsudo: seteuid(%u) failed: %s",
                       g_invoking_uid, strerror(saved));
            return -1;
        }

        LAContext *ctx = [[LAContext alloc] init];
        ctx.localizedFallbackTitle = @"Use Password";
        NSError *policyErr = nil;
        BOOL canEval = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication
                                        error:&policyErr];
        if (!canEval) {
            (void)seteuid(0);
            close(preFd);
            set_errstr(errstr, "tsudo: cannot evaluate authentication policy: %s",
                       utf8_or(policyErr.localizedDescription, "unknown"));
            return 0;
        }

        __block BOOL allowed = NO;
        __block NSError *replyErr = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
            localizedReason:promptText
                      reply:^(BOOL success, NSError *err) {
            allowed = success;
            replyErr = err;
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        /* Restore root EUID. If this fails, sudo cannot exec the target,
         * so abort hard rather than continuing in a degraded state. */
        if (seteuid(0) != 0) {
            _exit(1);
        }

        if (!allowed) {
            close(preFd);
            set_errstr(errstr, "tsudo: authorization denied: %s",
                       utf8_or(replyErr.localizedDescription, "user cancelled"));
            return 0;
        }

        /* (6) TOCTOU narrowing — re-stat the path and compare to the fd we
         * pinned before the prompt. If the file at the path no longer
         * matches the fd's (dev, inode), the binary was swapped while the
         * user was authenticating. */
        struct stat postSt;
        if (stat(commandC, &postSt) != 0) {
            int saved = errno;
            close(preFd);
            set_errstr(errstr, "tsudo: post-auth stat(%s) failed: %s",
                       commandC, strerror(saved));
            return 0;
        }
        close(preFd);

        if (postSt.st_dev != preSt.st_dev || postSt.st_ino != preSt.st_ino) {
            set_errstr(errstr, "tsudo: target binary changed during authorization");
            return 0;
        }

        return 1;
    }
}

__attribute__((visibility("default")))
struct approval_plugin tsudo_approval_plugin = {
    SUDO_APPROVAL_PLUGIN,
    SUDO_API_VERSION,
    tsudo_open,
    tsudo_close,
    tsudo_check,
    NULL
};
