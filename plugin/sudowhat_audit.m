/*
 * sudowhat audit plugin (sudo plugin API: SUDO_AUDIT_PLUGIN, type 3).
 *
 * The single owner of TERMINAL command display. sudo calls an audit plugin's
 * open() before any other plugin API function — in particular before the policy
 * plugin's check_policy, where PAM collects the password — so this plugin prints
 *   user / path / command
 * to the controlling terminal FIRST, on every path: the local console (before
 * the approval plugin's verify code + Touch ID sheet) and the non-console / SSH
 * case (before sudo's native PAM `Password:`). That closes the gap where a
 * non-console sudo used to step aside silently, showing a bare `Password:` with
 * no command. See docs/design-terminal-mode.md.
 *
 * This plugin NEVER handles the password and is NEVER a trust anchor: display is
 * disclosure, not authentication. Auth stays governed by sudo's native PAM and
 * the approval plugin. Accordingly it fails SOFT — any problem (no tty, missing
 * context, a tampered sibling bundle) means "show nothing", never "break sudo".
 * Integrity is enforced elsewhere: the approval plugin and pam_sudowhat fail
 * CLOSED if this bundle is present-but-tampered (the mutual-signature web), so a
 * swapped audit plugin that lies about the command cannot let sudo proceed.
 *
 * The untrusted-argv escaping/quoting is done in the Rust escape_core staticlib
 * (memory-safe), not in C here: this file is a thin ObjC shell doing the
 * code-signature check and the /dev/tty glue.
 */

#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>

#include "sudo_plugin.h"
#include "Constants.h"
#import "SignatureVerifier.h"   /* class SudoWhatAuditSigVerifier (per-target) */
#include "escape_core.h"

/* Build-time master switch for terminal display, chosen by -DSW_AUDIT_DISPLAY
 * (services.sudowhat.auditDisplay in the nix module; SUDOWHAT_AUDIT_DISPLAY in
 * the Makefile). Same fail-closed token machinery as the approval plugin's
 * knobs: a bare token names a fixed mode baked into the signed bundle.
 *
 *   on  - (default) show user / path / command on the controlling terminal.
 *   off - never display (the bundle loads but its open() shows nothing).
 *
 * An unknown token yields an undefined SW_AD_<name> and fails the compile — the
 * intended fail-closed result for a raw -D that bypasses the Makefile. */
#ifndef SW_AUDIT_DISPLAY
#define SW_AUDIT_DISPLAY on
#endif
#define SW_AD_off      0
#define SW_AD_on       1
#define SW_AD_CAT(x)   SW_AD_##x
#define SW_AD_SEL(x)   SW_AD_CAT(x)
enum { sw_audit_display_mode = SW_AD_SEL(SW_AUDIT_DISPLAY) };

/* Build-time colour policy, chosen by -DSW_AUDIT_ECHO_COLOR (echoColor in the
 * nix module / Makefile). Parsed here so the option surface is stable, but the
 * display is currently always plain: the anomaly colouriser lives in
 * PromptFormatter (a fixed ObjC class name that cannot be linked into this
 * second bundle without a duplicate-class collision), so colour lands only when
 * colorizeEscaped: is ported into escape_core (the documented fast-follow).
 * TODO(colorize fast-follow): route the escaped bytes through the Rust
 * colouriser here when sw_audit_color_mode == SW_ACOL_anomalies. */
#ifndef SW_AUDIT_ECHO_COLOR
#define SW_AUDIT_ECHO_COLOR anomalies
#endif
#define SW_ACOL_off        0
#define SW_ACOL_anomalies  1
#define SW_ACOL_CAT(x)     SW_ACOL_##x
#define SW_ACOL_SEL(x)     SW_ACOL_CAT(x)
enum { sw_audit_color_mode = SW_ACOL_SEL(SW_AUDIT_ECHO_COLOR) };

/* sudo delivers context as NULL-terminated "key=value" C-string arrays. Local
 * copy of the approval plugin's helper (kept file-static; the two bundles do not
 * share a translation unit). Matches the whole key up to '=' so "uid" never
 * matches "uidextra=". */
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

/* Escape a C string via the Rust core (sw_escape_control) and return it as an
 * NSString, or nil on failure. Two-call sizing: probe for the length, allocate,
 * fill. The Rust core replaces invalid UTF-8 with U+FFFD, so this never rejects
 * a value; it only returns nil on an allocation failure. */
static NSString *sw_audit_escape(const char *input) {
    if (input == NULL) return @"";
    size_t inlen = strlen(input);
    size_t needed = 0;
    sw_escape_control((const uint8_t *)input, inlen, NULL, 0, &needed);
    size_t cap = needed + 1;
    uint8_t *buf = malloc(cap);
    if (buf == NULL) return nil;
    size_t got = 0;
    NSString *s = nil;
    if (sw_escape_control((const uint8_t *)input, inlen, buf, cap, &got)
        == SW_ESCAPE_OK) {
        s = [[NSString alloc] initWithBytes:buf length:got
                                   encoding:NSUTF8StringEncoding];
    }
    free(buf);
    return s;
}

/* Build the as-typed command line from submit_argv[submit_optind..] via the Rust
 * core. We pass argv[0] as the "path" so sw_full_command_line's argv0-dedup
 * collapses it to a single leading token — the command exactly as the user typed
 * it, with every token shell-quoted and control-char escaped. Returns nil when
 * there is no command word (nothing to display) or on allocation failure. */
static NSString *sw_audit_command_line(char * const submit_argv[], int optind) {
    if (submit_argv == NULL || optind < 0) return nil;
    int n = 0;
    for (int i = optind; submit_argv[i] != NULL; i++) n++;
    if (n == 0) return nil;

    const char *path = submit_argv[optind];
    size_t path_len = strlen(path);

    const uint8_t **argv = calloc((size_t)n, sizeof(*argv));
    size_t *lens = calloc((size_t)n, sizeof(*lens));
    if (argv == NULL || lens == NULL) { free(argv); free(lens); return nil; }
    for (int i = 0; i < n; i++) {
        argv[i] = (const uint8_t *)submit_argv[optind + i];
        lens[i] = strlen(submit_argv[optind + i]);
    }

    size_t needed = 0;
    sw_full_command_line((const uint8_t *)path, path_len,
                         argv, lens, (size_t)n, NULL, 0, &needed);
    size_t cap = needed + 1;
    uint8_t *buf = malloc(cap);
    NSString *s = nil;
    if (buf != NULL) {
        size_t got = 0;
        if (sw_full_command_line((const uint8_t *)path, path_len,
                                 argv, lens, (size_t)n, buf, cap, &got)
            == SW_ESCAPE_OK) {
            s = [[NSString alloc] initWithBytes:buf length:got
                                       encoding:NSUTF8StringEncoding];
        }
        free(buf);
    }
    free(argv);
    free(lens);
    return s;
}

/* Write the assembled display block to the controlling terminal — and ONLY
 * there, exactly like the approval plugin's verify-code echo. /dev/tty is the
 * one channel a shell's fd redirects (`>f`, `2>f`, `&>f`) cannot touch, and a
 * captured `2>file` must never receive a possibly-confidential command. No
 * stderr fallback (the tty-only-signals invariant): no controlling terminal ->
 * write nothing, no crash. O_NOCTTY: never acquire a controlling terminal as a
 * side effect. O_CLOEXEC: never leak the fd into the execed target. Opened with
 * EUID root (as sudo's own prompt is), which may write the user's tty.
 *
 * ttyPath is a parameter (always "/dev/tty" in production) to keep the write
 * mechanism isolated and testable. The bytes are already escape_core-escaped, so
 * they carry no raw control byte regardless of what the user typed. */
static void sw_audit_write_tty(const char *ttyPath, NSString *block) {
    NSData *data = [block dataUsingEncoding:NSUTF8StringEncoding];
    if (data == nil || data.length == 0) return;

    int fd = open(ttyPath, O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) return;
    if (!isatty(fd)) { close(fd); return; }

    const char *bytes = data.bytes;
    size_t total = data.length;
    size_t off = 0;
    while (off < total) {
        ssize_t w = write(fd, bytes + off, total - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += (size_t)w;
    }
    close(fd);
}

/* Whether the invoking environment permits ANSI emphasis on the tty display —
 * the audit-plugin twin of the approval plugin's sw_color_allowed(). Cosmetic,
 * so reading the (spoofable) captured submit_envp is safe: the worst a liar
 * gains is the wrong emphasis, never a security effect (the trust anchor is the
 * verify code matching the system-rendered sheet, which cannot be coloured).
 * Off when NO_COLOR is present at any value (no-color.org) or TERM is
 * absent/empty/"dumb". isatty() in sw_audit_write_tty is the authoritative
 * final gate, so a redirect or non-tty always renders plain regardless. */
static BOOL sw_audit_color_allowed(char * const envp[]) {
    if (find_kv(envp, "NO_COLOR") != NULL) return NO;
    const char *term = find_kv(envp, "TERM");
    if (term == NULL || term[0] == '\0') return NO;
    if (strcmp(term, "dumb") == 0) return NO;
    return YES;
}

static int sudowhat_audit_open(unsigned int version,
                               sudo_conv_t conversation,
                               sudo_printf_t plugin_printf,
                               char * const settings[],
                               char * const user_info[],
                               int submit_optind,
                               char * const submit_argv[],
                               char * const submit_envp[],
                               char * const plugin_options[],
                               const char **errstr) {
    (void)conversation; (void)plugin_printf;
    (void)plugin_options; (void)errstr;

    /* Return convention for an audit open(): 1 = loaded, 0 = decline/unload
     * (sudo continues without us), -1 = fatal (sudo aborts). We NEVER return -1:
     * a display convenience must not be able to DoS sudo. Unknown API generation
     * -> decline cleanly. Everything else returns 1 after displaying or
     * deliberately not displaying. */
    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR) {
        return 0;
    }

    if (sw_audit_display_mode == SW_AD_off) return 1;

    @autoreleasepool {
        /* Root exemption, matching the approval plugin: a uid-0 caller is not
         * escalating, and root contexts generally have no controlling tty
         * anyway, so there is nothing to display. */
        const char *uidStr = find_kv(user_info, "uid");
        if (uidStr == NULL) return 1;   /* cannot classify -> no display */
        if ((uid_t)strtoul(uidStr, NULL, 10) == 0) return 1;

        /* Mutual integrity: confirm the approval plugin and pam_sudowhat on disk
         * are our own signed bundles before drawing a command that claims to be
         * what sudo will run. On any failure, show nothing — auth is still
         * governed by PAM and the approval plugin, so this is defense in depth,
         * not a gate. (This plugin does not verify itself; the approval plugin
         * and pam_sudowhat verify it, present-but-tampered, and fail closed.) */
        NSError *sigErr = nil;
        if (![SudoWhatAuditSigVerifier verifyPath:@SUDOWHAT_PLUGIN_PATH
                                            error:&sigErr]) {
            syslog(LOG_AUTHPRIV | LOG_WARNING,
                   "sudowhat_audit: approval plugin signature invalid; "
                   "suppressing terminal display");
            return 1;
        }
        if (![SudoWhatAuditSigVerifier verifyPath:@SUDOWHAT_PAM_PATH
                                            error:&sigErr]) {
            syslog(LOG_AUTHPRIV | LOG_WARNING,
                   "sudowhat_audit: pam_sudowhat signature invalid; "
                   "suppressing terminal display");
            return 1;
        }

        /* The command as typed — the star of the display. No command word -> the
         * invocation is not something to preview (e.g. `sudo -v`); show nothing. */
        NSString *commandLine = sw_audit_command_line(submit_argv, submit_optind);
        if (commandLine.length == 0) return 1;

        /* Target user: sudo puts runas_user in settings[] only when -u was given;
         * otherwise the default target is root. Mirrors the approval plugin's
         * runas resolution for the pre-resolution (audit) stage. */
        const char *runas = find_kv(settings, "runas_user");
        NSString *userLine = (runas && runas[0] != '\0')
            ? sw_audit_escape(runas) : @"root";

        /* Directory shown is the invoking cwd where execve will run (matches the
         * approval sheet's Directory line, the cwd, not a binary path).
         * command_info["cwd"] does not exist yet at audit open(); user_info's cwd
         * is the honest pre-resolution value. Absent -> omit the Directory line. */
        const char *cwd = find_kv(user_info, "cwd");
        NSString *dirLine = (cwd && cwd[0] != '\0') ? sw_audit_escape(cwd) : nil;

        if (userLine == nil || commandLine == nil) return 1;   /* alloc failure */

        /* Bold the label word purely for readability (our own fixed bytes, never
         * user input — the values are escape_core-escaped). Gated by the same env
         * opt-outs as the approval plugin's verify code (NO_COLOR / TERM), with
         * sw_audit_write_tty's isatty() as the final gate, so a redirect or a
         * non-tty always renders plain. Restores the emphasis the pre-v0.10.0
         * emit_full_context applied before terminal display moved here. */
        BOOL color = sw_audit_color_allowed(submit_envp);
        NSString *lb = color ? @"\033[1m" : @"";
        NSString *lo = color ? @"\033[0m" : @"";

        NSMutableString *block = [NSMutableString string];
        [block appendFormat:@"sudowhat: %@user:%@ %@\n", lb, lo, userLine];
        if (dirLine.length > 0) {
            [block appendFormat:@"sudowhat: %@directory:%@ %@\n", lb, lo, dirLine];
        }
        [block appendFormat:@"sudowhat: %@command:%@ %@\n", lb, lo, commandLine];

        sw_audit_write_tty("/dev/tty", block);
        return 1;
    }
}

/* Minimal tail. close() gets the exit disposition (nothing to clean up — open()
 * holds no persistent state). accept/reject/error return 1 (success) so sudo is
 * satisfied; accept() will host the future resolved-path last-look, which is why
 * the members are wired rather than NULL. The optional struct tail
 * (show_version, register_hooks, deregister_hooks, event_alloc) stays NULL. */
static void sudowhat_audit_close(int status_type, int status) {
    (void)status_type; (void)status;
}

static int sudowhat_audit_accept(const char *plugin_name,
                                 unsigned int plugin_type,
                                 char * const command_info[],
                                 char * const run_argv[],
                                 char * const run_envp[],
                                 const char **errstr) {
    (void)plugin_name; (void)plugin_type; (void)command_info;
    (void)run_argv; (void)run_envp; (void)errstr;
    return 1;
}

static int sudowhat_audit_reject(const char *plugin_name,
                                 unsigned int plugin_type,
                                 const char *audit_msg,
                                 char * const command_info[],
                                 const char **errstr) {
    (void)plugin_name; (void)plugin_type; (void)audit_msg;
    (void)command_info; (void)errstr;
    return 1;
}

static int sudowhat_audit_error(const char *plugin_name,
                                unsigned int plugin_type,
                                const char *audit_msg,
                                char * const command_info[],
                                const char **errstr) {
    (void)plugin_name; (void)plugin_type; (void)audit_msg;
    (void)command_info; (void)errstr;
    return 1;
}

__attribute__((visibility("default")))
struct audit_plugin sudowhat_audit_plugin = {
    SUDO_AUDIT_PLUGIN,
    SUDO_API_VERSION,
    sudowhat_audit_open,
    sudowhat_audit_close,
    sudowhat_audit_accept,
    sudowhat_audit_reject,
    sudowhat_audit_error,
    NULL,   /* show_version */
    NULL,   /* register_hooks */
    NULL,   /* deregister_hooks */
    NULL,   /* event_alloc */
};
