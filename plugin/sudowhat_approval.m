/*
 * sudowhat approval plugin (sudo plugin API: SUDO_APPROVAL_PLUGIN, type 4).
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
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <syslog.h>

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
 * Stash what check() needs at open-time. One snapshot of the invoking
 * context; each have_* flag marks whether its field was populated. */
typedef struct {
    uid_t uid;
    int   have_uid;
    char  tty[256];
    int   have_tty;
    char  cwd[1024];
    int   have_cwd;
    char  term_program[64];
    int   have_term_program;
    char  term[64];
    int   have_term;
    int   no_color;
} sw_invoking_ctx;

static sw_invoking_ctx g_inv = { .uid = (uid_t)-1 };

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

/* Channel-binding nonce. Crockford base32 minus '0' — the alphabet drops
 * I, L, O, U for shape ambiguity, plus '0' because system fonts used in
 * the LAContext sheet render zero without a slash or dot, so a stray '0'
 * could still be misread (esp. against D/Q). 31 chars at 4 positions =
 * ~923k combos (~20 bits), ample for one-shot human comparison.
 * arc4random_uniform is cryptographically strong and avoids modulo bias. */
static void generate_verify_nonce(char *out, size_t outsz) {
    static const char alphabet[] = "123456789ABCDEFGHJKMNPQRSTVWXYZ";
    if (outsz == 0) return;
    size_t n = outsz - 1;
    for (size_t i = 0; i < n; i++) {
        out[i] = alphabet[arc4random_uniform((uint32_t)(sizeof(alphabet) - 1))];
    }
    out[n] = '\0';
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

/* Classify /etc/pam.d/sudo_local content: is it the non-console GATE variant?
 *
 * The step-aside below is only safe when this file routes a non-console caller
 * through sudo's real password / smartcard factor instead of the unconditional
 * `pam_permit` the default console-only install ships. The gate variant has
 * BOTH our integrity line and our console-gate line, at OUR own module path:
 *   auth requisite  <SUDOWHAT_PAM_PATH>
 *   auth sufficient <SUDOWHAT_PAM_PATH> console-gate
 * Token-based and whitespace-insensitive (matching pam/SudoConfChecker);
 * '#' comments and blank lines are skipped. Pinning the module to
 * SUDOWHAT_PAM_PATH — the same store path the plugin already trusts for the
 * mutual signature check — is what couples this check to what the installer
 * wrote: a console-gate line pointing at some other module does not count.
 * file-static so the offline unit test can exercise it directly. */
static BOOL sudowhat_text_is_gate_variant(NSString *content) {
    if (content == nil) return NO;
    BOOL haveIntegrity = NO, haveGate = NO;
    NSCharacterSet *ws = [NSCharacterSet whitespaceCharacterSet];
    for (NSString *rawLine in [content componentsSeparatedByString:@"\n"]) {
        NSString *line = [rawLine stringByTrimmingCharactersInSet:ws];
        if (line.length == 0 || [line hasPrefix:@"#"]) continue;
        NSMutableArray<NSString *> *f = [NSMutableArray array];
        for (NSString *tok in [line componentsSeparatedByCharactersInSet:ws]) {
            if (tok.length > 0) [f addObject:tok];
        }
        if (f.count < 3) continue;
        if (![f[0] isEqualToString:@"auth"]) continue;
        if (![f[2] isEqualToString:@SUDOWHAT_PAM_PATH]) continue;
        if (f.count == 3 && [f[1] isEqualToString:@"requisite"]) {
            haveIntegrity = YES;
        }
        if (f.count >= 4 && [f[1] isEqualToString:@"sufficient"]
            && [f[3] isEqualToString:@SUDOWHAT_GATE_ARG]) {
            haveGate = YES;
        }
    }
    return haveIntegrity && haveGate;
}

/* Reads /etc/pam.d/sudo_local and reports whether the non-console password
 * path (the gate variant) is installed. Unreadable / absent / wrong shape ->
 * NO, so the step-aside falls back to a deny. */
static BOOL sudowhat_noncon_password_path_installed(void) {
    NSString *content = [NSString stringWithContentsOfFile:@SUDOWHAT_SUDO_LOCAL
                                                  encoding:NSUTF8StringEncoding
                                                     error:NULL];
    return sudowhat_text_is_gate_variant(content);
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

/* The verify-code line. One set of pieces so the /dev/tty path and the stderr
 * fallback below can never drift apart. The substituted code is the plugin's
 * own nonce — no caller-controlled bytes reach this line — so it needs no
 * escaping. */
#define SW_VERIFY_PREFIX "sudowhat: verify code "
#define SW_VERIFY_SUFFIX " in the prompt\n"
#define SW_VERIFY_LINE_FMT      SW_VERIFY_PREFIX "%s" SW_VERIFY_SUFFIX
/* Bold (SGR 1) the code, then reset all (SGR 0). Bold rather than a specific
 * color because it is background-independent — a foreground color can vanish
 * against some terminal themes, defeating the very visibility this echo exists
 * for. Emphasis only, never a trust signal (see write_verify_code_to_tty). */
#define SW_VERIFY_LINE_FMT_BOLD SW_VERIFY_PREFIX "\033[1m%s\033[0m" SW_VERIFY_SUFFIX

/* Render the verify-code line into buf, wrapping the code in ANSI bold when
 * colorize is YES. Returns snprintf's count so callers can fail closed on
 * truncation. Pure (no fd, no env) so it is unit-testable for both renderings. */
static int format_verify_line(char *buf, size_t bufsz, const char *code,
                              BOOL colorize) {
    return snprintf(buf, bufsz,
                    colorize ? SW_VERIFY_LINE_FMT_BOLD : SW_VERIFY_LINE_FMT,
                    code);
}

/* Whether the invoking environment permits ANSI emphasis on the tty echo. This
 * is cosmetic, so reading it from the (spoofable) captured submit_envp is safe:
 * the most an attacker gains by lying is the wrong emphasis, never a security
 * effect — the trust anchor is the code matching the Touch ID sheet, which is
 * system-rendered and cannot be colored. Off when NO_COLOR is present at any
 * value (no-color.org) or TERM is absent/empty/"dumb". The authoritative gate
 * is isatty() at the write site, so a redirect or the stderr fallback always
 * stays plain. */
static BOOL sw_color_allowed(void) {
    if (g_inv.no_color) return NO;
    if (!g_inv.have_term || g_inv.term[0] == '\0') return NO;
    if (strcmp(g_inv.term, "dumb") == 0) return NO;
    return YES;
}

/* Write the verify-code line straight to the controlling terminal.
 *
 * The code is an out-of-band trust signal the user compares against the
 * LAContext sheet, so it has to reach the human at the keyboard regardless of
 * how the command's I/O is wired. A shell only rewires fds 0-2, so every
 * redirect there is — `sudo cmd >f`, `sudo tee f >/dev/null`, `2>/dev/null`,
 * `&>f` — leaves the *controlling terminal* untouched. Writing to /dev/tty (the
 * same channel sudo uses for its own "Password:" prompt) therefore survives all
 * of them, where an earlier stdout/stderr write did not.
 *
 * O_NOCTTY: never acquire a controlling terminal as a side effect of the open.
 * O_CLOEXEC: don't leak the fd into the execed target. The fd is opened with
 * EUID still root (the seteuid drop happens later); root may write the user's
 * tty, exactly as sudo's own prompt does.
 *
 * ttyPath is a parameter (always "/dev/tty" in production) so the offline unit
 * test can point it at a temp file and read the bytes back. colorAllowed folds
 * in the env opt-outs (NO_COLOR/TERM); the isatty() check below is the final
 * gate, so escape bytes only ever reach a real terminal — never a file or pipe
 * (e.g. a temp-file test path, or `2>/dev/tty` aimed at a regular file), where
 * they would corrupt a captured log rather than emphasise anything. Returns YES
 * iff the entire line was written. */
static BOOL write_verify_code_to_tty(const char *ttyPath, const char *code,
                                     BOOL colorAllowed) {
    int fd = open(ttyPath, O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) return NO;

    BOOL colorize = colorAllowed && isatty(fd);

    char line[96];
    int n = format_verify_line(line, sizeof(line), code, colorize);
    if (n < 0 || (size_t)n >= sizeof(line)) { close(fd); return NO; }

    ssize_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, line + off, (size_t)(n - off));
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return NO;
        }
        off += w;
    }
    close(fd);
    return YES;
}

/* Emit the channel-binding verify code. Prefer the controlling terminal so no
 * fd redirect can hide it; fall back to sudo's stderr via plugin_printf only
 * when open("/dev/tty") fails. By the time we reach here the caller is already
 * classified active-console (root and non-console callers returned upstream, in
 * sudowhat_check), so this fallback is NOT the detached/cron case — those never
 * get here. It is the narrow one of an in-session process that happens to have
 * no controlling terminal: launched by the Dock / Spotlight / a GUI agent
 * rather than from a shell. stderr still beats staying silent there — a human
 * in that session may see it — and we use SUDO_CONV_ERROR_MSG, never INFO_MSG,
 * since sudo routes INFO to stdout (sudo/src/conversation.c) where a `>file`
 * redirect would swallow it. The printf and ttyPath are passed in so the
 * offline unit test can exercise both branches without a live sudo or real
 * tty. */
static void emit_verify_code(sudo_printf_t printf_fn, const char *ttyPath,
                             const char *code, BOOL colorAllowed) {
    if (write_verify_code_to_tty(ttyPath, code, colorAllowed)) return;
    if (printf_fn != NULL) {
        /* The fallback is sudo's stderr, not a known terminal, so it is always
         * plain — escape bytes here could land in a `2>file` capture. */
        printf_fn(SUDO_CONV_ERROR_MSG, SW_VERIFY_LINE_FMT, code);
    }
}

static int sudowhat_open(unsigned int version,
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
    (void)plugin_options;

    g_plugin_printf = plugin_printf;

    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR) {
        set_errstr(errstr, "sudowhat: unsupported sudo plugin API major version %u",
                   SUDO_API_VERSION_GET_MAJOR(version));
        return -1;
    }

    const char *uidStr = find_kv(user_info, "uid");
    if (uidStr == NULL) {
        set_errstr(errstr, "sudowhat: missing uid in user_info");
        return -1;
    }
    g_inv.uid = (uid_t)strtoul(uidStr, NULL, 10);
    g_inv.have_uid = 1;

    /* tty is optional context for the prompt trailer; absence is not fatal.
     * Apple's sudo on Tahoe has been observed leaving tty= empty even when
     * invoked from a real terminal, so we try in order:
     *   1. sudo's user_info["tty"]
     *   2. ttyname() on stderr / stdin — works in plain terminal sessions
     *      where stderr is the PTY
     *   3. open("/dev/tty") — resolves to the calling process's controlling
     *      terminal regardless of fd redirection. Catches cases like Claude
     *      Code's bash, where stdin/stderr are pipes (so #2 fails) but a
     *      controlling tty still exists upstream. */
    const char *ttyStr = find_kv(user_info, "tty");
    if (ttyStr != NULL && ttyStr[0] != '\0') {
        snprintf(g_inv.tty, sizeof(g_inv.tty), "%s", ttyStr);
        g_inv.have_tty = 1;
    }
    if (!g_inv.have_tty) {
        const char *t = ttyname(STDERR_FILENO);
        if (t == NULL) t = ttyname(STDIN_FILENO);
        if (t != NULL && t[0] != '\0') {
            snprintf(g_inv.tty, sizeof(g_inv.tty), "%s", t);
            g_inv.have_tty = 1;
        }
    }
    if (!g_inv.have_tty) {
        int fd = open("/dev/tty", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            const char *t = ttyname(fd);
            if (t != NULL && t[0] != '\0') {
                snprintf(g_inv.tty, sizeof(g_inv.tty), "%s", t);
                g_inv.have_tty = 1;
            }
            close(fd);
        }
    }

    /* cwd captured here is the invoking user's cwd. command_info["cwd"]
     * in check() takes precedence when present (sudoers cwd= directive),
     * but sudo doesn't emit command_info["cwd"] in the common case where
     * it just inherits the invoking cwd — this stash covers that case. */
    const char *cwdStr = find_kv(user_info, "cwd");
    if (cwdStr != NULL && cwdStr[0] != '\0') {
        snprintf(g_inv.cwd, sizeof(g_inv.cwd), "%s", cwdStr);
        g_inv.have_cwd = 1;
    }

    /* TERM_PROGRAM is set by the terminal emulator (Ghostty, iTerm.app,
     * Apple_Terminal, etc.) and inherited by the shell, so it's present
     * in the user's submitted env. Purely a recognition aid in the prompt
     * trailer — TRIVIALLY SPOOFABLE by 'TERM_PROGRAM=fake sudo ...', so
     * the trust signal is the channel-binding nonce, not this string. */
    const char *termProg = find_kv(submit_envp, "TERM_PROGRAM");
    if (termProg != NULL && termProg[0] != '\0') {
        snprintf(g_inv.term_program, sizeof(g_inv.term_program),
                 "%s", termProg);
        g_inv.have_term_program = 1;
    }
    /* TERM is the secondary fallback: terminals like kitty and alacritty
     * don't set TERM_PROGRAM and only identify themselves via a
     * terminal-specific TERM value (xterm-kitty, alacritty). Same trust
     * class as TERM_PROGRAM — env-set, spoofable. */
    const char *term = find_kv(submit_envp, "TERM");
    if (term != NULL && term[0] != '\0') {
        snprintf(g_inv.term, sizeof(g_inv.term), "%s", term);
        g_inv.have_term = 1;
    }
    /* NO_COLOR (no-color.org): present at ANY value — including empty — means
     * the user opted out of ANSI emphasis on the verify-code tty echo. Same
     * spoofable env class as TERM above; only the echo's color depends on it.
     * find_kv returns non-NULL for "NO_COLOR=" (empty value), so presence — not
     * truthiness — is the test, exactly as the standard specifies. */
    g_inv.no_color = (find_kv(submit_envp, "NO_COLOR") != NULL);
    return 1;
}

static void sudowhat_close(void) {
    /* Single struct-zero clears every field and resets the have_* flags, so
     * adding a field to sw_invoking_ctx can't leave a stale value behind. */
    g_inv = (sw_invoking_ctx){ .uid = (uid_t)-1 };
    g_plugin_printf = NULL;
}

static int sudowhat_check(char * const command_info[],
                          char * const run_argv[],
                          char * const run_envp[],
                          const char **errstr) {
    (void)run_envp;

    @autoreleasepool {
        /* (1) Mutual integrity check: verify pam_sudowhat.so before
         * trusting that the PAM step was actually our module. */
        NSError *sigErr = nil;
        if (![SudoWhatSignatureVerifier verifyPath:@SUDOWHAT_PAM_PATH error:&sigErr]) {
            set_errstr(errstr, "sudowhat: pam_sudowhat signature invalid: %s",
                       utf8_or(sigErr.localizedDescription, "unknown"));
            return 0;
        }

        /* (2) Caller classification.
         *
         * sudowhat gates *escalation* — an unprivileged principal reaching
         * for root — behind the console user's biometric. A uid-0 caller is
         * not escalating: it is already root. sudo grants it nothing it can't
         * already do (root can run the command directly, rewrite
         * /etc/sudo.conf, or unload this plugin), so the console gate is
         * security-vacuous for root yet actively breaks legitimate
         * root-context automation that shells out through sudo — notably
         * nix-darwin / home-manager per-user activation, which runs as root
         * and invokes `launchctl asuser <uid> sudo -u <user>` (invoking uid
         * 0). Those calls are non-interactive, so prompting would fail-closed
         * with no human to answer. Exempt root from the console gate and the
         * prompt; syslog it so the bypass is auditable rather than silent.
         * The mutual integrity check above still runs, so a tampered plugin
         * cannot ride this path. */
        if (!g_inv.have_uid) {
            set_errstr(errstr, "sudowhat: invoking uid not captured at open()");
            return -1;
        }
        if (g_inv.uid == 0) {
            /* Log the decision, not the command. sudo's own log_allowed (on
             * by default) already records the full command line to authpriv;
             * repeating argv here would only leak potentially sensitive
             * arguments into a second place. Record just the fact that the
             * console-user guard was deliberately bypassed. */
            syslog(LOG_AUTHPRIV | LOG_NOTICE,
                   "sudowhat: console-user guard bypassed (root-initiated sudo)");
            return 1;
        }

        /* Non-root caller: classify by the invoking SECURITY SESSION (see
         * SessionGuard — a local GUI login vs. an SSH / launchd / headless
         * session), NOT by uid alone. A non-console caller must never be able
         * to pop a Touch ID dialog the console user reflexively approves —
         * proven on hardware, a same-uid SSH session DOES render the sheet on
         * the console — so a non-console caller never reaches the LAContext/AS
         * block below. */
        if (![SudoWhatSessionGuard isInvokingUserActiveConsole:g_inv.uid]) {
            /* sudo already authenticated this caller per the installed PAM
             * chain (the approval plugin runs after PAM). If the non-console
             * GATE variant of /etc/pam.d/sudo_local is installed, a real factor
             * on the caller's OWN session was required: the console-gate line
             * fails for a non-console caller, so the parent /etc/pam.d/sudo
             * chain falls through to pam_smartcard / pam_opendirectory on the
             * caller's own tty (or the caller matched an operator NOPASSWD
             * rule). Either way, rendering a sheet here would put it on the
             * CONSOLE user's screen, so we STEP ASIDE and allow.
             *
             * TRIPWIRE FOR MAINTAINERS: do NOT move this below the
             * seteuid(g_inv.uid)+LAContext/AS block, and never raise a
             * biometric/Authorization Services sheet for a non-console uid.
             * BiometricsOrCompanion is a same-session SEP confirmation of a
             * locally rendered sheet, not an out-of-band push — for a
             * non-console caller it renders in the CONSOLE user's session,
             * which is exactly the reflexive-approval hole this guard exists to
             * close. Remote approval would need the rejected daemon design.
             *
             * If the gate variant is NOT installed (default console-only
             * config: `sufficient pam_permit.so`), PAM authenticated nobody, so
             * stepping aside would grant passwordless root — deny instead,
             * exactly as before this feature existed. */
            if (sudowhat_noncon_password_path_installed()) {
                syslog(LOG_AUTHPRIV | LOG_NOTICE,
                       "sudowhat: non-console caller allowed (invoking uid %u, "
                       "tty %s); sudo required a factor on the caller's own "
                       "session", g_inv.uid,
                       g_inv.have_tty ? g_inv.tty : "unknown");
                return 1;
            }
            set_errstr(errstr, "sudowhat: not in active GUI session "
                               "(invoking uid %u is not the console user)",
                       g_inv.uid);
            return 0;
        }

        /* (3) Resolve command. */
        const char *commandC = find_kv(command_info, "command");
        if (commandC == NULL) {
            set_errstr(errstr, "sudowhat: missing 'command' in command_info");
            return -1;
        }
        NSString *commandPath = [NSString stringWithUTF8String:commandC];

        /* Prefer sudo's already-resolved runas_user (it's the authoritative
         * name for the target uid, including the case where uid 0's
         * passwd entry is named something other than "root"). Fall back
         * to looking up uid 0 ourselves if sudo didn't supply a name. */
        const char *runasU = find_kv(command_info, "runas_user");
        NSString *runasUser;
        if (runasU && runasU[0] != '\0') {
            runasUser = [NSString stringWithUTF8String:runasU];
        } else {
            struct passwd *pw = getpwuid(0);
            runasUser = (pw && pw->pw_name)
                ? [NSString stringWithUTF8String:pw->pw_name]
                : @"root";
        }

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
            set_errstr(errstr, "sudowhat: cannot open target binary %s: %s",
                       commandC, strerror(errno));
            return 0;
        }
        struct stat preSt;
        if (fstat(preFd, &preSt) != 0) {
            int saved = errno;
            close(preFd);
            set_errstr(errstr, "sudowhat: fstat(%s) failed: %s",
                       commandC, strerror(saved));
            return -1;
        }

        /* (4) Format prompt. cwd preference: command_info["cwd"] (set
         * when sudoers has cwd=) > stashed invoking cwd from user_info
         * (the default case where sudo just inherits the caller's cwd
         * without emitting command_info["cwd"]). Either way the value
         * reflects where execve will run. */
        const char *cwdC = find_kv(command_info, "cwd");
        NSString *cwd = nil;
        if (cwdC && cwdC[0] != '\0') {
            cwd = [NSString stringWithUTF8String:cwdC];
        } else if (g_inv.have_cwd) {
            cwd = [NSString stringWithUTF8String:g_inv.cwd];
        }

        /* Channel-binding nonce: print it to the user's terminal BEFORE we
         * put up the LAContext sheet, then embed the same value in the prompt
         * body. A real sudo run originated from the user's foreground shell
         * shows matching codes; a sudo spawned by a background process the
         * user didn't initiate shows a code in some other terminal (or
         * nowhere), letting the user reject before authenticating. Not a
         * defense against post-compromise, but a defense against absent-minded
         * approval. emit_verify_code targets /dev/tty (see there) so no
         * redirect of the command's stdout or stderr can hide the code. */
        char nonceBuf[5];
        generate_verify_nonce(nonceBuf, sizeof(nonceBuf));
        NSString *verifyCode = [NSString stringWithUTF8String:nonceBuf];
        emit_verify_code(g_plugin_printf, "/dev/tty", nonceBuf,
                         sw_color_allowed());

        /* Two renderings of the same content: LAContext wraps our text in
         * a system-supplied sentence and appends a period, so we use the
         * SystemSheet style there. Authorization Services (password
         * fallback below) shows our text verbatim, so SelfContained gives
         * it a capitalized verb and its own terminal period. */
        NSString *promptTextLA =
            [SudoWhatPromptFormatter formatWithCommandPath:commandPath
                                                 runasUser:runasUser
                                                       cwd:cwd
                                                verifyCode:verifyCode
                                                      argv:argv
                                                     style:SWPromptStyleSystemSheet];
        NSString *promptTextAS =
            [SudoWhatPromptFormatter formatWithCommandPath:commandPath
                                                 runasUser:runasUser
                                                       cwd:cwd
                                                verifyCode:verifyCode
                                                      argv:argv
                                                     style:SWPromptStyleSelfContained];

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
        if (seteuid(g_inv.uid) != 0) {
            int saved = errno;
            close(preFd);
            set_errstr(errstr, "sudowhat: seteuid(%u) failed: %s",
                       g_inv.uid, strerror(saved));
            return -1;
        }

        LAContext *ctx = [[LAContext alloc] init];
        ctx.localizedFallbackTitle = @"Use Password";

        /* Tiered policy selection. Prefer
         * LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion
         * (renamed from ...WithBiometricsOrWatch in macOS 15) so a
         * paired Apple Watch's side-button double-click approves
         * alongside Touch ID. The policy nominally also covers iPhone
         * proximity unlock since macOS 15 / iOS 18, but that path has
         * not been observed firing in testing - watch is the verified
         * companion. That policy has no password fallback, so when the
         * user has neither biometric nor a usable companion (lid closed
         * without external Touch ID, watch off-wrist), fall back to
         * LAPolicyDeviceOwnerAuthentication, which adds password as a
         * last resort. canEvaluatePolicy reports availability against
         * the EUID we already dropped to, so the companion/biometric
         * checks see the user's enrollments. */
        LAPolicy chosen = LAPolicyDeviceOwnerAuthentication;
        NSError *policyErr = nil;
        if ([ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion
                             error:&policyErr]) {
            chosen = LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion;
        } else if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication
                                     error:&policyErr]) {
            (void)seteuid(0);
            close(preFd);
            set_errstr(errstr, "sudowhat: cannot evaluate authentication policy: %s",
                       utf8_or(policyErr.localizedDescription, "unknown"));
            return 0;
        }

        __block BOOL allowed = NO;
        __block NSError *replyErr = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [ctx evaluatePolicy:chosen
            localizedReason:promptTextLA
                      reply:^(BOOL success, NSError *err) {
            allowed = success;
            replyErr = err;
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        /* "Use Password" fallback for the BiometricsOrCompanion path.
         * BiometricsOrCompanion has no password support: clicking the
         * fallback button or otherwise failing biometric/companion
         * returns LAErrorUserFallback or LAErrorAuthenticationFailed.
         *
         * Re-prompting with LAPolicyDeviceOwnerAuthentication is awkward
         * UX (the second dialog also defaults to biometric when biometric
         * is available, requiring a second "Use Password" click), so use
         * Authorization Services here instead: a password-only dialog
         * that displays our command in the prompt body via
         * kAuthorizationEnvironmentPrompt. We're already running with
         * EUID dropped to the invoking user, so AS auths against that
         * account.
         *
         * Skip on LAErrorUserCancel so an explicit "Cancel" still
         * cancels (no second dialog). */
        if (!allowed
            && chosen == LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion
            && replyErr != nil
            && [replyErr.domain isEqualToString:LAErrorDomain]) {
            NSInteger code = replyErr.code;
            BOOL shouldRetry = (code == LAErrorUserFallback ||
                                code == LAErrorAuthenticationFailed ||
                                code == LAErrorBiometryLockout);
            if (shouldRetry) {
                const char *p = promptTextAS.UTF8String;
                const char *promptUtf8 = p ? p : "";
                AuthorizationItem rightItem = {
                    .name = "system.privilege.admin",
                    .valueLength = 0,
                    .value = NULL,
                    .flags = 0,
                };
                AuthorizationRights rights = { .count = 1, .items = &rightItem };

                AuthorizationItem envItem = {
                    .name = kAuthorizationEnvironmentPrompt,
                    .valueLength = strlen(promptUtf8),
                    .value = (void *)promptUtf8,
                    .flags = 0,
                };
                AuthorizationEnvironment env = { .count = 1, .items = &envItem };

                AuthorizationFlags flags = kAuthorizationFlagDefaults
                                         | kAuthorizationFlagInteractionAllowed
                                         | kAuthorizationFlagExtendRights;

                AuthorizationRef auth = NULL;
                OSStatus asStatus = AuthorizationCreate(&rights, &env, flags, &auth);
                if (auth) {
                    AuthorizationFree(auth, kAuthorizationFlagDefaults);
                }

                if (asStatus == errAuthorizationSuccess) {
                    allowed = YES;
                    replyErr = nil;
                } else {
                    NSString *desc;
                    if (asStatus == errAuthorizationCanceled) {
                        desc = @"Authentication canceled.";
                    } else if (asStatus == errAuthorizationDenied) {
                        desc = @"Password authentication failed.";
                    } else {
                        desc = [NSString stringWithFormat:@"AuthorizationCreate failed: %d",
                                (int)asStatus];
                    }
                    replyErr = [NSError errorWithDomain:NSOSStatusErrorDomain
                                                   code:asStatus
                                               userInfo:@{NSLocalizedDescriptionKey: desc}];
                }
            }
        }

        /* Restore root EUID. If this fails, sudo cannot exec the target,
         * so abort hard rather than continuing in a degraded state. */
        if (seteuid(0) != 0) {
            _exit(1);
        }

        if (!allowed) {
            close(preFd);
            set_errstr(errstr, "sudowhat: authorization denied: %s",
                       utf8_or(replyErr.localizedDescription, "user canceled"));
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
            set_errstr(errstr, "sudowhat: post-auth stat(%s) failed: %s",
                       commandC, strerror(saved));
            return 0;
        }
        close(preFd);

        if (postSt.st_dev != preSt.st_dev || postSt.st_ino != preSt.st_ino) {
            set_errstr(errstr, "sudowhat: target binary changed during authorization");
            return 0;
        }

        return 1;
    }
}

__attribute__((visibility("default")))
struct approval_plugin sudowhat_approval_plugin = {
    SUDO_APPROVAL_PLUGIN,
    SUDO_API_VERSION,
    sudowhat_open,
    sudowhat_close,
    sudowhat_check,
    NULL
};
