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

/* Denial reason, in sudowhat's own voice.
 *
 * We interpret the auth outcome and phrase it ourselves rather than forwarding
 * the framework's localizedDescription. That Apple string is GUI-facing: it is
 * localized (non-ASCII on a non-English system), sentence-cased with a trailing
 * period, and free to change across macOS releases - none of which belongs in a
 * Unix errstr we emit, prefixed with our own name, next to sudo's own lowercase
 * output. The phrase itself carries the provenance ("password ..." for the AS
 * fallback vs a bare "authentication ..." for the biometric path), so no
 * separate source tag is needed. An unmapped code still degrades to an ASCII
 * "(... N)" - debuggable, still our voice, no locale leak. */
static NSString *sw_denial_reason(NSError *err) {
    if (err == nil) {
        return @"authentication denied";
    }
    if ([err.domain isEqualToString:LAErrorDomain]) {
        switch (err.code) {
            case LAErrorUserCancel:
            case LAErrorSystemCancel:
            case LAErrorAppCancel:
                return @"authentication canceled";
            case LAErrorUserFallback:
                return @"authentication canceled";
            case LAErrorAuthenticationFailed:
                return @"authentication failed";
            case LAErrorBiometryLockout:
                return @"biometry locked out";
            case LAErrorPasscodeNotSet:
                return @"no passcode set";
            default:
                return [NSString stringWithFormat:@"authentication error (LAError %ld)",
                        (long)err.code];
        }
    }
    if ([err.domain isEqualToString:NSOSStatusErrorDomain]) {
        switch (err.code) {
            case errAuthorizationCanceled:
                return @"authentication canceled";
            case errAuthorizationDenied:
                return @"password authentication failed";
            default:
                return [NSString stringWithFormat:@"authentication error (OSStatus %ld)",
                        (long)err.code];
        }
    }
    return [NSString stringWithFormat:@"authentication error (%@ %ld)",
            err.domain, (long)err.code];
}

/* Channel-binding nonce, uppercase only. Built from Crockford base32 (which
 * already drops I, O, U) with edits for the two surfaces this code is compared
 * across — the SF system font on the LAContext sheet and the monospace
 * terminal:
 *   - drop '0': SF renders zero with no slash or dot, misread vs D/Q.
 *   - keep 'L', drop '1': Crockford drops L only because it folds case
 *     (lowercase 'l' == '1'); uppercase-only, capital L's foot makes it
 *     distinct from a bare bar. But '1' and 'L' share a vertical-stroke
 *     silhouette, so keep one of the two, not both.
 *   - break each surviving digit/letter homoglyph pair 2/Z 5/S 6/G 8/B by
 *     dropping one side: drop 2 B G S, keep Z 5 6 8. Dropping one side ends
 *     the confusion; dropping both would only shrink the keyspace (easier to
 *     guess) for no added clarity.
 * Net 27 symbols, no internal look-alike pair. 27^4 = 531441 ~= 19.0 bits,
 * ample for one-shot human comparison. arc4random_uniform is cryptographically
 * strong and avoids modulo bias. */
static void generate_verify_nonce(char *out, size_t outsz) {
    static const char alphabet[] = "3456789ACDEFHJKLMNPQRTVWXYZ";
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

/* Does /etc/pam.d/sudo_local carry pam_sudowhat's INTEGRITY line
 *   auth requisite <SUDOWHAT_PAM_PATH>
 * at our own baked module path? This line is present in BOTH the default
 * console-only variant and the non-console gate variant, and it is what makes
 * pam_sudowhat's auth entry run — and set the policy-deference marker — whenever
 * sudo runs the PAM auth stack. The absent-marker skip relies on that premise:
 * if this line is NOT present, an absent marker cannot be trusted to mean
 * "sudoers waived authentication" (pam_sudowhat might simply be unwired), so the
 * caller must fail toward prompting. A strict subset of what
 * sudowhat_text_is_gate_variant checks; token-based and whitespace-insensitive,
 * '#'-comments and blank lines skipped, pinned to SUDOWHAT_PAM_PATH so a line at
 * some other module path does not count. file-static for the offline unit test.
 *
 * NOTE: like the existing gate-variant check, this reads sudo_local only, not
 * the OS-owned /etc/pam.d/sudo that includes it. Editing either file to unwire
 * pam_sudowhat requires root, which is outside the threat model (an attacker
 * with root has already won); this is defense-in-depth against a misconfigured
 * sudo_local, not a guarantee against a root actor. */
static BOOL sudowhat_text_has_integrity_line(NSString *content) {
    if (content == nil) return NO;
    NSCharacterSet *ws = [NSCharacterSet whitespaceCharacterSet];
    for (NSString *rawLine in [content componentsSeparatedByString:@"\n"]) {
        NSString *line = [rawLine stringByTrimmingCharactersInSet:ws];
        if (line.length == 0 || [line hasPrefix:@"#"]) continue;
        NSMutableArray<NSString *> *f = [NSMutableArray array];
        for (NSString *tok in [line componentsSeparatedByCharactersInSet:ws]) {
            if (tok.length > 0) [f addObject:tok];
        }
        if (f.count == 3
            && [f[0] isEqualToString:@"auth"]
            && [f[1] isEqualToString:@"requisite"]
            && [f[2] isEqualToString:@SUDOWHAT_PAM_PATH]) {
            return YES;
        }
    }
    return NO;
}

/* Reads /etc/pam.d/sudo_local and reports whether pam_sudowhat's integrity line
 * is wired in. Unreadable / absent / wrong shape -> NO, so an absent marker is
 * treated as untrustworthy and the console user is prompted (fail-safe). */
static BOOL sudowhat_pam_integrity_line_installed(void) {
    NSString *content = [NSString stringWithContentsOfFile:@SUDOWHAT_SUDO_LOCAL
                                                  encoding:NSUTF8StringEncoding
                                                     error:NULL];
    return sudowhat_text_has_integrity_line(content);
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

/* Build-time emphasis preset for the tty echo, chosen by -DSW_VERIFY_STYLE
 * (services.sudowhat.verifyStyle in the nix module; SUDOWHAT_VERIFY_STYLE in the
 * Makefile). The style names one of the fixed SGR sequences below — never a
 * free-form string — so the only escape bytes that can ever reach a terminal
 * stay a small, reviewed set and a malformed escape cannot be expressed. Every
 * color leads with "1;" (bold + color) so the emphasis still carries on a theme
 * where the color washes out; "plain" is the empty SGR, which routes
 * format_verify_line to its unstyled branch (a compile-time NO_COLOR); "random"
 * picks one of a curated color subset per invocation (sw_verify_sgr below). Bold
 * is the default because it is background-independent. Emphasis only, never a trust
 * signal (see write_verify_code_to_tty).
 *
 * The Makefile normalizes any unknown style to bold (with a warning), so in a
 * supported build this token-paste only ever sees a known name; a raw -D that
 * bypasses the Makefile with an unknown name yields an undefined identifier here
 * and fails the compile — the intended fail-closed result for that unsupported
 * path. */
#ifndef SW_VERIFY_STYLE
#define SW_VERIFY_STYLE bold
#endif
#define SW_SGR_plain   ""
#define SW_SGR_bold    "1"
#define SW_SGR_red     "1;31"
#define SW_SGR_green   "1;32"
#define SW_SGR_yellow  "1;33"
#define SW_SGR_blue    "1;34"
#define SW_SGR_magenta "1;35"
#define SW_SGR_cyan    "1;36"
#define SW_SGR_CAT(x)  SW_SGR_##x
#define SW_SGR_SEL(x)  SW_SGR_CAT(x)

/* "random" is the one style resolved at runtime: each invocation picks one of a
 * curated color subset. Detected here so every other style stays compile-time.
 * SW_VS_<name> is 0 for each fixed preset and 1 only for "random"; an undefined
 * SW_VS_<name> (impossible in a Makefile build) evaluates to 0 in #if, i.e. a
 * fixed style, and then fails to compile at SW_SGR_SEL below — the same
 * fail-closed path as an unknown fixed name. */
#define SW_VS_plain   0
#define SW_VS_bold    0
#define SW_VS_red     0
#define SW_VS_green   0
#define SW_VS_yellow  0
#define SW_VS_blue    0
#define SW_VS_magenta 0
#define SW_VS_cyan    0
#define SW_VS_random  1
#define SW_VS_CAT(x)  SW_VS_##x
#define SW_VS_SEL(x)  SW_VS_CAT(x)

#if SW_VS_SEL(SW_VERIFY_STYLE)
/* Curated subset, legible on both light and dark backgrounds. Every entry is
 * bold+color, so even where the color washes out the bold still carries. The
 * table is compile-time constant — only the index is runtime — so the bytes
 * reaching the tty stay the same reviewed set as the fixed presets. blue (dim on
 * common dark backgrounds even bolded) and yellow (washes out on light) are
 * excluded. */
static const char *const sw_sgr_random_set[] = {
    SW_SGR_red, SW_SGR_green, SW_SGR_magenta, SW_SGR_cyan,
};
static const char *sw_verify_sgr(void) {
    uint32_t n = (uint32_t)(sizeof sw_sgr_random_set / sizeof sw_sgr_random_set[0]);
    return sw_sgr_random_set[arc4random_uniform(n)];
}
#else
/* Fixed style: the SGR is a compile-time constant. An unknown name here is an
 * undefined SW_SGR_<name>, which fails the compile (fail-closed). */
static const char *sw_verify_sgr(void) { return SW_SGR_SEL(SW_VERIFY_STYLE); }
#endif

/* Render the verify-code line into buf. Styled (the resolved SGR wrapping only
 * the code) when colorize is YES and the style is not "plain" (empty SGR);
 * unstyled otherwise. The SGR comes only from the fixed table above, never from
 * input, so substituting it via %s adds no more surface than the nonce already
 * does. Returns snprintf's count so callers can fail closed on truncation.
 * Deterministic for every fixed style (unit-testable); "random" is the sole
 * non-deterministic case. */
static int format_verify_line(char *buf, size_t bufsz, const char *code,
                              BOOL colorize) {
    const char *sgr = sw_verify_sgr();
    if (colorize && sgr[0] != '\0') {
        return snprintf(buf, bufsz,
                        SW_VERIFY_PREFIX "\033[%sm%s\033[0m" SW_VERIFY_SUFFIX,
                        sgr, code);
    }
    return snprintf(buf, bufsz, SW_VERIFY_LINE_FMT, code);
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

/* Emit the channel-binding verify code to the controlling terminal — and ONLY
 * there. /dev/tty is the one channel no fd redirect can hide (a shell rewires
 * only fds 0-2; the controlling terminal is untouched), which is the whole
 * reason the code lives there. When there is no controlling terminal at all —
 * an in-session process launched by the Dock / Spotlight / a GUI agent / a tool
 * like Claude Code rather than from a shell (root and non-console callers have
 * already returned upstream in sudowhat_check, so this is never the cron/SSH
 * case) — we emit NOTHING rather than fall back to sudo's stderr.
 *
 * Dropping that fallback is deliberate: in those contexts stderr is seldom a
 * live terminal a human is watching, so the fallback rarely delivered its one
 * benefit, while it would clutter the process's error stream and could be
 * slurped into a `2>file` capture. And the security floor does not need it — a
 * sheet the user did not initiate shows no matching code on the terminal they
 * ARE watching, which is the entire signal; "no code on my terminal" is exactly
 * the cue to distrust. So the rule is simply: the code appears on the terminal
 * that launched sudo, or nowhere. (Genuine errors still reach the user via
 * set_errstr/stderr; only this out-of-band convenience signal is tty-or-nothing.)
 *
 * Having no stderr channel here is structural, not merely a runtime choice:
 * emit_verify_code takes no printf, so it CANNOT write anywhere but the tty.
 * ttyPath is a parameter so the offline unit test can aim it at a temp file. */
static void emit_verify_code(const char *ttyPath, const char *code,
                             BOOL colorAllowed) {
    write_verify_code_to_tty(ttyPath, code, colorAllowed);
}

/* Build-time master switch for POLICY DEFERENCE, chosen by -DSW_POLICY_DEFERENCE
 * (services.sudowhat.policyDeference in the nix module; SUDOWHAT_POLICY_DEFERENCE
 * in the Makefile). Same fail-closed token machinery as the knobs above.
 *
 *   on  - (default) when sudoers itself waived authentication for this
 *         invocation (a NOPASSWD rule, `Defaults !authenticate`, or a valid
 *         timestamp cache), the console user's Touch ID prompt is SKIPPED and
 *         the command just runs. Detected via the pam_sudowhat auth marker: sudo
 *         runs the PAM auth stack (which sets the marker) only when it requires
 *         authentication, so an absent marker — with pam_sudowhat still wired
 *         into the chain — means sudoers waived it. Fail-safe in every uncertain
 *         direction (see sw_defer_decision).
 *   off - the console user is always prompted, exactly as before this feature
 *         (the marker is not consulted).
 *
 * An unknown token yields an undefined SW_PD_<name> and fails the compile. */
#ifndef SW_POLICY_DEFERENCE
#define SW_POLICY_DEFERENCE on
#endif
#define SW_PD_off      0
#define SW_PD_on       1
#define SW_PD_CAT(x)   SW_PD_##x
#define SW_PD_SEL(x)   SW_PD_CAT(x)
enum { sw_policy_deference_mode = SW_PD_SEL(SW_POLICY_DEFERENCE) };

/* Pure decision: should the console user's approval prompt be SKIPPED because
 * sudoers waived authentication for this invocation? All inputs are explicit so
 * every branch is unit-testable. Fail-safe in every uncertain direction — any
 * doubt returns NO (prompt):
 *   deference off             -> NO   (today's always-prompt behavior)
 *   marker present            -> NO   (sudo ran the auth stack => auth required)
 *   integrity line not wired  -> NO   (an absent marker can't be trusted to mean
 *                                      "waived" if pam_sudowhat may be unwired)
 *   otherwise                 -> YES  (auth waived, chain intact => skip)
 *
 * The security property that makes presence-only enough: SKIP is the dangerous
 * outcome and it is driven by marker ABSENCE, which cannot be forged. sudo's own
 * pam_sudowhat setenv() runs in-process AFTER the caller's environment was
 * captured and overwrites any pre-set value, so a caller can never make the
 * marker absent when the auth stack actually ran — they can only ADD it (forcing
 * a prompt, the safe direction). A secret marker value would only protect
 * PRESENCE, which needs no protection. */
static BOOL sw_defer_decision(BOOL deferenceOn, BOOL markerPresent,
                              BOOL integrityInstalled) {
    if (!deferenceOn)        return NO;
    if (markerPresent)       return NO;
    if (!integrityInstalled) return NO;
    return YES;
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

/* Verify the audit plugin's on-disk signature IF it is installed. The audit
 * plugin owns terminal command display (its open() runs before this check); a
 * present-but-tampered audit bundle could draw a false command, so we refuse to
 * proceed when it fails to validate. It is OPTIONAL, though: an ABSENT bundle
 * simply means no terminal display, with auth unaffected, so absence passes.
 * This is tamper-evidence in place, not removal-proofing — removing the bundle
 * or its sudo.conf line needs root, which is outside the threat model. Uses the
 * plugin's own signature class (SudoWhatSignatureVerifier). Returns YES when
 * absent or validly signed; NO (with *error set) when present-but-invalid. */
static BOOL sudowhat_audit_bundle_ok(NSError **error) {
    if (![[NSFileManager defaultManager] fileExistsAtPath:@SUDOWHAT_AUDIT_PATH]) {
        return YES;
    }
    return [SudoWhatSignatureVerifier verifyPath:@SUDOWHAT_AUDIT_PATH error:error];
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

        /* (1b) If the audit plugin (terminal command display) is installed, its
         * signature must validate — a tampered display bundle could lie about
         * the command, so fail closed. Absent is fine (no display, auth
         * unaffected). See sudowhat_audit_bundle_ok. */
        if (!sudowhat_audit_bundle_ok(&sigErr)) {
            set_errstr(errstr, "sudowhat: audit plugin signature invalid: %s",
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

        /* Resolve cwd once — used by the policy-deference echo just below and by
         * the prompt formatting further down. Preference: command_info["cwd"]
         * (set when sudoers has cwd=) > the stashed invoking cwd from user_info
         * (the default case, where sudo inherits the caller's cwd without
         * emitting command_info["cwd"]). Either way it reflects where execve
         * will run. */
        const char *cwdC = find_kv(command_info, "cwd");
        NSString *cwd = nil;
        if (cwdC && cwdC[0] != '\0') {
            cwd = [NSString stringWithUTF8String:cwdC];
        } else if (g_inv.have_cwd) {
            cwd = [NSString stringWithUTF8String:g_inv.cwd];
        }

        /* (3.5) POLICY DEFERENCE. sudo runs the PAM auth stack — and pam_sudowhat
         * sets SUDOWHAT_AUTH_MARKER_ENV — only when sudoers requires
         * authentication. A NOPASSWD rule, `Defaults !authenticate`, or a valid
         * timestamp cache skip it entirely, leaving the marker absent. Honor that
         * by SKIPPING our own Touch ID prompt: the whole point is that a NOPASSWD
         * command just runs, with no sheet and no password. This is an
         * authorization-trust step, not an authentication one — sudoers already
         * authorized the caller (the approval plugin runs after check_policy
         * succeeds); here we simply do not re-gate what sudoers chose not to
         * gate. Separate from the root and non-console exits above; it only
         * affects the console user's prompt.
         *
         * Read the marker and immediately clear it (hygiene: no stale value can
         * linger; sudo builds the command's environment separately, so this
         * never reaches the execed program regardless). The integrity-line check
         * runs only when it can matter (deference on AND marker absent) and
         * confirms an absent marker really means "the auth stack did not run"
         * rather than "pam_sudowhat is unwired" — otherwise sw_defer_decision
         * fails toward prompting. No TOCTOU pre-stat is needed on this path:
         * there is no authorization delay, hence no window to swap the binary.
         *
         * timestamp interaction: with a non-zero timestamp_timeout a cached
         * credential also skips the auth stack, so a second in-window command on
         * the same tty is deferred and runs with no sheet — sudo's normal grace
         * after the first real factor on that tty. Set timestamp_timeout=0 (the
         * module default) for a sheet on every command. */
        const char *authMarker = getenv(SUDOWHAT_AUTH_MARKER_ENV);
        BOOL markerPresent = (authMarker != NULL);
        unsetenv(SUDOWHAT_AUTH_MARKER_ENV);
        BOOL deferenceOn = (sw_policy_deference_mode == SW_PD_on);
        BOOL integrityInstalled =
            (deferenceOn && !markerPresent)
                ? sudowhat_pam_integrity_line_installed() : NO;
        if (sw_defer_decision(deferenceOn, markerPresent, integrityInstalled)) {
            /* The command was already shown on the controlling terminal by the
             * audit plugin (its open() runs before this check), so a deferred
             * NOPASSWD run still discloses what ran — there is nothing to echo
             * here. Record the skip and allow. */
            syslog(LOG_AUTHPRIV | LOG_NOTICE,
                   "sudowhat: prompt skipped, sudoers waived authentication "
                   "(invoking uid %u)", g_inv.uid);
            return 1;
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

        /* (4) Format prompt. cwd was resolved above (shared with the
         * policy-deference echo) and reflects where execve will run. */
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

        /* Two renderings of the same content: LAContext wraps our text in
         * a system-supplied sentence and appends a period, so we use the
         * SystemSheet style there. Authorization Services (password
         * fallback below) shows our text verbatim, so SelfContained is the
         * whole message. A "(see terminal)" marker either sheet emits for an
         * over-long item is backed by the audit plugin's full-command line,
         * already printed to this terminal before this plugin ran. (Formatting
         * is pure and precedes the seteuid drop, so doing it before the tty
         * write is safe.) */
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

        /* The command itself is shown on the terminal by the audit plugin
         * (before this plugin runs) and on the sheet below (resolved), so the
         * approval plugin emits only the verify code here — the one out-of-band
         * signal binding the sheet to the terminal. No fd redirect can hide it
         * (emit_verify_code targets /dev/tty). */
        emit_verify_code("/dev/tty", nonceBuf, sw_color_allowed());

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
            /* Not a routine denial but a "the auth stack can't even start"
             * setup failure, where the framework's own detail ("Biometry is not
             * available", a passcode/enrollment problem, ...) is the useful
             * forensic. So unlike sw_denial_reason() we forward it verbatim -
             * but attribute the source ("LocalAuthentication:") so the reader
             * knows the sentence-cased, possibly-localized text is a quoted
             * framework message, not sudowhat's own voice. */
            set_errstr(errstr, "sudowhat: cannot evaluate authentication policy: LocalAuthentication: %s",
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
                    /* Carry the OSStatus; sw_denial_reason() phrases it. */
                    replyErr = [NSError errorWithDomain:NSOSStatusErrorDomain
                                                   code:asStatus
                                               userInfo:nil];
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
                       sw_denial_reason(replyErr).UTF8String);
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
