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
#include "escape_core.h"
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

/* sudo's conversation callback, delivered to open() only -- check() has no
 * conversation parameter -- so it is stashed here for the one caller that needs
 * it: the exec_confirm prompt (see sw_step_aside_allow). Cleared in close()
 * alongside g_plugin_printf, so a stale pointer can never outlive the plugin
 * session. NULL means "no conversation available", which every caller must treat
 * as a conversation failure rather than as a silent success. */
static sudo_conv_t g_conversation = NULL;

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

/* The verify-code line. One set of pieces so the styled and the unstyled
 * rendering can never drift apart. The substituted code is the plugin's own
 * nonce -- no caller-controlled bytes reach this line -- so it needs no escaping.
 *
 * The line is a FIELD in the audit plugin's label gutter, not a sentence: the
 * same "sudowhat: " provenance prefix, the label padded so the value starts in
 * the same column as user / directory / input / path (SW_AUDIT_GUTTER, 12 -- the
 * longest label "directory:" plus two spaces), then the code, then what to do
 * with it. The two plugins are separate bundles that never share a translation
 * unit, so the width is duplicated rather than shared; if one moves, move both.
 *
 * The gutter family is now six labels across the two bundles: run as:, directory:,
 * input: and path: from the audit plugin, then verify: and execute: from this
 * one.
 * Every value starts at column 22 (10 bytes of "sudowhat: " plus the 12-wide
 * gutter), so the whole ceremony reads as one table however it is split between
 * bundles.
 *
 *   sudowhat: verify:     Z96E  (compare with the prompt)
 *
 * Styling is deliberately thin: the label bold like the other rows, the code
 * carrying a fixed bold magenta, the trailing instruction dim because it is our
 * own chrome, not a value. No attention colour -- yellow in this block means
 * "the target user is not root", and spending it here would both say something
 * the reader already knows and give one colour two meanings.
 *
 * The code's emphasis is a compile-time constant, not a knob: one reviewed SGR
 * is the only escape sequence that can ever reach the terminal here, so there is
 * nothing to misconfigure, and the emphasis is cosmetic in the first place --
 * never a trust signal, since the anchor is the code matching the
 * system-rendered prompt (see write_verify_code_to_tty). Accepted imperfection:
 * escape_core's anomaly palette also spends bold magenta on control-byte
 * escapes, so a control-byte span inside a command value shares this colour.
 * That is rare, and a control byte in argv is itself an alarm the reader should
 * stop at, so the collision is accepted rather than designed around. */
#define SW_VERIFY_LABEL  "verify:"
#define SW_VERIFY_GAP    "     "     /* pads "verify:" (7) out to the 12-col gutter */
#define SW_VERIFY_TAIL   "(compare with the prompt)"

#define SW_VERIFY_PREFIX "sudowhat: " SW_VERIFY_LABEL SW_VERIFY_GAP
#define SW_VERIFY_SUFFIX "  " SW_VERIFY_TAIL "\n"
#define SW_VERIFY_LINE_FMT      SW_VERIFY_PREFIX "%s" SW_VERIFY_SUFFIX

#define SW_VERIFY_PREFIX_STYLED \
    "sudowhat: \033[1m" SW_VERIFY_LABEL "\033[0m" SW_VERIFY_GAP
#define SW_VERIFY_SUFFIX_STYLED \
    "  \033[2m" SW_VERIFY_TAIL "\033[0m\n"

/* The code's emphasis: bold magenta, one compile-time constant. Bold leads so
 * the emphasis still carries on a theme where the colour washes out. There is no
 * build-time or runtime selector -- see the block comment above for why the
 * style is fixed. */
#define SW_VERIFY_SGR "1;35"

/* Render the verify-code line into buf. Styled (bold label, bold magenta code,
 * dim tail) when colorize is YES; entirely unstyled otherwise. Both branches lay
 * out the SAME field widths, so the plain line is the styled one with every
 * escape sequence removed. Every escape byte here is a literal in this file,
 * never anything derived from input. Returns snprintf's count so callers can
 * fail closed on truncation. Fully deterministic, hence unit-testable. */
static int format_verify_line(char *buf, size_t bufsz, const char *code,
                              BOOL colorize) {
    if (colorize) {
        return snprintf(buf, bufsz,
                        SW_VERIFY_PREFIX_STYLED
                        "\033[" SW_VERIFY_SGR "m%s\033[0m"
                        SW_VERIFY_SUFFIX_STYLED,
                        code);
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

    /* Sized for the widest line the styled branch can produce (the gutter field,
     * a 4-char code, the tail, and five SGR sequences -- about 81 bytes) with
     * room to spare, because truncation here fails the whole write: the user
     * would get NO code on the terminal, which is exactly the cue to distrust. */
    char line[128];
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

/* ---------------------------------------------------------------------------
 * The `execute:` line -- the RESOLVED command.
 *
 * DISPLAY OWNERSHIP (docs/design-resolved-exec.md, section 3). The audit plugin
 * (plugin/sudowhat_audit.m) owns the PRE-AUTH block -- run as:, directory:,
 * input:, and path: (the caller's PATH, shown only for a bare command name;
 * not a claim about the final resolution PATH, which sudoers secure_path may
 * override) -- everything that exists before sudo has resolved the command. This
 * plugin owns DECISION-ADJACENT display -- verify:, the LAContext sheet, and
 * this execute: line -- everything that exists only after resolution. The audit
 * plugin's open() runs before the policy step, where the command is still only
 * what the user typed; check() here runs after it, holding sudo's own
 * command_info["command"]. The seam is stated on both sides; if one moves, move
 * both.
 *
 * INVARIANT: the path displayed is NEVER resolved plugin-side. Only
 * command_info["command"] (plus run_argv) is ever shown, because an independent
 * PATH walk here could diverge from what sudo actually execve()s -- i.e. it
 * could display a lie, which is worse than displaying nothing.
 *
 * Both bundles render command lines through the same Rust escape core, so
 * input: and execute: cannot disagree about how a token is spelled: any
 * difference the reader sees between the two lines is a real difference in the
 * command, which IS the anomaly display (a shadowed bare name shows up as
 * input/execute divergence, with no heuristic needed).
 * ------------------------------------------------------------------------- */

/* Build-time colour policy for the execute: VALUE, chosen by -DSW_ECHO_COLOR
 * (services.sudowhat.echoColor in the nix module; SUDOWHAT_ECHO_COLOR in the
 * Makefile).
 *
 *   on  - (default) the resolved command line is highlighted by role: the
 *         program's directory part plain cyan and its basename bold cyan,
 *         option flags bold blue, every other token plain, the quotes the
 *         escape core itself added dim, and escaped/anomalous spans in the
 *         fixed anomaly palette on top.
 *   off - the resolved command line renders plain.
 *
 * ONE token governs BOTH command lines, input: and execute:, because a reader
 * sees one display: an admin who silenced the colour on the line the audit
 * bundle prints did not ask for a coloured twin of it two lines later. The knob
 * is therefore in the GLOBAL Makefile CFLAGS, not target-specific to either
 * bundle.
 *
 * The two lines render at different WEIGHTS under `on`. execute: keeps the full
 * role palette above; the audit bundle's input: line renders its routine tokens
 * dim (sw_full_command_line_colored_dim) with the anomaly spans still at full
 * strength, so the resolved command reads as the authoritative one and the
 * pre-resolution line sits quiet beneath it. Both come out of ONE walk in
 * escape_core over one token list -- the base palette is the only difference --
 * so the two can still never disagree on a token.
 *
 * It governs the command VALUE only. The frame around it -- the provenance
 * prefix, the bold label, the gutter -- follows the runtime NO_COLOR / TERM /
 * isatty gates alone, exactly as the audit block's frame rows and the verify:
 * line do with their own knob: the frame is our own fixed chrome, not a
 * rendering of untrusted argv.
 *
 * Deliberately duplicated from plugin/sudowhat_audit.m (SW_ECHO_COLOR,
 * SW_ACOL_*, its sw_audit_color_mode), which carries the colouriser's full
 * rationale: the two bundles are separate Mach-O images that never share a
 * translation unit, so this small token machinery is copied rather than linked.
 * If one moves, move both.
 *
 * An unknown token yields an undefined SW_ACOL_<name> and fails the compile --
 * the intended fail-closed result for a raw -D that bypasses the Makefile's
 * validation. */
#ifndef SW_ECHO_COLOR
#define SW_ECHO_COLOR on
#endif
#define SW_ACOL_off        0
#define SW_ACOL_on         1
#define SW_ACOL_CAT(x)     SW_ACOL_##x
#define SW_ACOL_SEL(x)     SW_ACOL_CAT(x)
enum { sw_echo_color_mode = SW_ACOL_SEL(SW_ECHO_COLOR) };

#define SW_EXEC_LABEL  "execute:"
#define SW_EXEC_GAP    "    "   /* pads "execute:" (8) out to the 12-col gutter */

#define SW_EXEC_PREFIX "sudowhat: " SW_EXEC_LABEL SW_EXEC_GAP
#define SW_EXEC_PREFIX_STYLED \
    "sudowhat: \033[1m" SW_EXEC_LABEL "\033[0m" SW_EXEC_GAP

/* The solo frame: label, one space, value -- no gutter. Same bold-the-label-only
 * emphasis as the grouped twin. */
#define SW_EXEC_PREFIX_SOLO "sudowhat: " SW_EXEC_LABEL " "
#define SW_EXEC_PREFIX_SOLO_STYLED \
    "sudowhat: \033[1m" SW_EXEC_LABEL "\033[0m "

/* Which of those two frames an emit site asks for.
 *
 * GROUPED (every site but one): the label is padded out to the shared 12-col
 * gutter so the value lands in the same column as the audit block's run as: /
 * directory: / input: rows and the verify: line. That column is the entire
 * reason the two bundles duplicate the width rather than share it.
 *
 * SOLO (the root-bypass site only): the gutter is dropped. That site is
 * PROVABLY alone on the terminal -- the audit plugin exempts uid 0, so no
 * input: block precedes it, and verify: is raised only on the console biometric
 * path, which the root bypass returns before reaching. A column aligns
 * siblings; with no siblings, a label floating four spaces from its value
 * reads as a rendering bug rather than as alignment. Same unpadded shape the
 * Linux port prints for a lone line.
 *
 * One accepted edge: a NON-root run on a build with auditDisplay=off is alone
 * too, and still gets the grouped form. This bundle cannot see the audit
 * bundle's build token (separate images, separate -D), and that admin
 * explicitly chose to strip the block, so the alignment is vestigial there
 * rather than wrong. Deciding per emit site keeps the choice compile-time and
 * provable instead of guessing at another bundle's configuration. */
typedef enum {
    SW_EXEC_GROUPED = 0,
    SW_EXEC_SOLO    = 1,
} sw_exec_layout;

/* The two escape_core command-line renderers share one signature, so the caller
 * below can pick between them without duplicating the two-call sizing dance.
 * Deliberately duplicated from plugin/sudowhat_audit.m (sw_cmdline_fn,
 * sw_audit_render, sw_audit_command_line_with): the two bundles are separate
 * Mach-O images that never share a translation unit, so this small machinery is
 * copied rather than linked. If one moves, move both. */
typedef int (*sw_cmdline_fn)(const uint8_t *path, size_t path_len,
                             const uint8_t *const *argv,
                             const size_t *argv_lens, size_t argv_count,
                             uint8_t *out, size_t out_cap, size_t *needed);

/* Run one renderer with the two-call sizing protocol: probe for the length,
 * allocate, fill. Returns nil on allocation failure or a non-OK return, which is
 * what makes the colour->plain fallback below a plain nil check. */
static NSString *sw_exec_render(sw_cmdline_fn render,
                                const char *path, size_t path_len,
                                const uint8_t **argv, size_t *lens, size_t n) {
    size_t needed = 0;
    render((const uint8_t *)path, path_len, argv, lens, n, NULL, 0, &needed);
    size_t cap = needed + 1;
    uint8_t *buf = malloc(cap);
    if (buf == NULL) return nil;
    size_t got = 0;
    NSString *s = nil;
    if (render((const uint8_t *)path, path_len, argv, lens, n, buf, cap, &got)
        == SW_ESCAPE_OK) {
        s = [[NSString alloc] initWithBytes:buf length:got
                                   encoding:NSUTF8StringEncoding];
    }
    free(buf);
    return s;
}

/* Build the RESOLVED command line: sudo's command_info["command"] as the path,
 * then run_argv, with the escape core dropping run_argv[0] when it duplicates
 * the path or its basename (the same dedup the sheet's commandPartsForPath
 * does, from the same token list). Every token is shell-quoted and
 * control-character escaped there, so nothing a caller typed can reach the
 * terminal as a raw escape sequence.
 *
 * When colour is on the coloured renderer is tried first and the plain one is
 * the fallback: colour is layout over the same bytes, so degrading to plain
 * loses emphasis and nothing else. The renderers are parameters (production
 * passes the escape_core pair) to keep that fallback isolated and testable, the
 * same reason write_exec_line_to_tty takes its ttyPath. Returns nil with no
 * path, or on allocation failure. */
static NSString *sw_exec_command_line_with(sw_cmdline_fn colored,
                                           sw_cmdline_fn plain,
                                           const char *path,
                                           char * const run_argv[],
                                           BOOL color) {
    if (path == NULL) return nil;
    size_t path_len = strlen(path);

    size_t n = 0;
    if (run_argv != NULL) {
        while (run_argv[n] != NULL) n++;
    }

    const uint8_t **argv = NULL;
    size_t *lens = NULL;
    if (n > 0) {
        argv = calloc(n, sizeof(*argv));
        lens = calloc(n, sizeof(*lens));
        if (argv == NULL || lens == NULL) { free(argv); free(lens); return nil; }
        for (size_t i = 0; i < n; i++) {
            argv[i] = (const uint8_t *)run_argv[i];
            lens[i] = strlen(run_argv[i]);
        }
    }

    NSString *s = nil;
    if (color) s = sw_exec_render(colored, path, path_len, argv, lens, n);
    if (s == nil) s = sw_exec_render(plain, path, path_len, argv, lens, n);

    free(argv);
    free(lens);
    return s;
}

static NSString *sw_exec_command_line(const char *path,
                                      char * const run_argv[], BOOL color) {
    return sw_exec_command_line_with(sw_full_command_line_colored,
                                     sw_full_command_line,
                                     path, run_argv, color);
}

/* Render the whole execute: line -- frame plus value -- as one string.
 *
 * Pure and deterministic, so the exact bytes are unit-testable without a
 * terminal, exactly like format_verify_line above. layout picks the grouped or
 * solo frame (see sw_exec_layout).
 *
 * FRAME COLOUR AND VALUE COLOUR ARE SEPARATE INPUTS, because they answer to
 * different authorities. The frame is ours -- the provenance prefix and the
 * bold label -- and follows the runtime gates alone. The value's styling
 * belongs to the escape-core renderer, which colours the program path and the
 * anomaly spans by role, and is additionally governed by the echoColor build
 * token (see SW_ECHO_COLOR above). Keeping both as parameters keeps this
 * function pure and every combination table-testable; the production write site
 * derives them.
 *
 * Within one layout both frame branches lay out the SAME field widths, so the
 * plain line is the styled one with every escape sequence removed.
 *
 * Returns nil when there is no path or the renderers produced nothing, which
 * makes "show nothing" a plain nil check at the write site rather than a
 * half-built line reaching a terminal. */
static NSString *sw_format_exec_line(const char *path,
                                     char * const run_argv[],
                                     sw_exec_layout layout,
                                     BOOL frameColor, BOOL valueColor) {
    if (path == NULL) return nil;
    NSString *value = sw_exec_command_line(path, run_argv, valueColor);
    if (value.length == 0) return nil;
    const char *prefix;
    if (layout == SW_EXEC_SOLO) {
        prefix = frameColor ? SW_EXEC_PREFIX_SOLO_STYLED : SW_EXEC_PREFIX_SOLO;
    } else {
        prefix = frameColor ? SW_EXEC_PREFIX_STYLED : SW_EXEC_PREFIX;
    }
    return [NSString stringWithFormat:@"%s%@\n", prefix, value];
}

/* Write the execute: line straight to the controlling terminal -- and ONLY there,
 * exactly like write_verify_code_to_tty above and the audit plugin's block:
 * /dev/tty is the one channel a shell's fd redirects (`>f`, `2>f`, `&>f`) cannot
 * touch, and a captured `2>file` must never receive a possibly-confidential
 * command. There is no stderr fallback and no printf parameter that could carry
 * one, so this function structurally CANNOT write anywhere but the tty.
 *
 * O_NOCTTY: never acquire a controlling terminal as a side effect. O_CLOEXEC:
 * never leak the fd into the execed target. Opened with EUID still root (the
 * seteuid drop happens later on the console path), which may write the user's
 * tty, exactly as sudo's own prompt does.
 *
 * isatty() on the opened fd is the final colour gate, so SGR bytes only ever
 * reach a real terminal -- never a file or a pipe, where they would corrupt a
 * captured log rather than emphasise anything. ttyPath is a parameter (always
 * "/dev/tty" in production) so the offline unit test can point it at a temp file
 * and read the bytes back. Returns YES iff the whole line was written. */
static BOOL write_exec_line_to_tty(const char *ttyPath, const char *path,
                                   char * const run_argv[],
                                   sw_exec_layout layout, BOOL colorAllowed) {
    if (path == NULL) return NO;

    int fd = open(ttyPath, O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) return NO;

    /* The two colour decisions, derived here and nowhere else. The frame obeys
     * the runtime gates alone (env opt-outs, folded into colorAllowed, then
     * isatty); the value additionally needs the echoColor build token, so
     * echoColor=off strips the role colouring from execute: exactly as it does
     * from the audit bundle's input:, while both lines keep their bold label. */
    BOOL frameColor = colorAllowed && isatty(fd);
    BOOL valueColor = frameColor && (sw_echo_color_mode == SW_ACOL_on);

    /* The value is unbounded (a command line can be arbitrarily long), so the
     * line is assembled as an NSString and written as bytes rather than through
     * a fixed stack buffer the way the 4-char verify code is. Nothing is
     * truncated: an elided execute: line would be worse than none, because the
     * reader would trust an incomplete command. */
    NSString *line = sw_format_exec_line(path, run_argv, layout,
                                         frameColor, valueColor);
    if (line == nil) { close(fd); return NO; }

    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    if (data == nil || data.length == 0) { close(fd); return NO; }

    const char *bytes = data.bytes;
    size_t total = data.length;
    size_t off = 0;
    while (off < total) {
        ssize_t w = write(fd, bytes + off, total - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return NO;
        }
        off += (size_t)w;
    }
    close(fd);
    return YES;
}

/* Build-time master switch for the INFORMATIONAL execute: echo, chosen by
 * -DSW_EXEC_DISPLAY (services.sudowhat.execDisplay in the nix module;
 * SUDOWHAT_EXEC_DISPLAY in the Makefile). Same fail-closed token machinery as
 * the other knobs in this file, in its own SW_ED_ namespace -- SW_EC_ belongs
 * to execConfirm and SW_ACOL_ to echoColor.
 *
 *   on  - (default) every informational emit site prints: the root bypass (the
 *         solo line), the non-console step-aside last-look, the
 *         policy-deference skip, and the console biometric pre-sheet line.
 *   off - none of them print. The bundle still loads, still verifies, still
 *         gates exactly as before -- it just shows nothing. Same spirit as the
 *         audit bundle's auditDisplay = off.
 *
 * NAMING. execDisplay pairs with auditDisplay: the two DISPLAY switches, one
 * per line family -- the audit bundle's pre-auth block, this bundle's execute:
 * line. The echo* family (echoColor) names colour instead, i.e. how the two
 * command VALUES are rendered once they are shown. Presence and styling are
 * deliberately separate names because they are separate decisions.
 *
 * PRECEDENCE over execConfirm, the one subtlety. This knob silences the
 * informational echo only. With execConfirm = on, the confirm ceremony on the
 * step-aside path STILL prints the resolved line before its `run? [y/N]`: a
 * y/N about a command the plugin refuses to show would be empty ceremony. That
 * is the same principle sw_step_aside_allow already applies to a missing
 * command key, where it fails closed instead of asking about nothing --
 * extended here from "cannot show" to "configured not to show". Mechanically,
 * the confirm branch calls write_exec_line_to_tty directly, below this gate,
 * while every informational site goes through emit_exec_line, which carries
 * it. An admin who wants neither the line nor the question turns execConfirm
 * off as well; execDisplay = off alone means "do not narrate", not "ask me
 * blind".
 *
 * The runtime gates are untouched in both modes: /dev/tty only, no stderr
 * fallback, and nothing at all without a controlling terminal.
 *
 * An unknown token yields an undefined SW_ED_<name> and fails the compile --
 * the intended fail-closed result for a raw -D that bypasses the Makefile's
 * validation. */
#ifndef SW_EXEC_DISPLAY
#define SW_EXEC_DISPLAY on
#endif
#define SW_ED_off      0
#define SW_ED_on       1
#define SW_ED_CAT(x)   SW_ED_##x
#define SW_ED_SEL(x)   SW_ED_CAT(x)
enum { sw_exec_display_mode = SW_ED_SEL(SW_EXEC_DISPLAY) };

/* Emit the resolved command line to the controlling terminal, or nowhere.
 *
 * This is the INFORMATIONAL entry point, and the one place the execDisplay
 * build token is consulted (see above): with the knob off it returns before
 * opening anything, so all four informational sites fall silent from a single
 * seam rather than each carrying a copy of the condition. The confirm ceremony
 * deliberately does not come through here.
 *
 * Called on every ALLOW path (root bypass, non-console step-aside, policy
 * deference, and -- pre-decision -- the console biometric path), which is the
 * point: a predictable ceremony beats a clever conditional, and a line that is
 * "only sometimes present" would itself need explaining. The knob does not
 * reintroduce that unpredictability -- it is one build-wide answer, the same on
 * every path. With no controlling terminal there is nowhere to print, so
 * nothing happens and behaviour is otherwise unchanged; no invocation can newly
 * block on this.
 *
 * A NULL path (sudo did not give us command_info["command"]) is a silent skip
 * rather than an error: this is a display, and the console path's own fatal
 * check on that key is still where it always was. Note that the confirm gate in
 * sw_step_aside_allow does NOT share that tolerance -- it fails closed, because
 * asking a human to approve a command it cannot show them would be theatre.
 *
 * layout is the caller's, not a guess: only the emit site knows whether its
 * line has siblings on the terminal (see sw_exec_layout). Every site here
 * passes SW_EXEC_GROUPED except the root bypass, which is provably alone. */
static void emit_exec_line(const char *ttyPath, const char *path,
                           char * const run_argv[], sw_exec_layout layout,
                           BOOL colorAllowed) {
    if (sw_exec_display_mode != SW_ED_on) return;
    if (path == NULL) return;
    write_exec_line_to_tty(ttyPath, path, run_argv, layout, colorAllowed);
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

/* Build-time master switch for EXEC CONFIRM, chosen by -DSW_EXEC_CONFIRM
 * (services.sudowhat.execConfirm in the nix module; SUDOWHAT_EXEC_CONFIRM in the
 * Makefile). Same fail-closed token machinery as the knobs above: a bare token
 * names a fixed mode baked into the signed bundle, never a runtime file.
 *
 *   off - (default) the terminal-password path prints the execute: line and
 *         allows. A last-look, not a decision.
 *   on  - the terminal-password path prints the execute: line and then asks one
 *         `run? [y/N]` on the tty via sudo's conversation API, so the decision
 *         completes AFTER the resolved path is visible -- the same guarantee
 *         biometric mode gives, split into authenticate-then-confirm.
 *
 * AUTHENTICATE-then-confirm, literally: the question is asked only when sudo
 * actually ran the PAM auth stack for THIS invocation, i.e. when a human just
 * presented a factor. A caller sudoers waived authentication for (NOPASSWD,
 * `Defaults !authenticate`, or a live timestamp cache) is never asked, terminal
 * or not -- re-gating what sudoers explicitly chose not to gate would contradict
 * the same deference principle step (3.5) applies on the console path. Detection
 * reuses that same in-process pam_sudowhat marker; see sw_confirm_decision.
 *
 * WHY ONLY THAT ONE PATH (docs/design-resolved-exec.md). The asymmetry this
 * closes is specific to terminal-password mode: sudo resolves the command inside
 * the policy step that also collects the password, and no plugin hook exists
 * between resolution and auth, so a resolved pre-PASSWORD display is impossible
 * there. The biometric path has no such problem -- the sheet IS the decision,
 * this plugin raises it, and the execute: line already lands before it. The root
 * bypass and the policy-deference path are excluded by the spec for the same
 * reason each exists: neither is a moment where sudowhat gets to decide.
 *
 * MODE LANDSCAPE. "Terminal-password mode" is today exactly the non-console
 * step-aside: sudo's own PAM factor ran on the caller's own terminal, and this
 * plugin steps aside afterwards. A future CONSOLE terminal mode (open decision 1
 * in docs/design-terminal-mode.md) would be the second member of that family and
 * should share this same gate rather than grow its own.
 *
 * No password ever touches plugin code here: sudo's PAM auth has already
 * succeeded by the time this runs, and the only thing asked for is a y/N.
 *
 * An unknown token yields an undefined SW_EC_<name> and fails the compile. */
#ifndef SW_EXEC_CONFIRM
#define SW_EXEC_CONFIRM off
#endif
#define SW_EC_off      0
#define SW_EC_on       1
#define SW_EC_CAT(x)   SW_EC_##x
#define SW_EC_SEL(x)   SW_EC_CAT(x)
enum { sw_exec_confirm_mode = SW_EC_SEL(SW_EXEC_CONFIRM) };

/* Pure decision: does the confirm prompt run for this invocation? All four
 * inputs explicit so every branch is unit-testable, exactly like
 * sw_defer_decision:
 *   knob off                  -> NO   (the default; plain last-look, then allow)
 *   no controlling terminal   -> NO   (nowhere to ask, and nobody to answer --
 *                                      so a piped or automated invocation
 *                                      behaves IDENTICALLY with the knob on or
 *                                      off, and can never newly block)
 *   marker present            -> YES  (sudo ran the PAM auth stack: a human just
 *                                      authenticated, so ask them to confirm.
 *                                      This is the knob's whole meaning)
 *   integrity line not wired  -> YES  (an absent marker can't be trusted to mean
 *                                      "waived" if pam_sudowhat may be unwired,
 *                                      so ask rather than skip)
 *   otherwise                 -> NO   (marker absent, chain intact => sudoers
 *                                      waived authentication for this
 *                                      invocation -- NOPASSWD, !authenticate, or
 *                                      a live timestamp cache. Print the
 *                                      execute: line and allow, exactly as the
 *                                      knob-off branch does; do not re-gate what
 *                                      sudoers chose not to gate)
 *
 * The last two rows are the whole point of the marker being read here at all:
 * without them the knob asked every non-console caller on a live terminal,
 * NOPASSWD ones included, which contradicts step (3.5)'s deference principle on
 * the console path.
 *
 * FAIL DIRECTION, and note it is the OPPOSITE of sw_defer_decision's: there,
 * uncertainty returns NO, meaning "prompt for Touch ID"; here, uncertainty
 * returns YES, meaning "ask the y/N". Both fail TOWARD the gate -- the shared
 * rule is "when in doubt, put the question to the human", and the two functions
 * only differ in which boolean expresses that.
 *
 * Neither outcome here is dangerous in the sw_defer_decision sense: NO lands on
 * today's behaviour (sudo has already authenticated the caller and sudoers has
 * already authorized them), and YES only adds a question. The marker's
 * unforgeable direction (absence cannot be faked -- see sw_defer_decision) still
 * matters, though: it is exactly what keeps a caller from suppressing the
 * question after a real authentication. */
static BOOL sw_confirm_decision(BOOL confirmOn, BOOL haveTty,
                                BOOL markerPresent, BOOL integrityInstalled) {
    if (!confirmOn)          return NO;
    if (!haveTty)            return NO;
    if (markerPresent)       return YES;
    if (!integrityInstalled) return YES;
    return NO;
}

/* Classify the answer to `run? [y/N]`. Accepts only an affirmative: "y" or
 * "yes", any case, with surrounding whitespace (including the newline a
 * conversation implementation may leave on) trimmed. Everything else -- "n",
 * empty, garbage, NULL -- is a decline, which is the whole point of a [y/N]
 * default: a stray Enter must never approve. Pure, so the classification is
 * unit-testable without a tty. */
static BOOL sw_confirm_answer_is_yes(const char *reply) {
    if (reply == NULL) return NO;

    const char *p = reply;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    const char *end = p + strlen(p);
    while (end > p && (end[-1] == ' ' || end[-1] == '\t'
                       || end[-1] == '\r' || end[-1] == '\n')) end--;

    size_t len = (size_t)(end - p);
    if (len == 1) return (p[0] == 'y' || p[0] == 'Y');
    if (len == 3) {
        return (p[0] == 'y' || p[0] == 'Y')
            && (p[1] == 'e' || p[1] == 'E')
            && (p[2] == 's' || p[2] == 'S');
    }
    return NO;
}

/* Is there a controlling terminal to print on and ask through? Opened and
 * closed immediately -- the answer, not the fd, is what the gate needs, and the
 * two writers below each open their own. Same flags as every other /dev/tty open
 * in this file: O_NOCTTY never acquires a controlling terminal as a side effect,
 * O_CLOEXEC never leaks into the execed target. isatty() is checked because a
 * `/dev/tty` that is somehow a regular file is not somebody who can answer. */
static BOOL sw_have_controlling_tty(const char *ttyPath) {
    int fd = open(ttyPath, O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) return NO;
    BOOL yes = isatty(fd) ? YES : NO;
    close(fd);
    return yes;
}

/* Ask the one question, through sudo's conversation API (the same channel sudo
 * uses for its own prompts, so it reaches the caller's terminal however sudo has
 * wired it). SUDO_CONV_PROMPT_ECHO_ON: the answer is a y/N, not a secret, and
 * the human needs to see what they typed. The "sudowhat: " prefix is the same
 * provenance marker every other line of ours carries -- this question lands in
 * the middle of somebody else's output and has to say who is asking.
 *
 * The conversation contract puts the reply buffer in the caller's hands, so it
 * is freed here. Returns NO on a NULL conversation pointer or a conversation
 * error as well as on a real decline: the caller treats all three the same way
 * (a quiet abort), because a question that could not be asked has not been
 * answered. */
static BOOL sw_ask_run_confirm(void) {
    if (g_conversation == NULL) return NO;

    struct sudo_conv_message msg = {
        .msg_type = SUDO_CONV_PROMPT_ECHO_ON,
        .timeout  = 0,
        .msg      = "sudowhat: run? [y/N] ",
    };
    struct sudo_conv_reply reply = { .reply = NULL };

    int rc = g_conversation(1, &msg, &reply, NULL);
    BOOL yes = (rc == 0) && sw_confirm_answer_is_yes(reply.reply);
    if (reply.reply != NULL) {
        free(reply.reply);
        reply.reply = NULL;
    }
    return yes;
}

/* The non-console step-aside, with its display and its optional confirm. Split
 * out of sudowhat_check so the TOCTOU pin, the prompt and the re-stat read as
 * one unit. Returns the plugin verdict: 1 = allow, 0 = deny, -1 = plugin error.
 *
 * Knob off (the default) is the whole of this function's first branch: print
 * execute: and allow. Reaching this path at all means sudo's PAM auth already
 * succeeded on the caller's own terminal -- OR that sudoers waived it -- so the
 * line is a last-look, not a decision: the honest maximum in a mode where the
 * password is collected inside the policy step that resolves the command.
 *
 * markerPresent is the stashed pam_sudowhat auth marker, read once per check()
 * up at (1d): YES means sudo really ran the PAM auth stack for this invocation.
 * It is what separates the two callers this path sees -- a human who just typed
 * a password, and a NOPASSWD rule -- and only the first is asked anything (see
 * sw_confirm_decision). The integrity-line read stays LAZY, exactly as on the
 * console deference path: it is consulted only when it can change the answer,
 * i.e. knob on AND a tty AND the marker absent.
 *
 * Knob on (for a caller who authenticated) adds the decision back. Then a TOCTOU
 * pin is required and it is NOT optional: the confirm introduces an
 * authorization DELAY on a path that previously had none, which opens the same
 * binary-swap window the console biometric path already guards against with its
 * pre-prompt open()+fstat and post-auth re-stat. The pin is taken BEFORE the
 * human is asked anything, so what they approve is the file that was there when
 * the question was posed. */
static int sw_step_aside_allow(const char *commandC, char * const run_argv[],
                               BOOL markerPresent, const char **errstr) {
    BOOL confirmOn = (sw_exec_confirm_mode == SW_EC_on);
    BOOL haveTty = confirmOn ? sw_have_controlling_tty("/dev/tty") : NO;
    BOOL integrityInstalled =
        (confirmOn && haveTty && !markerPresent)
            ? sudowhat_pam_integrity_line_installed() : NO;

    if (!sw_confirm_decision(confirmOn, haveTty, markerPresent,
                             integrityInstalled)) {
        emit_exec_line("/dev/tty", commandC, run_argv, SW_EXEC_GROUPED,
                       sw_color_allowed());
        return 1;
    }

    /* Fail closed on a missing command key here, unlike the display helper's
     * silent skip: asking a human to confirm a command we cannot show them
     * would be a ceremony with nothing in it. */
    if (commandC == NULL) {
        set_errstr(errstr, "sudowhat: missing 'command' in command_info; "
                           "cannot confirm what would run");
        return 0;
    }

    /* Pre-prompt pin -- same pattern, same reasons, as the console path's (3a).
     * O_CLOEXEC so the fd does not leak into the execed program. */
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

    /* Straight to the writer, deliberately below emit_exec_line's execDisplay
     * gate (see there): this line is not narration, it is the subject of the
     * question asked two statements down. execDisplay = off silences the four
     * informational echoes; it must not turn this one into a blind y/N. */
    write_exec_line_to_tty("/dev/tty", commandC, run_argv, SW_EXEC_GROUPED,
                           sw_color_allowed());

    /* Decline, an empty answer, or a conversation that could not run at all:
     * quiet abort. Terse on purpose -- nothing is wedged, nothing is cached,
     * and the caller can simply run the command again. */
    if (!sw_ask_run_confirm()) {
        close(preFd);
        set_errstr(errstr, "sudowhat: run not confirmed");
        return 0;
    }

    /* Post-answer re-stat: if the file at the path no longer matches the fd we
     * pinned, the binary was swapped while the human was reading and answering. */
    struct stat postSt;
    if (stat(commandC, &postSt) != 0) {
        int saved = errno;
        close(preFd);
        set_errstr(errstr, "sudowhat: post-confirm stat(%s) failed: %s",
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
    (void)settings;
    (void)submit_optind; (void)submit_argv;
    (void)plugin_options;

    g_plugin_printf = plugin_printf;
    /* check() has no conversation parameter, so stash it here for the
     * exec_confirm prompt (sw_step_aside_allow). Captured unconditionally: the
     * knob is a compile-time constant, and a captured pointer nobody calls costs
     * nothing. */
    g_conversation = conversation;

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
    g_conversation = NULL;
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
    return [SudoWhatSignatureVerifier verifyPath:@SUDOWHAT_AUDIT_PATH
                                       identifier:@SUDOWHAT_AUDIT_IDENT
                                            error:error];
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
        if (![SudoWhatSignatureVerifier verifyPath:@SUDOWHAT_PAM_PATH
                                        identifier:@SUDOWHAT_PAM_IDENT
                                             error:&sigErr]) {
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

        /* (1c) Capture the RESOLVED command, best-effort, before any allow path
         * can return. sudo has finished resolving by the time check() runs, so
         * command_info["command"] is the absolute path it will execve() -- the
         * one thing the pre-auth terminal block (audit plugin, input:) could not
         * know. Hoisted this high so every allow below can display it; a NULL
         * here is not handled here, because the two consumers want opposite
         * things from it: emit_exec_line skips silently (a display), while (3)'s
         * long-standing fatal check stays exactly where it always was, so the
         * root bypass does not newly turn a missing key into an error. */
        const char *commandC = find_kv(command_info, "command");

        /* (1d) Read the pam_sudowhat auth marker, ONCE, before any caller
         * classification -- two consumers need it now and they sit on opposite
         * sides of that fork: the non-console step-aside's confirm gate (see
         * sw_confirm_decision) and the console path's policy deference at (3.5).
         * Reading it in one place is what keeps them from disagreeing, and is
         * the only way the non-console branch can see it at all: (3.5) runs
         * AFTER that branch has already returned.
         *
         * Read and immediately clear (this is the hygiene rationale that used to
         * live at (3.5), moved here with the read): no stale value can linger
         * into a later consumer. sudo builds the command's environment
         * separately, so this never reaches the execed program regardless. The
         * clear now also runs on the root-bypass and deny paths, which
         * previously returned before reaching it -- strictly more hygienic, and
         * behaviourally invisible, since neither path consults the marker.
         *
         * PRESENT means sudo ran the PAM auth stack for this invocation, i.e.
         * sudoers required authentication. ABSENT means it did not: a NOPASSWD
         * rule, `Defaults !authenticate`, or a valid timestamp cache. Absence
         * cannot be forged -- pam_sudowhat's setenv() runs in-process, after the
         * caller's environment was captured, and overwrites any pre-set value --
         * which is what makes both consumers safe to key on it. */
        const char *authMarker = getenv(SUDOWHAT_AUTH_MARKER_ENV);
        BOOL markerPresent = (authMarker != NULL);
        unsetenv(SUDOWHAT_AUTH_MARKER_ENV);

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
            /* Still show what will run. Root contexts usually have no
             * controlling terminal, in which case this is a no-op -- but when
             * one IS present (a root shell in a terminal), the ceremony should
             * look the same as everywhere else. The audit plugin exempts root
             * from its block, so this is the one line root gets; that is fine,
             * because root is not being gated here, only informed.
             *
             * SW_EXEC_SOLO for exactly that reason: no input: block above it
             * (audit exempts uid 0) and no verify: line (biometric is
             * console-only, and this branch returns before it), so there is
             * nothing to align with and the label keeps a single space. This is
             * the ONE site where that holds -- see sw_exec_layout. */
            emit_exec_line("/dev/tty", commandC, run_argv, SW_EXEC_SOLO,
                           sw_color_allowed());
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
                /* Terminal-password mode. sudo already collected the factor,
                 * inside the policy step that also resolved the command, so the
                 * execute: line lands after auth and before execve -- a
                 * last-look, not a preview. With execConfirm on, the decision
                 * moves back after the display -- but only for a caller sudo
                 * actually authenticated, which is what the marker from (1d)
                 * tells it.
                 * See sw_step_aside_allow. */
                int verdict = sw_step_aside_allow(commandC, run_argv,
                                                  markerPresent, errstr);
                if (verdict != 1) return verdict;
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

        /* (3) Resolve command. commandC was captured back at (1c) so the allow
         * paths above could display it; the fatal check stays HERE, on the
         * console path, where a missing key really does mean there is nothing to
         * put on the sheet. */
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
         * The marker itself was read and cleared once at (1d), before the caller
         * classification, because the non-console step-aside needs it too and
         * returns long before this point; the read-and-immediately-clear hygiene
         * rationale moved there with it. This step just consumes the stashed
         * markerPresent -- same value, same one read per check(). The
         * integrity-line check runs only when it can matter (deference on AND
         * marker absent) and confirms an absent marker really means "the auth
         * stack did not run" rather than "pam_sudowhat is unwired" — otherwise
         * sw_defer_decision fails toward prompting. No TOCTOU pre-stat is needed
         * on this path: there is no authorization delay, hence no window to swap
         * the binary.
         *
         * timestamp interaction: with a non-zero timestamp_timeout a cached
         * credential also skips the auth stack, so a second in-window command on
         * the same tty is deferred and runs with no sheet — sudo's normal grace
         * after the first real factor on that tty. Set timestamp_timeout=0 (the
         * module default) for a sheet on every command. */
        BOOL deferenceOn = (sw_policy_deference_mode == SW_PD_on);
        BOOL integrityInstalled =
            (deferenceOn && !markerPresent)
                ? sudowhat_pam_integrity_line_installed() : NO;
        if (sw_defer_decision(deferenceOn, markerPresent, integrityInstalled)) {
            /* The command as typed was already shown on the controlling
             * terminal by the audit plugin (its open() runs before this check).
             * The RESOLVED line is this plugin's to echo, and a deferred run
             * gets it like every other allow path: sudoers waiving
             * authentication is a reason not to gate, not a reason to stop
             * disclosing. No prompt is added here -- the spec is explicit that
             * deference behaviour is otherwise unchanged, and execConfirm
             * deliberately does not reach this path. Record the skip and
             * allow. */
            emit_exec_line("/dev/tty", commandC, run_argv, SW_EXEC_GROUPED,
                           sw_color_allowed());
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

        /* Two lines, in this order, then the sheet.
         *
         * The verify code first: the one out-of-band signal binding the sheet to
         * the terminal. No fd redirect can hide it (emit_verify_code targets
         * /dev/tty).
         *
         * Then the resolved command. This is the moment the whole execute: design
         * exists for: the sheet IS the decision, this plugin raises it, and this
         * plugin controls the ordering -- so here, uniquely, the resolved path
         * reaches the human BEFORE they decide, not merely before exec. It also
         * makes the sheet's "(see terminal)" overflow referral truthful: when the
         * command is too long for the sheet, the terminal now holds the full
         * RESOLVED line, not just the as-typed one.
         *
         * Emitted before the seteuid drop, while EUID is still root -- the same
         * condition every other /dev/tty write in this file relies on -- and
         * before the LAContext call, which blocks until the human answers. */
        emit_verify_code("/dev/tty", nonceBuf, sw_color_allowed());
        emit_exec_line("/dev/tty", commandC, run_argv, SW_EXEC_GROUPED,
                       sw_color_allowed());

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
