/*
 * sudowhat audit plugin (sudo plugin API: SUDO_AUDIT_PLUGIN, type 3).
 *
 * The owner of the PRE-AUTH terminal block. sudo calls an audit plugin's open()
 * before any other plugin API function -- in particular before the policy
 * plugin's check_policy, where PAM collects the password — so this plugin prints
 *   user / directory / input [/ path]
 * to the controlling terminal FIRST, on every path: the local console (before
 * the approval plugin's verify code + Touch ID sheet) and the non-console / SSH
 * case (before sudo's native PAM `Password:`). That closes the gap where a
 * non-console sudo used to step aside silently, showing a bare `Password:` with
 * no command. See docs/design-terminal-mode.md.
 *
 * DISPLAY OWNERSHIP CARVE-OUT (docs/design-resolved-exec.md, section 3). This
 * plugin owns everything that exists BEFORE resolution: run as:, directory:,
 * input: -- the command as the user typed it, which is all sudo has produced at
 * this point -- and path:, the caller's PATH as handed to sudo, shown only when
 * the typed command is a bare name (the surface that steers how that name will
 * resolve; NOT a claim about the final resolution PATH, which sudoers
 * secure_path may override). The approval plugin (plugin/sudowhat_approval.m) owns
 * DECISION-ADJACENT display: verify:, the LAContext sheet, and the execute: line
 * carrying sudo's resolved command_info["command"] -- everything that exists only
 * after resolution. Both bundles render command lines through the same Rust
 * escape core, so the split cannot produce two spellings of one command; the
 * seam is commented on both sides, and if one moves, move both.
 *
 * This plugin NEVER handles the password and is NEVER a trust anchor: display is
 * disclosure, not authentication. Auth stays governed by sudo's native PAM and
 * the approval plugin. Accordingly it fails SOFT — any problem (no tty, missing
 * context, a tampered sibling bundle) means "show nothing", never "break sudo".
 * Integrity is enforced elsewhere: the approval plugin and pam_sudowhat fail
 * CLOSED if this bundle is present-but-tampered (the mutual-signature web), so a
 * swapped audit plugin that lies about the command cannot let sudo proceed.
 *
 * The untrusted-argv escaping/quoting -- and the colouring layered over it -- is
 * done in the Rust escape_core staticlib (memory-safe), not in C here: this file
 * is a thin ObjC shell doing the code-signature check and the /dev/tty glue.
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
 *   on  - (default) show user / directory / input [/ path] on the controlling
 *         terminal.
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

/* Build-time colour policy, chosen by -DSW_ECHO_COLOR (echoColor in the
 * nix module / Makefile).
 *
 *   on  - (default) highlight the command line. The input: value renders its
 *         ROUTINE tokens - program, flags, values alike - dim, with the
 *         escaped/anomalous spans (deceptive Unicode, control bytes, shell
 *         metacharacters, notable whitespace) at full strength on top: the
 *         pre-resolution line reads quiet under the resolved execute: line,
 *         and the anomalies are the only coloured thing on it. The approval
 *         bundle's execute: line keeps the full role palette (program dirname
 *         plain cyan, basename bold cyan, flags bold blue, values plain), so
 *         what sudo will actually run is the loud line.
 *   off - the command line renders plain.
 *
 * This knob governs the COMMAND VALUE only. The frame around it (the label
 * gutter, the bold labels, the directory and target-user emphasis) is governed
 * by the NO_COLOR / TERM / isatty gates alone, because it is our own fixed
 * chrome rather than a rendering of untrusted argv.
 *
 * The SAME token governs the approval bundle's execute: value, which is why
 * -DSW_ECHO_COLOR sits in the Makefile's global CFLAGS rather than in this
 * bundle's target-specific ones: input: and execute: are one display to a reader,
 * and silencing one of them alone would be arbitrary. That bundle carries its
 * own copy of this token machinery (plugin/sudowhat_approval.m, SW_ECHO_COLOR /
 * SW_ACOL_* / sw_echo_color_mode) because the two are separate Mach-O images
 * that never share a translation unit. If one moves, move both.
 *
 * The colouriser lives in escape_core (sw_full_command_line_colored_dim here,
 * sw_full_command_line_colored there), not in
 * PromptFormatter: that class has a fixed ObjC name that cannot be linked into
 * this second bundle without a duplicate-class collision. The two entry points
 * are two BASE palettes over one shared token walk, not two renderers, so the
 * two lines can never disagree about which tokens the command has or how a
 * token is spelled - any difference the reader sees is a real difference in the
 * command. Colour is layout only,
 * applied around the already-escaped, already-quoted tokens - strip the SGR and
 * the bytes are the plain line's exactly - so it can neither add nor hide
 * content. Runtime gates (NO_COLOR / TERM, then isatty) still apply on top, and
 * any failure falls back to the plain line. */
#ifndef SW_ECHO_COLOR
#define SW_ECHO_COLOR on
#endif
#define SW_ACOL_off        0
#define SW_ACOL_on         1
#define SW_ACOL_CAT(x)     SW_ACOL_##x
#define SW_ACOL_SEL(x)     SW_ACOL_CAT(x)
enum { sw_audit_color_mode = SW_ACOL_SEL(SW_ECHO_COLOR) };

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

/* Every escape_core command-line renderer shares one signature, so the caller
 * below can pick between them without duplicating the two-call sizing dance. */
typedef int (*sw_cmdline_fn)(const uint8_t *path, size_t path_len,
                             const uint8_t *const *argv,
                             const size_t *argv_lens, size_t argv_count,
                             uint8_t *out, size_t out_cap, size_t *needed);

/* Run one renderer with the two-call sizing protocol: probe for the length,
 * allocate, fill. Returns nil on allocation failure or a non-OK return, which is
 * what makes the colour->plain fallback below a plain nil check. */
static NSString *sw_audit_render(sw_cmdline_fn render,
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

/* Build the as-typed command line from submit_argv[submit_optind..] via the Rust
 * core. We pass argv[0] as the "path" so the argv0-dedup collapses it to a single
 * leading token — the command exactly as the user typed it, with every token
 * shell-quoted and control-char escaped. Returns nil when there is no command
 * word (nothing to display) or on allocation failure.
 *
 * When colour is on, the coloured renderer is tried first and the plain one is
 * the fallback: colour is layout over the same bytes, so degrading to plain
 * loses emphasis and nothing else. A display tool must never fail to "show
 * nothing". The two renderers are parameters (production passes the escape_core
 * pair) to keep that fallback isolated and testable, the same reason
 * sw_audit_write_tty takes its ttyPath. */
static NSString *sw_audit_command_line_with(sw_cmdline_fn colored,
                                            sw_cmdline_fn plain,
                                            char * const submit_argv[],
                                            int optind, BOOL color) {
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

    NSString *s = nil;
    if (color) s = sw_audit_render(colored, path, path_len, argv, lens, (size_t)n);
    if (s == nil) s = sw_audit_render(plain, path, path_len, argv, lens, (size_t)n);

    free(argv);
    free(lens);
    return s;
}

/* The input: line takes the DIM variant of the shared renderer: routine tokens
 * quiet, anomaly spans at full strength. The approval bundle's execute: line
 * takes the role-coloured variant of the same walk, so the resolved command is
 * the loud one and this pre-resolution line sits under it. The plain renderer
 * is the fallback for both. */
static NSString *sw_audit_command_line(char * const submit_argv[], int optind,
                                       BOOL color) {
    return sw_audit_command_line_with(sw_full_command_line_colored_dim,
                                      sw_full_command_line,
                                      submit_argv, optind, color);
}

/* Whether the typed command word is a BARE NAME: a token containing no '/' at
 * all. Only a bare name is looked up through PATH. An absolute path
 * (/bin/systemctl) and any relative path carrying a slash (./x, a/b) are used
 * as given and never consult PATH, so for those the caller's PATH decides
 * nothing and the path: row would be noise on the block. NULL or empty -> NO:
 * there is nothing to classify, and every doubt means no row. */
static BOOL sw_audit_is_bare_name(const char *cmd) {
    if (cmd == NULL || cmd[0] == '\0') return NO;
    return strchr(cmd, '/') == NULL;
}

/* The path: row's value, or nil when the row must not print.
 *
 * What the row discloses is the PATH ENVIRONMENT sudo was handed by the caller
 * -- the attacker-influenceable surface that decides how a bare command name
 * resolves. It is deliberately NOT a claim about the final resolution PATH:
 * sudoers secure_path may override it entirely, and the approval bundle's
 * execute: line still shows the resolved outcome. What this row buys is
 * PRE-GATE disclosure on the password path, where execute: cannot appear before
 * the password has already been spent.
 *
 * NO plugin-side resolution, ever: this shows the PATH string as handed over.
 * It never walks the list, never stats an entry, never claims which entry would
 * win. That invariant is settled (docs/design-resolved-exec.md, "Not in
 * scope"); a resolver here would be a second, disagreeing answer to a question
 * sudo already answers on the execute: line.
 *
 * nil (no row) when: there is no command word, the command word is not a bare
 * name, PATH is absent or empty (nothing to disclose), or the escape allocation
 * failed. Fail-soft like everything else here -- any doubt shows no row, never
 * a broken block.
 *
 * The value is escaped through the same one core as run as: and directory:
 * (escape_core's sw_escape_control), so a PATH entry carrying control bytes or
 * deceptive Unicode reaches the terminal as text, never as bytes. */
static NSString *sw_audit_path_row_value(char * const submit_argv[],
                                         int submit_optind,
                                         char * const submit_envp[]) {
    if (submit_argv == NULL || submit_optind < 0) return nil;
    if (!sw_audit_is_bare_name(submit_argv[submit_optind])) return nil;

    const char *path = find_kv(submit_envp, "PATH");
    if (path == NULL || path[0] == '\0') return nil;

    NSString *value = sw_audit_escape(path);
    if (value.length == 0) return nil;   /* alloc failure -> no row */
    return value;
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
 * no control byte here came from what the user typed: the only escape sequences
 * present are our own fixed SGR palette, added around the escaped tokens. */
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

/* The label gutter. Every value on the block starts in the same column, so the
 * rows read as a table instead of as three sentences, and a long directory can
 * never shove the command value out of line. Width is the longest label
 * ("directory:", 10 characters) plus two spaces -- the house minimum for a
 * gutter -- measured from the first byte AFTER the "sudowhat: " prefix. That
 * prefix stays on every row rather than being hoisted into a header: the block
 * lands in the middle of somebody else's output, so each line has to carry its
 * own provenance. The approval plugin's verify: and execute: lines
 * (SW_VERIFY_PREFIX, SW_EXEC_PREFIX) are further fields in the same gutter, so
 * six labels across two bundles -- run as:, directory:, input:, path: here,
 * verify: and execute: there -- share this one width; keep them in step. */
#define SW_AUDIT_GUTTER 12

/* One frame row: prefix, the bolded label padded out to the gutter, the value.
 * The padding sits OUTSIDE the emphasis -- bold spaces render as nothing, and
 * keeping them plain means the only bytes wearing SGR 1 are the label itself.
 * The label is our own fixed literal; the value is already escape_core-escaped
 * (and, when it is the command, already coloured). */
static NSString *sw_audit_row(NSString *label, NSString *value, BOOL color) {
    NSUInteger pad = (label.length < SW_AUDIT_GUTTER)
        ? SW_AUDIT_GUTTER - label.length : 1;
    NSString *gap = [@"" stringByPaddingToLength:pad withString:@" "
                                     startingAtIndex:0];
    if (color) {
        return [NSString stringWithFormat:@"sudowhat: \033[1m%@\033[0m%@%@\n",
                                          label, gap, value];
    }
    return [NSString stringWithFormat:@"sudowhat: %@%@%@\n", label, gap, value];
}

/* The cwd, coloured the way escape_core renders a program path: the directory
 * part plain cyan, the last component bold cyan -- the one word the reader is
 * actually checking. Done here rather than by routing the cwd through
 * sw_full_command_line_colored, which would give the same split for free but
 * would also SHELL-QUOTE the token: a directory with a space in it would then
 * gain quotes the uncoloured row does not have, and the block would stop being
 * the same bytes with and without colour. It would also drag the anomaly
 * palette onto a value the frame is supposed to keep to bold/plain/yellow plus
 * this one cyan pair.
 *
 * The input is already escape_control-escaped, so it holds no control byte and
 * a '/' can only be a literal '/'. A trailing slash (or no slash at all) leaves
 * one half empty; that half is simply not emitted, so no empty SGR span is
 * ever written. */
static NSString *sw_audit_color_dir(NSString *dir) {
    NSRange slash = [dir rangeOfString:@"/" options:NSBackwardsSearch];
    if (slash.location == NSNotFound) {
        return [NSString stringWithFormat:@"\033[1;36m%@\033[0m", dir];
    }
    NSUInteger cut = slash.location + slash.length;
    NSString *head = [dir substringToIndex:cut];
    NSString *base = [dir substringFromIndex:cut];
    if (base.length == 0) {
        return [NSString stringWithFormat:@"\033[36m%@\033[0m", head];
    }
    return [NSString stringWithFormat:@"\033[36m%@\033[0m\033[1;36m%@\033[0m",
                                      head, base];
}

/* Attention colour on an unexpected target. root is what `sudo` means with no
 * -u, so it is the expected value and earns no emphasis; anything else is the
 * case worth catching an eye. Plain yellow, not bold: it says "look" without
 * competing with the bold labels, and it stays clear of the anomaly palette
 * escape_core owns (1;31m, 1;35m, 1;36m, 100m). Yellow means exactly this one
 * thing anywhere in the block. */
static NSString *sw_audit_color_user(NSString *user) {
    if ([user isEqualToString:@"root"]) return user;
    return [NSString stringWithFormat:@"\033[33m%@\033[0m", user];
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
                                       identifier:@SUDOWHAT_PLUGIN_IDENT
                                            error:&sigErr]) {
            syslog(LOG_AUTHPRIV | LOG_WARNING,
                   "sudowhat_audit: approval plugin signature invalid; "
                   "suppressing terminal display");
            return 1;
        }
        if (![SudoWhatAuditSigVerifier verifyPath:@SUDOWHAT_PAM_PATH
                                       identifier:@SUDOWHAT_PAM_IDENT
                                            error:&sigErr]) {
            syslog(LOG_AUTHPRIV | LOG_WARNING,
                   "sudowhat_audit: pam_sudowhat signature invalid; "
                   "suppressing terminal display");
            return 1;
        }

        /* Whether ANSI emphasis is permitted at all. Resolved before the command
         * line because the command line is the one value that is coloured by
         * role, not merely emphasised: build knob AND the env opt-outs, with
         * sw_audit_write_tty's isatty() as the final gate. */
        BOOL color = sw_audit_color_allowed(submit_envp);
        BOOL colorCommand = color && (sw_audit_color_mode == SW_ACOL_on);

        /* The command as typed -- the star of the display, and the reason its
         * label is `input:` rather than `command:`: at audit open() sudo has not
         * resolved anything, so this line can only ever state what the invoking
         * user asked for -- the plugin's input, before resolution. The label
         * carries that epistemic status honestly; the approval plugin's
         * `execute:` states what sudo will actually run, so the pair reads as
         * in/out, and the juxtaposition of the two IS the anomaly display (a
         * shadowed bare name shows up as input/execute divergence, with no
         * heuristic needed).
         *
         * No command word -> the invocation is not something to preview (e.g.
         * `sudo -v`); show nothing. Highlighted by role on one logical line (the
         * terminal soft-wraps it); a colouriser failure degrades to the same
         * line in plain. */
        NSString *commandLine = sw_audit_command_line(submit_argv, submit_optind,
                                                      colorCommand);
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

        /* Assemble the block: user / directory / input [/ path]. Labels are
         * bolded purely for readability (our own fixed bytes, never user input
         * -- the values are escape_core-escaped), and the values carry the
         * emphasis their meaning earns: the target user yellow when it is not
         * root, the cwd split dirname/basename like a program path, and the
         * caller's PATH plain. Same env gate as the approval plugin's verify code
         * (resolved above), so a redirect or a non-tty renders the identical
         * block with no SGR at all.
         *
         * No leading blank line. The block lands mid-stream in output sudowhat
         * does not own either side of, and it cannot know what preceded it;
         * spacing belongs to whoever invoked sudo. */
        NSString *userValue = color ? sw_audit_color_user(userLine) : userLine;

        NSMutableString *block = [NSMutableString string];
        [block appendString:sw_audit_row(@"run as:", userValue, color)];
        if (dirLine.length > 0) {
            NSString *dirValue = color ? sw_audit_color_dir(dirLine) : dirLine;
            [block appendString:sw_audit_row(@"directory:", dirValue, color)];
        }
        [block appendString:sw_audit_row(@"input:", commandLine, color)];

        /* path: sits directly after input: because it QUALIFIES that row: it is
         * the environment that decides how the bare name just shown will
         * resolve. Value plain -- the same treatment run as: and directory: get by
         * default -- because it earns no role colour: it is one opaque string,
         * not a token walk, and the yellow/cyan the frame spends elsewhere
         * already mean specific things.
         *
         * MODE SCOPING, and why there is none. Ideally this row would print
         * only where execute: cannot appear before the gate -- the password
         * path. It cannot: the audit bundle deliberately carries no session
         * classification (no SessionGuard here; a third per-target ObjC class
         * would be needed, even console sessions can land on the password path,
         * and the bundle cannot see the sudo_local variant either), so at open()
         * the plugin cannot know whether this invocation will show execute:
         * before the gate. The sanctioned fallback is to print whenever the
         * condition above holds, accepting mild redundancy on biometric
         * consoles, where execute: also appears pre-sheet. A row that is
         * occasionally redundant beats a row that is occasionally missing from
         * the one path that needs it. */
        NSString *pathValue = sw_audit_path_row_value(submit_argv,
                                                      submit_optind,
                                                      submit_envp);
        if (pathValue != nil) {
            [block appendString:sw_audit_row(@"path:", pathValue, color)];
        }

        sw_audit_write_tty("/dev/tty", block);
        return 1;
    }
}

/* Minimal tail. close() gets the exit disposition (nothing to clean up — open()
 * holds no persistent state). accept/reject/error return 1 (success) so sudo is
 * satisfied.
 *
 * accept() was once earmarked for a resolved-path last-look. That last-look now
 * exists as the approval plugin's execute: line, and it lives THERE by design, not
 * by convenience: accept() fires after the decision on every path, whereas the
 * approval plugin's check() runs before it raises the sheet -- which is what lets
 * the biometric mode show the resolved path PRE-decision rather than merely
 * pre-exec (docs/design-resolved-exec.md). The members stay wired rather than
 * NULL so the plugin presents a complete audit interface to sudo. The optional
 * struct tail (show_version, register_hooks, deregister_hooks, event_alloc)
 * stays NULL. */
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
