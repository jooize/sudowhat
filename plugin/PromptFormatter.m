#import "PromptFormatter.h"

#include "escape_core.h"

/* Every value on the sheet is rendered by escape_core, from the raw bytes, by
 * the same functions the terminal's execute: line uses. Its output is valid
 * UTF-8 for any input (a byte that does not decode becomes the text \xHH), so
 * a nil from these helpers is an allocation failure, never a property of the
 * value, and the caller fails closed on it. */

/* Decode one escape_core result. NSString's UTF-8 decode cannot fail on
 * escape_core output, which is why it is safe here and nowhere upstream. */
static NSString *sw_pf_string(const uint8_t *buf, size_t len) {
    return [[NSString alloc] initWithBytes:buf length:len
                                  encoding:NSUTF8StringEncoding];
}

/* A value escaped by the untrusted-text rules (sw_escape_control), with the
 * two-call sizing protocol: probe for the length, allocate, fill. */
static NSString *sw_pf_escape(const char *s) {
    size_t inlen = strlen(s), needed = 0;
    sw_escape_control((const uint8_t *)s, inlen, NULL, 0, &needed);
    uint8_t *buf = malloc(needed + 1);
    if (buf == NULL) return nil;
    size_t got = 0;
    NSString *out = nil;
    if (sw_escape_control((const uint8_t *)s, inlen, buf, needed + 1, &got)
        == SW_ESCAPE_OK) {
        out = sw_pf_string(buf, got);
    }
    free(buf);
    return out;
}

/* The command line (sw_full_command_line): the quoted path, then argv minus
 * argv[0] when it duplicates the path or its basename. The terminal's plain
 * execute: value, byte for byte. */
static NSString *sw_pf_command_line(const char *path, char * const argv[]) {
    size_t n = 0;
    if (argv != NULL) {
        while (argv[n] != NULL) n++;
    }
    const uint8_t **toks = calloc(n ? n : 1, sizeof(*toks));
    size_t *lens = calloc(n ? n : 1, sizeof(*lens));
    if (toks == NULL || lens == NULL) { free(toks); free(lens); return nil; }
    for (size_t i = 0; i < n; i++) {
        toks[i] = (const uint8_t *)argv[i];
        lens[i] = strlen(argv[i]);
    }
    size_t plen = strlen(path), needed = 0;
    sw_full_command_line((const uint8_t *)path, plen, toks, lens, n,
                         NULL, 0, &needed);
    uint8_t *buf = malloc(needed + 1);
    NSString *out = nil;
    size_t got = 0;
    if (buf != NULL
        && sw_full_command_line((const uint8_t *)path, plen, toks, lens, n,
                                buf, needed + 1, &got) == SW_ESCAPE_OK) {
        out = sw_pf_string(buf, got);
    }
    free(buf);
    free(toks);
    free(lens);
    return out;
}

@implementation SudoWhatPromptFormatter

+ (NSString *)formatWithCommandPath:(const char *)path
                          runasUser:(const char *)user
                                cwd:(const char *)cwd
                         verifyCode:(NSString *)verifyCode
                               argv:(char * const *)argv
                              style:(SWPromptStyle)style {
    return [self formatWithCommandPath:path runasUser:user cwd:cwd
                            verifyCode:verifyCode argv:argv style:style
                              overflow:NULL];
}

+ (NSString *)formatWithCommandPath:(const char *)path
                          runasUser:(const char *)user
                                cwd:(const char *)cwd
                         verifyCode:(NSString *)verifyCode
                               argv:(char * const *)argv
                              style:(SWPromptStyle)style
                       wasTruncated:(BOOL *)outTruncated {
    SWPromptOverflow ov = { NO, NO, NO };
    NSString *out = [self formatWithCommandPath:path runasUser:user cwd:cwd
                                     verifyCode:verifyCode argv:argv style:style
                                       overflow:&ov];
    if (outTruncated) *outTruncated = (ov.user || ov.path || ov.command);
    return out;
}

+ (NSString *)formatWithCommandPath:(const char *)path
                          runasUser:(const char *)user
                                cwd:(const char *)cwd
                         verifyCode:(NSString *)verifyCode
                               argv:(char * const *)argv
                              style:(SWPromptStyle)style
                           overflow:(SWPromptOverflow *)outOverflow {
    /* LA caps the localizedReason at ~510 chars total — anything past the cap
     * is a hard NSString cut, including newlines and any content meant for a
     * later line. We render within a conservative 480-char budget (~30 chars
     * of margin) so the closing reminder is never the thing clipped. Every
     * component below is either a fixed string or a per-item value bounded by a
     * cap, so this total holds structurally for any input.
     *
     * CAVEAT (~80% confidence, untested across locales): the ~510 was measured
     * with the English system prefix. Our strings are English-only, so OUR
     * length is locale-invariant; but if macOS caps the TOTAL sheet text
     * (system prefix + our reason) a longer localized prefix could eat this
     * budget. To confirm: render a near-480-char prompt under a long-prefix
     * locale and check the closing line survives. If not, lower kMaxTotal. */
    const NSUInteger kMaxTotal = 480;
    const NSUInteger kMaxUserDisplay   = 64;
    const NSUInteger kMaxCwdDisplay     = 160;
    const NSUInteger kMaxVerifyDisplay = 32;

    /* Opening line. macOS frames the biometric sheet as `"sudo" is trying to
     * <this>`, so it is a lowercase continuation, and the full stop lives
     * here, at the top. */
    NSString *header = @"run a command.";

    /* Verify code. The plugin has already echoed the same value to the user's
     * controlling terminal; they compare the two before approving. Capped
     * (plain cut, no marker) purely so the budget holds against a malformed
     * code — the production nonce is 3 chars. */
    if (path == NULL) return nil;

    NSString *verifyLine;
    if (verifyCode.length > 0) {
        NSString *v = sw_pf_escape(verifyCode.UTF8String);
        if (v == nil) return nil;
        if (v.length > kMaxVerifyDisplay) v = [v substringToIndex:kMaxVerifyDisplay];
        verifyLine = [NSString stringWithFormat:@"Verify Code: %@", v];
    } else {
        verifyLine = @"Verify Code: unavailable";
    }

    /* Item values, escaped (and the command shell-quoted) by escape_core from
     * the raw bytes. Each is shown whole or, if over budget, replaced by the
     * marker — never partially truncated. A displayed cwd always starts with
     * '/', so it can never collide with the parenthesised marker; the command
     * region quotes any token with unsafe bytes, so a literal "(see terminal)"
     * argument renders quoted and stays distinguishable. A value that cannot
     * be rendered fails the whole sheet: a sheet missing a value would ask the
     * human to approve something it does not show. */
    NSString *const kSeeTerminal = @"(see terminal)";
    NSString *userVal = (user != NULL && user[0] != '\0') ? sw_pf_escape(user)
                                                          : @"root";
    NSString *pathVal = nil;
    if (cwd != NULL && cwd[0] != '\0') {
        pathVal = sw_pf_escape(cwd);
        if (pathVal == nil) return nil;
    }
    NSString *cmdVal = sw_pf_command_line(path, argv);
    if (userVal == nil || cmdVal == nil) return nil;

    /* Closing reminder. Bounded either way; reserve the larger for the budget
     * so the fit holds before we know which one we will emit. */
    /* Both end in a full stop. Before macOS 27 the sheet absorbs its own
     * period after ours; SystemHeadline drops ours below, since macOS 27
     * appends one regardless. */
    NSString *bottomClean = @"Code must match your terminal.";
    NSString *bottomTrunc = @"⚠️ Long items are shown in your terminal.";
    NSUInteger bottomReserve = (bottomClean.length > bottomTrunc.length)
        ? bottomClean.length : bottomTrunc.length;

    /* Per-item all-or-nothing. user/path take fixed caps; the command gets
     * whatever budget remains, so the star of the prompt keeps the largest
     * share. Anything over its budget becomes "(see terminal)" and the caller
     * echoes the full value to the controlling terminal. */
    BOOL userOverflow = (userVal.length > kMaxUserDisplay);
    NSString *userShown = userOverflow ? kSeeTerminal : userVal;

    BOOL pathOverflow = (pathVal != nil && pathVal.length > kMaxCwdDisplay);
    NSString *pathShown = pathVal ? (pathOverflow ? kSeeTerminal : pathVal) : nil;

    /* Layout: header \n\n "RUN AS\n"u \n\n ["DIRECTORY\n"p \n\n]
     *         "EXECUTE\n"c \n\n verify \n\n bottom. Stacked labels: each
     *         label sits alone on its line, the value below it, a blank line
     *         between fields — so a value wrapped by the narrow sheet cannot
     *         run into the next label, and the value gets the full line width.
     *         Caps carry the label-vs-value distinction on a surface that has
     *         no bold and no colour. RUN AS names the runas target (the same
     *         referent as the terminal's run as: row) and EXECUTE the resolved
     *         path (the terminal's execute: row). The verify code sits after
     *         the command block, so the code-matching step lands immediately
     *         before the decision. Fixed labels are 7/10/8 chars including
     *         their newline. */
    NSUInteger overhead =
        header.length + 2
        + verifyLine.length + 2
        + 7 + userShown.length + 2
        + (pathShown ? (10 + pathShown.length + 2) : 0)
        + 8
        + 2 + bottomReserve;
    NSUInteger cmdBudget = (kMaxTotal > overhead) ? kMaxTotal - overhead : 0;

    BOOL cmdOverflow = (cmdVal.length > cmdBudget);
    NSString *cmdShown = cmdOverflow ? kSeeTerminal : cmdVal;

    if (outOverflow) {
        outOverflow->user = userOverflow;
        outOverflow->path = pathOverflow;
        outOverflow->command = cmdOverflow;
    }

    NSString *bottom = (userOverflow || pathOverflow || cmdOverflow)
        ? bottomTrunc : bottomClean;
    /* macOS 27's sheet appends its period even after ours ("terminal.."), so
     * that style ends bare and the system supplies the stop. */
    if (style == SWPromptStyleSystemHeadline && [bottom hasSuffix:@"."]) {
        bottom = [bottom substringToIndex:bottom.length - 1];
    }

    /* What makes a label unforgeable is the SHAPE, not the spelling: a real
     * label sits alone on its own line, directly after a blank line, with its
     * value on the line below. escape_core escapes newlines and the Unicode
     * line/paragraph separators in every displayed value, so no value can
     * contain a line break at all — it may well contain the text "RUN AS" or
     * "EXECUTE", but it can never put that text alone on a line of its own,
     * and it can never fabricate the blank line that precedes every real
     * label. The line structure here is therefore unambiguously ours: the
     * caps are for the reader, not the guarantee. */
    NSMutableString *out = [NSMutableString stringWithCapacity:kMaxTotal];
    [out appendFormat:@"%@\n\nRUN AS\n%@\n\n", header, userShown];
    if (pathShown) [out appendFormat:@"DIRECTORY\n%@\n\n", pathShown];
    [out appendFormat:@"EXECUTE\n%@\n\n%@\n\n%@", cmdShown, verifyLine, bottom];
    return out;
}

@end
