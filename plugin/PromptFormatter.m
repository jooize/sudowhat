#import "PromptFormatter.h"

@implementation SudoWhatPromptFormatter

+ (NSCharacterSet *)safeSet {
    static NSCharacterSet *set;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        set = [NSCharacterSet characterSetWithCharactersInString:
               @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
               @"+_./:=@%,-"];
    });
    return set;
}

+ (NSString *)escapeControlChars:(NSString *)s {
    NSMutableString *out = [NSMutableString stringWithCapacity:s.length];
    NSUInteger len = s.length;
    NSUInteger i = 0;
    while (i < len) {
        unichar c = [s characterAtIndex:i];

        /* Run of 3+ ASCII '.' is visually indistinguishable from a single
         * U+2026 `…` in proportional fonts — it would impersonate our
         * truncation marker. Escape every dot in the run. (Single '.' and
         * the parent-dir reference '..' pass through unchanged; both are
         * legitimate path content.) */
        if (c == '.') {
            NSUInteger j = i + 1;
            while (j < len && [s characterAtIndex:j] == '.') j++;
            NSUInteger runLen = j - i;
            if (runLen >= 3) {
                for (NSUInteger k = 0; k < runLen; k++) {
                    [out appendString:@"\\u002e"];
                }
                i = j;
                continue;
            }
            /* run of 1 or 2: fall through to literal emit */
        }

        if (c == '\\') {
            /* Escape literal backslashes so the prompt is unambiguous
             * about what the source bytes were. Without this, a literal
             * two-char `\n` in argv would render identically to our
             * escape for a real 0x0a newline, letting an attacker spoof
             * the "this contained a newline" signal with plain text. */
            [out appendString:@"\\\\"];
        } else if (c == '\n') {
            [out appendString:@"\\n"];
        } else if (c == '\r') {
            [out appendString:@"\\r"];
        } else if (c == '\t') {
            [out appendString:@"\\t"];
        } else if (c == '\0') {
            [out appendString:@"\\0"];
        } else if (c < 0x20 || c == 0x7f) {
            /* C0 controls and DEL not already handled above. */
            [out appendFormat:@"\\x%02x", (unsigned)c];
        } else if (c >= 0x80 && c <= 0x9f) {
            /* C1 control range, including U+0085 NEL which some text
             * renderers treat as a line break. */
            [out appendFormat:@"\\u%04x", (unsigned)c];
        } else if (c == 0x2028 || c == 0x2029) {
            /* Unicode line / paragraph separators. NSString renderers
             * routinely honour these as real line breaks. Escaping them
             * is what makes a blank line a trustworthy structural marker
             * in the rendered prompt — without this, a 63-byte
             * TERM_PROGRAM (or any other shown string) could inject a
             * fake paragraph break and impersonate prompt structure. */
            [out appendFormat:@"\\u%04x", (unsigned)c];
        } else if (c == 0x2026 || c == 0x22EF || c == 0x2024 || c == 0x2025) {
            /* Ellipsis / dot-leader homoglyphs. U+2026 HORIZONTAL ELLIPSIS and
             * U+22EF MIDLINE HORIZONTAL ELLIPSIS render as `…`; U+2024 ONE DOT
             * LEADER and U+2025 TWO DOT LEADER render as dots that read as `…`
             * when repeated. Escaping them keeps the rendered dots honest — no
             * displayed value can mimic a run of real periods it does not have. */
            [out appendFormat:@"\\u%04x", (unsigned)c];
        } else if ((c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069)
                   || c == 0x200E || c == 0x200F || c == 0x061C) {
            /* Bidirectional formatting / override characters (Trojan Source,
             * CVE-2021-42574): LRE/RLE/PDF/LRO/RLO, the isolates LRI/RLI/FSI/PDI,
             * the marks LRM/RLM, and ALM. They visually REORDER surrounding text,
             * so the glyphs on the sheet can read as a different, innocuous
             * command than the bytes execve runs — single-quoting does not
             * neutralize them. Escape so rendered order matches byte order. */
            [out appendFormat:@"\\u%04x", (unsigned)c];
        } else if (c == 0x200B || c == 0x200C || c == 0x200D
                   || c == 0x2060 || c == 0xFEFF) {
            /* Zero-width / invisible format characters (ZWSP, ZWNJ, ZWJ, WORD
             * JOINER, ZWNBSP/BOM): no visible glyph, so they can hide bytes or
             * splice tokens with nothing shown. Escape so nothing in a displayed
             * value is invisible. */
            [out appendFormat:@"\\u%04x", (unsigned)c];
        } else {
            [out appendFormat:@"%C", c];
        }
        i++;
    }
    return out;
}

+ (NSString *)quoteToken:(NSString *)token {
    if (token == nil) return @"''";
    if (token.length == 0) return @"''";

    NSString *escaped = [self escapeControlChars:token];

    NSCharacterSet *unsafe = [[self safeSet] invertedSet];
    if ([escaped rangeOfCharacterFromSet:unsafe].location == NSNotFound) {
        return escaped;
    }

    NSMutableString *quoted = [NSMutableString stringWithCapacity:escaped.length + 2];
    [quoted appendString:@"'"];
    NSUInteger len = escaped.length;
    for (NSUInteger i = 0; i < len; i++) {
        unichar c = [escaped characterAtIndex:i];
        if (c == '\'') {
            [quoted appendString:@"'\\''"];
        } else {
            [quoted appendFormat:@"%C", c];
        }
    }
    [quoted appendString:@"'"];
    return quoted;
}

/* Build the displayable token list: resolved path, then argv tokens minus
 * argv[0] when it duplicates the path/basename. Each token is shell-quoted and
 * control-char escaped. Shared by the sheet formatter below (which then applies
 * the length budget) and the full-command terminal echo (which does not), so
 * the two renderings can never disagree on how a token is quoted or escaped. */
+ (NSArray<NSString *> *)commandPartsForPath:(NSString *)path
                                        argv:(NSArray<NSString *> *)argv {
    NSMutableArray<NSString *> *parts = [NSMutableArray arrayWithCapacity:(argv.count + 1)];
    [parts addObject:[self quoteToken:path]];

    NSString *basename = [path lastPathComponent];
    NSUInteger startIdx = 0;
    if (argv.count > 0) {
        NSString *first = argv[0];
        if ([first isEqualToString:path] ||
            (basename.length > 0 && [first isEqualToString:basename])) {
            startIdx = 1;
        }
    }
    for (NSUInteger i = startIdx; i < argv.count; i++) {
        [parts addObject:[self quoteToken:argv[i]]];
    }
    return parts;
}

+ (NSString *)fullCommandLineForCommandPath:(NSString *)path
                                       argv:(NSArray<NSString *> *)argv {
    return [[self commandPartsForPath:path argv:argv]
            componentsJoinedByString:@" "];
}

+ (NSString *)formatWithCommandPath:(NSString *)path
                          runasUser:(NSString *)user
                                cwd:(NSString *)cwd
                         verifyCode:(NSString *)verifyCode
                                argv:(NSArray<NSString *> *)argv
                              style:(SWPromptStyle)style {
    return [self formatWithCommandPath:path runasUser:user cwd:cwd
                            verifyCode:verifyCode argv:argv style:style
                              overflow:NULL];
}

+ (NSString *)formatWithCommandPath:(NSString *)path
                          runasUser:(NSString *)user
                                cwd:(NSString *)cwd
                         verifyCode:(NSString *)verifyCode
                                argv:(NSArray<NSString *> *)argv
                              style:(SWPromptStyle)style
                       wasTruncated:(BOOL *)outTruncated {
    SWPromptOverflow ov = { NO, NO, NO };
    NSString *out = [self formatWithCommandPath:path runasUser:user cwd:cwd
                                     verifyCode:verifyCode argv:argv style:style
                                       overflow:&ov];
    if (outTruncated) *outTruncated = (ov.user || ov.path || ov.command);
    return out;
}

+ (NSString *)formatWithCommandPath:(NSString *)path
                          runasUser:(NSString *)user
                                cwd:(NSString *)cwd
                         verifyCode:(NSString *)verifyCode
                                argv:(NSArray<NSString *> *)argv
                              style:(SWPromptStyle)style
                           overflow:(SWPromptOverflow *)outOverflow {
    BOOL selfContained = (style == SWPromptStyleSelfContained);

    /* LA caps the localizedReason at ~510 chars total — anything past the cap
     * is a hard NSString cut, including newlines and any content meant for a
     * later line. We render both styles within a conservative 480-char budget
     * (~30 chars of margin) so the closing reminder is never the thing clipped,
     * and so Touch ID and the AS password fallback look identical. Every
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
     * <this>` and appends a period, so SystemSheet is a lowercase continuation;
     * the AS dialog shows our text verbatim, so it is capitalized. Either way
     * the full stop lives here, at the top. */
    NSString *header = selfContained ? @"Run a command." : @"run a command.";

    /* Verify code. The plugin has already echoed the same value to the user's
     * controlling terminal; they compare the two before approving. Capped
     * (plain cut, no marker) purely so the budget holds against a malformed
     * code — the production nonce is 4 chars. */
    NSString *verifyLine;
    if (verifyCode.length > 0) {
        NSString *v = [self escapeControlChars:verifyCode];
        if (v.length > kMaxVerifyDisplay) v = [v substringToIndex:kMaxVerifyDisplay];
        verifyLine = [NSString stringWithFormat:@"Verify code: %@", v];
    } else {
        verifyLine = @"Verify code: unavailable";
    }

    /* Item values, fully escaped/quoted. Each is shown whole or, if over budget,
     * replaced by the marker — never partially truncated. A displayed cwd always
     * starts with '/', so it can never collide with the parenthesised marker;
     * the command region quotes any token with unsafe bytes, so a literal
     * "(see terminal)" argument renders quoted and stays distinguishable. */
    NSString *const kSeeTerminal = @"(see terminal)";
    NSString *userVal = (user.length > 0) ? [self escapeControlChars:user] : @"root";
    NSString *pathVal = (cwd.length > 0) ? [self escapeControlChars:cwd] : nil;
    NSString *cmdVal  = [[self commandPartsForPath:path argv:argv]
                          componentsJoinedByString:@" "];

    /* Closing reminder. Bounded either way; reserve the larger for the budget
     * so the fit holds before we know which one we will emit. */
    NSString *bottomClean = @"Code must match your terminal";
    NSString *bottomTrunc = @"⚠️ Long items are shown in your terminal";
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

    /* Layout: header \n\n verify \n\n "User: "u \n ["Path: "p \n] "Command: "c
     *         \n\n bottom. Fixed labels are 6/6/9 chars. */
    NSUInteger overhead =
        header.length + 2
        + verifyLine.length + 2
        + 6 + userShown.length + 1
        + (pathShown ? (6 + pathShown.length + 1) : 0)
        + 9
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

    /* escapeControlChars scrubs newlines and Unicode line/paragraph separators
     * from every value, so the blank lines here are unambiguously ours: no
     * displayed value can forge an extra "User:"/"Path:"/"Command:" line. */
    NSMutableString *out = [NSMutableString stringWithCapacity:kMaxTotal];
    [out appendFormat:@"%@\n\n%@\n\nUser: %@\n", header, verifyLine, userShown];
    if (pathShown) [out appendFormat:@"Path: %@\n", pathShown];
    [out appendFormat:@"Command: %@\n\n%@", cmdShown, bottom];
    return out;
}

@end
