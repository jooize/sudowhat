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

/* The hidden list of the untrusted-text rules, verbatim: code points that draw
 * nothing, draw as something else, or reorder the text after them. Twin of
 * escape_core's is_hidden; keep the two in step. A plain space is not on it. */
static BOOL sw_is_hidden(uint32_t u) {
    return u <= 0x1F || (u >= 0x7F && u <= 0x9F) || u == 0xA0 || u == 0xAD
        || u == 0x34F || u == 0x61C || (u >= 0x115F && u <= 0x1160)
        || (u >= 0x17B4 && u <= 0x17B5) || (u >= 0x180B && u <= 0x180E)
        || (u >= 0x2000 && u <= 0x200F) || (u >= 0x2028 && u <= 0x202F)
        || (u >= 0x205F && u <= 0x206F) || u == 0x3000 || u == 0x3164
        || (u >= 0xFE00 && u <= 0xFE0F) || u == 0xFEFF || u == 0xFFA0
        || (u >= 0xFFF9 && u <= 0xFFFB) || (u >= 0xE0000 && u <= 0xE007F)
        || (u >= 0xE0100 && u <= 0xE01EF);
}

static BOOL sw_is_hex_digit(uint32_t u) {
    return (u >= '0' && u <= '9') || (u >= 'A' && u <= 'F')
        || (u >= 'a' && u <= 'f');
}

/* Append the escape of one code point: a backslash, "u{", uppercase hex with
 * no leading zeros, "}". The format holds no backslash itself; %C adds it. */
static void sw_append_escape(NSMutableString *out, uint32_t u) {
    [out appendFormat:@"%Cu{%X}", (unichar)'\\', (unsigned)u];
}

+ (NSString *)escapeControlChars:(NSString *)s {
    NSUInteger len = s.length;

    /* Code points first: a surrogate pair combines into its scalar value, so
     * astral characters (emoji, tag characters) are judged whole. A lone
     * surrogate stays as its own unit. */
    NSMutableData *buf = [NSMutableData dataWithLength:(len + 1) * sizeof(uint32_t)];
    uint32_t *cps = buf.mutableBytes;
    NSUInteger n = 0;
    for (NSUInteger i = 0; i < len; ) {
        unichar c = [s characterAtIndex:i];
        if (CFStringIsSurrogateHighCharacter(c) && i + 1 < len
            && CFStringIsSurrogateLowCharacter([s characterAtIndex:i + 1])) {
            cps[n++] = (uint32_t)CFStringGetLongCharacterForSurrogatePair(
                c, [s characterAtIndex:i + 1]);
            i += 2;
        } else {
            cps[n++] = c;
            i += 1;
        }
    }

    NSMutableString *out = [NSMutableString stringWithCapacity:len];
    for (NSUInteger k = 0; k < n; k++) {
        uint32_t u = cps[k];
        if (sw_is_hidden(u) || (u >= 0xD800 && u <= 0xDFFF)) {
            /* Hidden: drawn as its escape, never raw and never dropped. A lone
             * surrogate is not text at all (it would draw as a replacement
             * glyph that hides which unit was there), so it shows escaped
             * too; it cannot arrive from UTF-8, which is all escape_core
             * sees. */
            sw_append_escape(out, u);
        } else if (u == '\\' && k + 2 < n
                   && ((cps[k + 1] == 'u' && cps[k + 2] == '{')
                       || (cps[k + 1] == 'x' && sw_is_hex_digit(cps[k + 2])))) {
            /* A literal backslash that would read as the start of an escape
             * (before "u{", or before "x" and a hex digit) shows as its own
             * escape, so an escape on screen can only ever be one. Every other
             * backslash is drawn as itself. */
            sw_append_escape(out, '\\');
        } else if (u > 0xFFFF) {
            UniChar pair[2];
            CFStringGetSurrogatePairForLongCharacter((UTF32Char)u, pair);
            [out appendString:[NSString stringWithCharacters:pair length:2]];
        } else {
            unichar c = (unichar)u;
            [out appendString:[NSString stringWithCharacters:&c length:1]];
        }
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
    NSString *verifyLine;
    if (verifyCode.length > 0) {
        NSString *v = [self escapeControlChars:verifyCode];
        if (v.length > kMaxVerifyDisplay) v = [v substringToIndex:kMaxVerifyDisplay];
        verifyLine = [NSString stringWithFormat:@"Verify Code: %@", v];
    } else {
        verifyLine = @"Verify Code: unavailable";
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
     * value on the line below. escapeControlChars scrubs newlines and Unicode
     * line/paragraph separators out of every displayed value, so no value can
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
