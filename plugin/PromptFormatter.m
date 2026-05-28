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

        if (c == '\n') {
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
        } else if (c == 0x2026 || c == 0x22EF) {
            /* U+2026 HORIZONTAL ELLIPSIS is our truncation marker; a path
             * containing `…` would otherwise be indistinguishable from a
             * truncated one. U+22EF MIDLINE HORIZONTAL ELLIPSIS renders
             * visually identical in most fonts and is the obvious bypass.
             * Escape both so only the formatter's added marker appears as
             * a literal `…` in the rendered prompt. */
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

+ (NSString *)formatWithCommandPath:(NSString *)path
                          runasUser:(NSString *)user
                                cwd:(NSString *)cwd
                         verifyCode:(NSString *)verifyCode
                                argv:(NSArray<NSString *> *)argv
                              style:(SWPromptStyle)style {
    /* Build the displayable token list: resolved path, then argv tokens
     * minus argv[0] when it duplicates the path/basename. */
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

    /* Header. SystemSheet uses a lowercase verb so the surrounding
     * sentence `"sudo" is trying to <header>` reads grammatically.
     * SelfContained is the entire rendered message, so a capitalized verb
     * fits. No trailing punctuation in either style — the header is a
     * statement label, not the end of a sentence. */
    NSString *runVerb = (style == SWPromptStyleSystemSheet) ? @"run" : @"Run";

    /* Bound the variable parts of the header so a long cwd or weird-long
     * username can't squeeze the command region out of view. Head-only
     * truncation (not middle-break) because these labels are read
     * left-to-right and the leading characters identify the value; the
     * trailing ellipsis signals truncation without needing a structural
     * indicator. */
    const NSUInteger kMaxUserDisplay = 32;
    const NSUInteger kMaxCwdDisplay  = 80;

    NSString *userEscaped = ([user length] > 0)
        ? [self escapeControlChars:user]
        : @"root";
    NSString *userPart = (userEscaped.length > kMaxUserDisplay)
        ? [[userEscaped substringToIndex:kMaxUserDisplay]
            stringByAppendingString:@"…"]
        : userEscaped;

    NSMutableString *header = [NSMutableString stringWithCapacity:64];
    [header appendFormat:@"%@ as user %@", runVerb, userPart];
    if ([cwd length] > 0) {
        NSString *cwdEscaped = [self escapeControlChars:cwd];
        NSString *cwdPart = (cwdEscaped.length > kMaxCwdDisplay)
            ? [[cwdEscaped substringToIndex:kMaxCwdDisplay]
                stringByAppendingString:@"…"]
            : cwdEscaped;
        [header appendFormat:@" in directory %@", cwdPart];
    }

    /* Verify code. The plugin has already printed the same value to the
     * user's controlling terminal; the user compares the two before
     * approving. Lives above the command region so it remains visible
     * even when the command region overflows the screen. */
    NSString *verifyLine = ([verifyCode length] > 0)
        ? [NSString stringWithFormat:@"Verify code: %@",
           [self escapeControlChars:verifyCode]]
        : @"Verify code: unavailable";

    /* LA caps the localizedReason string at ~510 chars total — anything
     * past the cap is a hard NSString cut, including newlines and content
     * intended to live on subsequent lines. Empirically verified by
     * rendering a 1040-char marker arg and confirming a "Showing N of M"
     * line emitted past the cap never appeared in the sheet. AS has a
     * much larger budget (rendered the full 1040 chars + footer), but we
     * apply the same conservative char budget to both styles so the
     * truncation indicator looks identical in Touch ID and password
     * fallback flows.
     *
     * Practical consequence: the truncation indicator MUST live ABOVE the
     * command region, because anything below it can be silently clipped.
     *
     * Budget 480 chars gives ~30 chars of safety margin against the
     * observed cap. */
    const NSUInteger kMaxTotal = 480;

    /* Trailing trust statement. Two things at once: gives a home to the
     * SystemSheet's auto-period (which would otherwise attach to the
     * command's last token and look like part of the argv), and reminds
     * the user what the verify code and command region actually mean —
     * including spelling out the U+2026 ellipsis as the only truncation
     * marker, so a path/arg containing a real `…` (which we escape to
     * `…`) can't impersonate truncation. SelfContained renders the
     * entire reason verbatim, so we add our own period; SystemSheet
     * relies on macOS auto-appending one and must not double up. */
    NSString *trailer = (style == SWPromptStyleSelfContained)
        ? @"Code verifies origin. Command shown is what runs, unless marked truncated with ellipsis \"…\" (\\u2026)."
        : @"Code verifies origin. Command shown is what runs, unless marked truncated with ellipsis \"…\" (\\u2026)";

    /* Pass 1: try to fit everything with no truncation indicator.
     * Layout overhead: header + "\n\n" + verifyLine + "\n\n\n"
     *                + command + "\n\n\n" + trailer */
    NSUInteger fixedOverhead = header.length + 2 + verifyLine.length + 3
                             + 3 + trailer.length;
    NSUInteger budget1 = (kMaxTotal > fixedOverhead)
        ? kMaxTotal - fixedOverhead : 0;

    NSUInteger allPartsLen = 0;
    for (NSString *p in parts) {
        allPartsLen += p.length + (allPartsLen > 0 ? 1 : 0); /* space sep */
    }

    NSString *const kTruncLabel = @"… COMMAND TRUNCATED …";
    NSArray<NSString *> *shownParts = nil;
    BOOL truncationAbove = NO;     /* indicator on its own line above command */
    /* (When neither flag is set and shownParts == parts, no truncation
     * happened. When middle-break fires, the indicator is embedded inside
     * the partial arg's text via "\n\nLABEL\n\n" so it appears between
     * head and tail in the rendered command region.) */

    if (allPartsLen <= budget1) {
        shownParts = parts;
    } else {
        /* Greedily fit whole parts. The first part that doesn't fit
         * either:
         *   - triggers a middle-break (if it's the LAST part): render its
         *     head + "\n\nLABEL\n\n" + tail inline. The double newlines
         *     above and below the label make the break impossible to
         *     miss visually, which is the point.
         *   - or, falls back to the "above command" indicator (if there
         *     are later parts we'd otherwise drop silently, or if no room
         *     for a meaningful partial). Trailing parts are dropped. */
        NSMutableArray<NSString *> *fitted = [NSMutableArray array];
        NSUInteger used = 0;
        for (NSUInteger i = 0; i < parts.count; i++) {
            NSString *p = parts[i];
            NSUInteger sep = (used > 0 ? 1 : 0);
            if (used + sep + p.length <= budget1) {
                [fitted addObject:p];
                used += sep + p.length;
                continue;
            }
            BOOL isLast = (i == parts.count - 1);
            BOOL didMiddleBreak = NO;
            if (isLast) {
                /* Middle-break overhead: " " (sep) + head + "\n\n" + label
                 * + "\n\n" + tail.  We've already subtracted `sep` above;
                 * inside the partial: 2 + label.length + 2 = label+4. */
                NSUInteger blockOverhead = kTruncLabel.length + 4;
                NSUInteger available = 0;
                if (budget1 > used + sep + blockOverhead) {
                    available = budget1 - used - sep - blockOverhead;
                }
                /* Require at least this many content chars to bother
                 * splitting; otherwise the head/tail fragments are too
                 * short to be useful. */
                const NSUInteger kMinPartial = 24;
                if (available >= kMinPartial && p.length > available) {
                    NSUInteger headLen = available / 2;
                    NSUInteger tailLen = available - headLen;
                    NSString *withBreak = [NSString stringWithFormat:
                                            @"%@\n\n%@\n\n%@",
                                            [p substringToIndex:headLen],
                                            kTruncLabel,
                                            [p substringFromIndex:p.length - tailLen]];
                    [fitted addObject:withBreak];
                    didMiddleBreak = YES;
                }
            }
            if (!didMiddleBreak) {
                /* Above-command indicator layout costs LABEL + "\n" more
                 * than the no-truncation layout. Re-fit by trimming any
                 * already-fitted parts that no longer fit in the smaller
                 * budget. Without this, the rendered prompt would overflow
                 * budget1 by LABEL.length + 1 chars (~18) in tight cases. */
                NSUInteger aboveBudget = (budget1 > kTruncLabel.length + 1)
                    ? budget1 - kTruncLabel.length - 1 : 0;
                while (fitted.count > 0 && used > aboveBudget) {
                    NSString *last = [fitted lastObject];
                    [fitted removeLastObject];
                    NSUInteger lastSep = (fitted.count > 0) ? 1 : 0;
                    used -= lastSep + last.length;
                }
                truncationAbove = YES;
            }
            break;
        }
        shownParts = fitted;
    }

    NSString *commandLine = [shownParts componentsJoinedByString:@" "];

    /* Layout. Blank lines are the structural separator; argv tokens are
     * joined with spaces and escapeControlChars above scrubs Unicode line
     * separators from every displayed string, so a blank line in the
     * rendered prompt is unambiguously ours and not argv content. The
     * trailer sits below the command region so the auto-period (LA) or
     * our own period (AS) attaches to it instead of the last argv token. */
    if (truncationAbove) {
        return [NSString stringWithFormat:@"%@\n\n%@\n\n\n%@\n%@\n\n\n%@",
                header, verifyLine, kTruncLabel, commandLine, trailer];
    }
    return [NSString stringWithFormat:@"%@\n\n%@\n\n\n%@\n\n\n%@",
            header, verifyLine, commandLine, trailer];
}

@end
