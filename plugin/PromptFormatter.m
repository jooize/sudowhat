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
    for (NSUInteger i = 0; i < len; i++) {
        unichar c = [s characterAtIndex:i];
        if (c < 0x20 || c == 0x7f) {
            /* C0 controls and DEL. */
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
        } else {
            [out appendFormat:@"%C", c];
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
    NSString *userPart = ([user length] > 0)
        ? [self escapeControlChars:user]
        : @"root";

    NSMutableString *header = [NSMutableString stringWithCapacity:64];
    [header appendFormat:@"%@ as user %@", runVerb, userPart];
    if ([cwd length] > 0) {
        [header appendFormat:@" in directory %@", [self escapeControlChars:cwd]];
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

    /* Pass 1: try to fit everything with no truncation indicator.
     * Layout overhead: header + "\n\n" + verifyLine + "\n\n\n" */
    NSUInteger noTruncOverhead = header.length + 2 + verifyLine.length + 3;
    NSUInteger budget1 = (kMaxTotal > noTruncOverhead)
        ? kMaxTotal - noTruncOverhead : 0;

    NSUInteger allPartsLen = 0;
    for (NSString *p in parts) {
        allPartsLen += p.length + (allPartsLen > 0 ? 1 : 0); /* space sep */
    }

    NSString *const kTruncLabel = @"Display truncated to fit";
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
                truncationAbove = YES;
            }
            break;
        }
        shownParts = fitted;
    }

    NSString *commandLine = [shownParts componentsJoinedByString:@" "];

    /* SelfContained renders the entire prompt itself, so it ends with a
     * period. SystemSheet relies on macOS auto-appending one. */
    if (style == SWPromptStyleSelfContained) {
        commandLine = [commandLine stringByAppendingString:@"."];
    }

    /* Layout. Blank lines are the structural separator; argv tokens are
     * joined with spaces and escapeControlChars above scrubs Unicode line
     * separators from every displayed string, so a blank line in the
     * rendered prompt is unambiguously ours and not argv content. */
    if (truncationAbove) {
        return [NSString stringWithFormat:@"%@\n\n%@\n\n\n%@\n%@",
                header, verifyLine, kTruncLabel, commandLine];
    }
    return [NSString stringWithFormat:@"%@\n\n%@\n\n\n%@",
            header, verifyLine, commandLine];
}

@end
