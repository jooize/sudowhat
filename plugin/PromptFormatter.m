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

    /* Cap displayed tokens. The LAContext sheet grows vertically without
     * bound and can fall off the screen; trust-critical info lives above
     * the command for that reason, but we still cap here so the command
     * region itself doesn't go absurdly long. 50 tokens is generous for
     * legitimate use and short enough to keep the prompt manageable. */
    const NSUInteger kMaxDisplayedTokens = 50;
    NSUInteger totalParts = parts.count;
    NSArray<NSString *> *shownParts = (totalParts > kMaxDisplayedTokens)
        ? [parts subarrayWithRange:NSMakeRange(0, kMaxDisplayedTokens)]
        : parts;
    NSString *commandLine = [shownParts componentsJoinedByString:@" "];

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

    /* Footer ONLY when we truncated — when the full command fits, an
     * always-on count line is just noise. Trade-off: without a footer,
     * the SystemSheet auto-period falls on the last character of the
     * command region, which can look weird depending on the last token.
     * Accepted because the no-truncation case is the common one and
     * cleaner-but-occasionally-ugly beats always-noisy. */
    BOOL truncated = shownParts.count < totalParts;
    NSString *footer = nil;
    if (truncated) {
        footer = [NSString stringWithFormat:@"Showing %lu of %lu arguments",
                  (unsigned long)shownParts.count,
                  (unsigned long)totalParts];
        if (style == SWPromptStyleSelfContained) {
            footer = [footer stringByAppendingString:@"."];
        }
    }

    /* Layout. Blank lines are the structural separator; argv tokens are
     * joined with spaces (not newlines) and escapeControlChars above
     * scrubs Unicode line separators from every displayed string, so a
     * blank line in the rendered prompt is unambiguously ours and not
     * argv content. Two blank lines around the command region give it
     * extra visual breathing room without needing a visible marker. */
    if (footer != nil) {
        return [NSString stringWithFormat:@"%@\n\n%@\n\n\n%@\n\n\n%@",
                header, verifyLine, commandLine, footer];
    }
    return [NSString stringWithFormat:@"%@\n\n%@\n\n\n%@",
            header, verifyLine, commandLine];
}

@end
