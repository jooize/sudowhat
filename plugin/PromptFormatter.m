#import "PromptFormatter.h"

@implementation TSudoPromptFormatter

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
            [out appendFormat:@"\\x%02x", (unsigned)c];
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
                                argv:(NSArray<NSString *> *)argv {
    NSMutableArray<NSString *> *parts = [NSMutableArray arrayWithCapacity:(argv.count + 1)];
    NSString *quotedPath = [self quoteToken:path];
    [parts addObject:quotedPath];

    NSString *basename = [path lastPathComponent];
    NSUInteger startIdx = 0;
    if (argv.count > 0 && basename.length > 0 && [argv[0] isEqualToString:basename]) {
        startIdx = 1;
    }
    for (NSUInteger i = startIdx; i < argv.count; i++) {
        [parts addObject:[self quoteToken:argv[i]]];
    }

    NSString *commandLine = [parts componentsJoinedByString:@" "];

    NSString *header = ([user length] > 0 && ![user isEqualToString:@"root"])
        ? [NSString stringWithFormat:@"Run as %@:", [self escapeControlChars:user]]
        : @"Run as root:";

    return [NSString stringWithFormat:@"%@\n\n%@", header, commandLine];
}

@end
