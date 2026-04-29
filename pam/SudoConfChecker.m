#import "SudoConfChecker.h"

@implementation TSudoSudoConfChecker

+ (BOOL)verifyConfPath:(NSString *)confPath
        expectedSymbol:(NSString *)symbol
          expectedPath:(NSString *)pluginPath
                 error:(NSError **)error {
    NSError *readErr = nil;
    NSString *content = [NSString stringWithContentsOfFile:confPath
                                                  encoding:NSUTF8StringEncoding
                                                     error:&readErr];
    if (content == nil) {
        if (error) {
            *error = readErr ? readErr : [NSError errorWithDomain:@"tsudo.SudoConfChecker"
                                                              code:1
                                                          userInfo:@{NSLocalizedDescriptionKey:
                                                                         [NSString stringWithFormat:@"cannot read %@", confPath]}];
        }
        return NO;
    }

    for (NSString *rawLine in [content componentsSeparatedByString:@"\n"]) {
        NSString *line = [rawLine stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceCharacterSet]];
        if (line.length == 0) continue;
        if ([line hasPrefix:@"#"]) continue;

        NSArray<NSString *> *fields = [line componentsSeparatedByCharactersInSet:
                                       [NSCharacterSet whitespaceCharacterSet]];
        NSMutableArray<NSString *> *nonEmpty = [NSMutableArray array];
        for (NSString *f in fields) if (f.length > 0) [nonEmpty addObject:f];
        if (nonEmpty.count < 3) continue;
        if (![nonEmpty[0] isEqualToString:@"Plugin"]) continue;
        if (![nonEmpty[1] isEqualToString:symbol]) continue;
        if (![nonEmpty[2] isEqualToString:pluginPath]) continue;
        return YES;
    }

    if (error) *error = [NSError errorWithDomain:@"tsudo.SudoConfChecker"
                                            code:2
                                        userInfo:@{NSLocalizedDescriptionKey:
                                                       [NSString stringWithFormat:@"%@ has no 'Plugin %@ %@' line",
                                                        confPath, symbol, pluginPath]}];
    return NO;
}

@end
