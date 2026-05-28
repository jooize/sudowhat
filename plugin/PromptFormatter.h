/*
 * PromptFormatter — renders the command sudo will execute as a single string
 * suitable for LAContext's localizedReason.
 *
 * Each argv token is shell-quoted if it contains anything outside a
 * conservative safe character set. Control characters (< 0x20, 0x7f) are
 * shown as \xNN escapes so an attacker can't smuggle hidden lines into the
 * visible prompt via embedded newlines or terminal escape sequences.
 */

#ifndef SUDOWHAT_PROMPT_FORMATTER_H
#define SUDOWHAT_PROMPT_FORMATTER_H

#import <Foundation/Foundation.h>

/* SWPromptStyle picks between two display modes for the same prompt
 * content:
 *   SystemSheet    — LAContext Touch ID sheet. macOS prepends
 *                    `"sudo" is trying to ` and appends a terminal
 *                    period. Our text uses a lowercase verb and no
 *                    trailing period so the surrounding sentence reads
 *                    grammatically.
 *   SelfContained  — Authorization Services password dialog. macOS
 *                    shows our text verbatim with no wrapper, so we
 *                    capitalize the verb and add our own terminal
 *                    period. */
typedef NS_ENUM(NSInteger, SWPromptStyle) {
    SWPromptStyleSystemSheet = 0,
    SWPromptStyleSelfContained,
};

@interface SudoWhatPromptFormatter : NSObject

+ (NSString *)formatWithCommandPath:(NSString *)path
                          runasUser:(NSString *)user
                                cwd:(NSString *)cwd
                         verifyCode:(NSString *)verifyCode
                                argv:(NSArray<NSString *> *)argv
                              style:(SWPromptStyle)style;

/* Exposed for unit tests. Public so a future test target can call it. */
+ (NSString *)quoteToken:(NSString *)token;

@end

#endif
