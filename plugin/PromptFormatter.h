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

@interface SudoWhatPromptFormatter : NSObject

+ (NSString *)formatWithCommandPath:(NSString *)path
                          runasUser:(NSString *)user
                                argv:(NSArray<NSString *> *)argv;

/* Exposed for unit tests. Public so a future test target can call it. */
+ (NSString *)quoteToken:(NSString *)token;

@end

#endif
