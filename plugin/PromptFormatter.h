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
 *                    period, so our opening line is a lowercase
 *                    continuation (`run a command.`).
 *   SelfContained  — Authorization Services password dialog. macOS
 *                    shows our text verbatim with no wrapper, so the
 *                    opening line is capitalized (`Run a command.`).
 * The full stop lives at the top (the opening line); the closing line
 * is a short reminder that harmlessly absorbs the sheet's auto-period. */
typedef NS_ENUM(NSInteger, SWPromptStyle) {
    SWPromptStyleSystemSheet = 0,
    SWPromptStyleSelfContained,
};

/* Per-item overflow report. The prompt shows each of user / path / command
 * either in full or, when it does not fit the sheet budget, as the marker
 * "(see terminal)" (all-or-nothing per item — no partial ellipsis). A YES field
 * means that item was replaced by the marker, so the plugin MUST echo the full
 * value to the controlling terminal or the marker would be a lie. */
typedef struct {
    BOOL user;
    BOOL path;
    BOOL command;
} SWPromptOverflow;

@interface SudoWhatPromptFormatter : NSObject

+ (NSString *)formatWithCommandPath:(NSString *)path
                          runasUser:(NSString *)user
                                cwd:(NSString *)cwd
                         verifyCode:(NSString *)verifyCode
                                argv:(NSArray<NSString *> *)argv
                              style:(SWPromptStyle)style;

/* As above, but reports via outTruncated whether ANY item was replaced by the
 * "(see terminal)" marker (user, path, or command). Pass NULL to ignore. */
+ (NSString *)formatWithCommandPath:(NSString *)path
                          runasUser:(NSString *)user
                                cwd:(NSString *)cwd
                         verifyCode:(NSString *)verifyCode
                                argv:(NSArray<NSString *> *)argv
                              style:(SWPromptStyle)style
                       wasTruncated:(BOOL *)outTruncated;

/* As above, but reports which specific items overflowed to the terminal, so the
 * plugin can echo exactly those. Pass NULL to ignore. */
+ (NSString *)formatWithCommandPath:(NSString *)path
                          runasUser:(NSString *)user
                                cwd:(NSString *)cwd
                         verifyCode:(NSString *)verifyCode
                                argv:(NSArray<NSString *> *)argv
                              style:(SWPromptStyle)style
                           overflow:(SWPromptOverflow *)outOverflow;

/* The full, untruncated command line — the resolved path plus argv, with the
 * SAME shell-quoting and control-char escaping the sheet uses, but no budget
 * cap. For echoing to the controlling terminal when the sheet truncated the
 * command. Disclosure only, never a trust signal: any process that can write
 * the terminal can forge these bytes, so the anchor stays the verify code
 * matching the system-rendered sheet. Because every token is escaped, the
 * returned string contains no raw control characters and is safe to write to a
 * terminal verbatim. */
+ (NSString *)fullCommandLineForCommandPath:(NSString *)path
                                       argv:(NSArray<NSString *> *)argv;

/* Exposed for unit tests. Public so a future test target can call it. */
+ (NSString *)quoteToken:(NSString *)token;

/* Escape control / homoglyph / bidi / zero-width characters to visible \xNN or
 * \uNNNN text, so the glyphs shown can neither smuggle hidden lines nor visually
 * reorder (Trojan Source). Public so the plugin can escape the user/path values
 * it echoes to the terminal with the same rules the sheet uses. */
+ (NSString *)escapeControlChars:(NSString *)s;

@end

#endif
