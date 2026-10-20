/*
 * PromptFormatter — renders the command sudo will execute as a single string
 * suitable for LAContext's localizedReason.
 *
 * Each argv token is shell-quoted if it contains anything outside a
 * conservative safe character set. Hidden characters (controls, bidi controls,
 * zero-width and other invisible characters) show as escapes, so an attacker
 * can't smuggle hidden lines into the visible prompt or reorder what it shows
 * (see escapeControlChars: below).
 */

#ifndef SUDOWHAT_PROMPT_FORMATTER_H
#define SUDOWHAT_PROMPT_FORMATTER_H

#import <Foundation/Foundation.h>

/* SWPromptStyle picks the display mode for the prompt content:
 *   SystemSheet    — LAContext Touch ID sheet. macOS prepends
 *                    `"sudo" is trying to ` and appends a terminal
 *                    period, so our opening line is a lowercase
 *                    continuation (`run a command.`).
 *   SystemHeadline — the same sheet on macOS 27 and later, where our text
 *                    is the bold headline and macOS appends its period
 *                    whether or not one is there, so the closing line
 *                    ends without one. Otherwise identical to SystemSheet.
 * The full stop lives at the top (the opening line); the closing line
 * is a short reminder that harmlessly absorbs the sheet's auto-period
 * before macOS 27, and takes it on 27. */
typedef NS_ENUM(NSInteger, SWPromptStyle) {
    SWPromptStyleSystemSheet = 0,
    SWPromptStyleSystemHeadline,
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

/* Escape a value by the house untrusted-text rules, so the glyphs shown are
 * exactly the characters that are there: a hidden-list code point (controls,
 * bidi controls, zero-width and other invisible characters, unusual spaces,
 * variation selectors, tags) shows as \u{HEX}, uppercase with no leading
 * zeros, and a literal backslash that would begin an escape (before u{, or
 * before x and a hex digit) as its own \u{5C}. Everything else is drawn as
 * itself. No line break survives, so no value can fake the sheet's structure.
 * Twin of escape_core's escape_bytes on valid UTF-8 (an NSString holds no
 * invalid bytes); tests/test_escape_core.m holds the two in step. */
+ (NSString *)escapeControlChars:(NSString *)s;

@end

#endif
