/*
 * PromptFormatter — lays out the Touch ID sheet's text (LAContext's
 * localizedReason): the target user, the directory, the command sudo will
 * execute and the verify code, within the sheet's length budget.
 *
 * It renders no value itself. Every value someone else chose arrives as the
 * raw bytes sudo handed over, and escape_core (shared/escape_core) escapes and
 * shell-quotes them: the same renderer that draws the terminal's execute: line,
 * so the sheet and the terminal show one value one way, an invalid UTF-8 byte
 * included (as \xHH on both). Decoding to an NSString first would fail on such
 * a byte and drop the value, so no untrusted value is ever an NSString here.
 * Hidden characters (controls, bidi controls, zero-width and other invisible
 * characters) show as escapes, so no value can smuggle a line break into the
 * sheet or reorder what it shows.
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

/* The sheet's text. path, user and cwd are NUL-terminated byte strings and argv
 * a NULL-terminated array of them (sudo's run_argv), taken as they are: no
 * value is rejected or dropped for its bytes. user NULL or empty shows "root"
 * (sudo's default target); cwd NULL or empty leaves out the DIRECTORY field;
 * argv NULL is a path-only command. verifyCode is ours (the nonce), escaped the
 * same way all the same.
 *
 * Returns nil when path is NULL or the renderer fails (an allocation failure):
 * the caller must then refuse rather than raise a sheet that does not show the
 * command. */
+ (NSString *)formatWithCommandPath:(const char *)path
                          runasUser:(const char *)user
                                cwd:(const char *)cwd
                         verifyCode:(NSString *)verifyCode
                               argv:(char * const *)argv
                              style:(SWPromptStyle)style;

/* As above, but reports via outTruncated whether ANY item was replaced by the
 * "(see terminal)" marker (user, path, or command). Pass NULL to ignore. */
+ (NSString *)formatWithCommandPath:(const char *)path
                          runasUser:(const char *)user
                                cwd:(const char *)cwd
                         verifyCode:(NSString *)verifyCode
                               argv:(char * const *)argv
                              style:(SWPromptStyle)style
                       wasTruncated:(BOOL *)outTruncated;

/* As above, but reports which specific items overflowed to the terminal, so the
 * plugin can echo exactly those. Pass NULL to ignore. */
+ (NSString *)formatWithCommandPath:(const char *)path
                          runasUser:(const char *)user
                                cwd:(const char *)cwd
                         verifyCode:(NSString *)verifyCode
                               argv:(char * const *)argv
                              style:(SWPromptStyle)style
                           overflow:(SWPromptOverflow *)outOverflow;

@end

#endif
