/*
 * SessionGuard — confirms the invoking UID is the active console (GUI) user.
 *
 * Defends against an SSH attacker on a shared box: they can't pop a Touch ID
 * dialog the local user reflexively approves, because their UID won't match
 * the console UID.
 */

#ifndef SUDOWHAT_SESSION_GUARD_H
#define SUDOWHAT_SESSION_GUARD_H

#import <Foundation/Foundation.h>
#include <sys/types.h>

@interface SudoWhatSessionGuard : NSObject

/* Returns YES iff invokingUid matches an active console session UID
 * (not 0, not (uid_t)-1). */
+ (BOOL)isInvokingUserActiveConsole:(uid_t)invokingUid;

@end

#endif
