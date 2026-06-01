/*
 * SessionGuard — decides whether the invoking caller is the LOCAL, physically
 * present console (GUI) user: the only context in which sudowhat raises a
 * biometric / Authorization Services sheet.
 *
 * It is deliberately NOT a uid comparison. SCDynamicStoreCopyConsoleUser
 * reports who owns the console *system-wide*, so comparing uids alone cannot
 * tell "user 501 sitting at the Mac" from "user 501 over SSH" or "user 501's
 * background launchd job" — all three see the same console uid. Proven on
 * hardware (2026-06-01): a same-uid SSH session, while that user is also
 * logged into the GUI, pops the LAContext sheet on the *console* screen. A uid
 * gate would wave it through. So the primary discriminator here is the
 * caller's SECURITY SESSION: a local GUI login has graphic access and is not
 * remote; an SSH session is remote, and a non-graphical session (a
 * system-domain LaunchDaemon, a remote login) has no graphic access. sudo
 * inherits the invoking process's session, so
 * SessionGetInfo(callerSecuritySession, …) reflects where sudo was actually
 * launched from — and it is the kernel audit session, not an environment
 * variable, so it cannot be spoofed by the caller.
 *
 * SCOPE — what this does NOT do. The session attributes belong to the LOGIN
 * session and inherit across fork/exec, so this distinguishes a local GUI login
 * from remote / non-graphical sessions but NOT the human at the keyboard from
 * another process inside the SAME GUI login: a gui-domain LaunchAgent, a
 * backgrounded job, or a helper of a compromised app all inherit the console
 * session's attributes and are classified as console here. That residual
 * reflexive-approval risk is handled by sudowhat's core defenses — the exact
 * command shown in the prompt and the channel-binding nonce echoed to the
 * originating terminal — NOT by this guard, whose narrower job is to keep
 * remote / non-graphical callers off the console biometric entirely.
 *
 * Why a build-time class-name macro: both bundles load into the same sudo
 * process, and two Objective-C classes of the same name collide at runtime, so
 * the class name is injected per target via -DSW_SESSIONGUARD_CLASS (plugin:
 * SudoWhatSessionGuard, PAM: SudoWhatPamSessionGuard), exactly as
 * shared/SignatureVerifier.h does. Compiling the one source into both places
 * means the PAM-phase console-gate and the approval-phase guard apply
 * IDENTICAL logic to the SAME process session — they cannot disagree. The
 * #error below fails the build loudly if a target forgets to define it.
 */

#ifndef SUDOWHAT_SESSION_GUARD_H
#define SUDOWHAT_SESSION_GUARD_H

#import <Foundation/Foundation.h>
#include <sys/types.h>

#ifndef SW_SESSIONGUARD_CLASS
#error "SW_SESSIONGUARD_CLASS must be defined per target (e.g. -DSW_SESSIONGUARD_CLASS=SudoWhatSessionGuard)"
#endif

@interface SW_SESSIONGUARD_CLASS : NSObject

/* YES iff the caller is the active LOCAL console (GUI) user: the caller's
 * security session has graphic access and is not remote, AND the active
 * console uid equals invokingUid and is neither 0 nor (uid_t)-1. Any failure
 * to confirm all of these returns NO — the guard fails toward "non-console",
 * never toward "console". */
+ (BOOL)isInvokingUserActiveConsole:(uid_t)invokingUid;

@end

#endif
