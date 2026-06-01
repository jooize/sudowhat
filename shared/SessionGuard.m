#import "SessionGuard.h"
#import <SystemConfiguration/SystemConfiguration.h>
#include <Security/AuthSession.h>

@implementation SW_SESSIONGUARD_CLASS

+ (BOOL)isInvokingUserActiveConsole:(uid_t)invokingUid {
    /* (1) The caller's security session must be a LOCAL GUI session. An SSH /
     * launchd / headless session has no graphic access (and SSH is also flagged
     * remote); a physically-present GUI login has graphic access and is not
     * remote. This is exactly what a uid comparison cannot see — and unlike an
     * SSH_TTY environment sniff, the audit session attributes are not spoofable
     * by the caller. Fail toward non-console on any error. */
    SecuritySessionId sid = 0;
    SessionAttributeBits attrs = 0;
    if (SessionGetInfo(callerSecuritySession, &sid, &attrs) != errSessionSuccess) {
        return NO;
    }
    if (!(attrs & sessionHasGraphicAccess)) return NO;
    if (attrs & sessionIsRemote) return NO;

    /* (2) And the caller must be the front-most console user. This closes the
     * fast-user-switching case where a backgrounded GUI session belonging to a
     * different uid also reports graphic access: only the uid that currently
     * owns the console may proceed. A console uid of 0 or (uid_t)-1 ("no
     * console user") is never a match. */
    uid_t consoleUid = (uid_t)-1;
    CFStringRef user = SCDynamicStoreCopyConsoleUser(NULL, &consoleUid, NULL);
    if (user) CFRelease(user);
    if (consoleUid == (uid_t)-1 || consoleUid == 0) return NO;
    return consoleUid == invokingUid;
}

@end
