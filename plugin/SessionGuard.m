#import "SessionGuard.h"
#import <SystemConfiguration/SystemConfiguration.h>

@implementation SudoWhatSessionGuard

+ (BOOL)isInvokingUserActiveConsole:(uid_t)invokingUid {
    uid_t consoleUid = (uid_t)-1;
    CFStringRef user = SCDynamicStoreCopyConsoleUser(NULL, &consoleUid, NULL);
    if (user) CFRelease(user);

    if (consoleUid == (uid_t)-1) return NO;
    if (consoleUid == 0) return NO;
    return consoleUid == invokingUid;
}

@end
