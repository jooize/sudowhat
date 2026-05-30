#import "SignatureVerifier.h"
#import <Security/Security.h>
#import "Constants.h"

@implementation SW_SIGVERIFIER_CLASS

+ (BOOL)verifyPath:(NSString *)path error:(NSError **)error {
    if (path.length == 0) {
        if (error) *error = [NSError errorWithDomain:@"sudowhat.SignatureVerifier"
                                                code:1
                                            userInfo:@{NSLocalizedDescriptionKey: @"empty path"}];
        return NO;
    }

    NSURL *url = [NSURL fileURLWithPath:path isDirectory:NO];
    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)url,
                                                  kSecCSDefaultFlags,
                                                  &code);
    if (status != errSecSuccess || code == NULL) {
        if (error) *error = [NSError errorWithDomain:NSOSStatusErrorDomain
                                                code:status
                                            userInfo:@{NSLocalizedDescriptionKey:
                                                           [NSString stringWithFormat:@"SecStaticCodeCreateWithPath(%@) failed: %d",
                                                            path, (int)status]}];
        return NO;
    }

    SecRequirementRef requirement = NULL;
    SecCSFlags flags = kSecCSStrictValidate | kSecCSCheckAllArchitectures;

    if (!SUDOWHAT_IS_DEV_BUILD()) {
        NSString *requirementText =
            [NSString stringWithFormat:@"anchor apple generic and certificate leaf[subject.OU] = \"%s\"",
             SUDOWHAT_TEAM_ID];
        status = SecRequirementCreateWithString((__bridge CFStringRef)requirementText,
                                                kSecCSDefaultFlags,
                                                &requirement);
        if (status != errSecSuccess || requirement == NULL) {
            CFRelease(code);
            if (error) *error = [NSError errorWithDomain:NSOSStatusErrorDomain
                                                    code:status
                                                userInfo:@{NSLocalizedDescriptionKey: @"failed to compile code requirement"}];
            return NO;
        }
    } else {
        /* Dev build: integrity-only — no requirement, basic-validate. */
        flags = kSecCSBasicValidateOnly;
    }

    CFErrorRef cfErr = NULL;
    status = SecStaticCodeCheckValidityWithErrors(code, flags, requirement, &cfErr);

    if (requirement) CFRelease(requirement);
    CFRelease(code);

    if (status != errSecSuccess) {
        if (error) {
            NSString *desc = cfErr ? [(__bridge NSError *)cfErr localizedDescription]
                                   : [NSString stringWithFormat:@"SecStaticCodeCheckValidity failed: %d", (int)status];
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain
                                         code:status
                                     userInfo:@{NSLocalizedDescriptionKey: desc}];
        }
        if (cfErr) CFRelease(cfErr);
        return NO;
    }
    if (cfErr) CFRelease(cfErr);
    return YES;
}

@end
