#import "SignatureVerifier.h"
#import <Security/Security.h>
#import "Constants.h"

@implementation SW_SIGVERIFIER_CLASS

/* Release-build code requirement. Four clauses, each load-bearing:
 *
 *   anchor apple generic
 *     The chain terminates at Apple's root CA (Developer ID, App Store,
 *     and Apple's own code all satisfy this alone -- hence the next two).
 *   certificate 1[field.1.2.840.113635.100.6.2.6]
 *     The intermediate is Apple's "Developer ID Certification Authority"
 *     (marker OID present). Excludes App Store / Apple-internal chains.
 *   certificate leaf[field.1.2.840.113635.100.6.1.13]
 *     The leaf is a "Developer ID Application" certificate (marker OID
 *     present). Excludes same-team Apple Development / Mac Installer
 *     certificates, which carry the same subject.OU but are easier to
 *     obtain (any team member can mint a development cert).
 *   certificate leaf[subject.OU] = "<team>"
 *     The Developer ID belongs to THIS team, not merely any developer.
 *   identifier "<ident>"
 *     The signature's embedded identifier names THIS bundle, so another
 *     binary signed by the same team cannot stand in for it. The expected
 *     identifiers are compile-time constants (Constants.h) matching the
 *     `codesign --identifier` values the Makefile sign target sets.
 *
 * The team ID and identifier are compile-time constants, never runtime
 * input, so no escaping of the quoted strings is needed. Guarded by
 * tests/test_sigverifier.m: the text must compile via
 * SecRequirementCreateWithString, and must NOT validate an
 * arbitrary Apple-signed binary. */
+ (NSString *)requirementTextForTeamID:(NSString *)teamID
                            identifier:(NSString *)identifier {
    return [NSString stringWithFormat:
            @"anchor apple generic"
             " and certificate 1[field.1.2.840.113635.100.6.2.6]"
             " and certificate leaf[field.1.2.840.113635.100.6.1.13]"
             " and certificate leaf[subject.OU] = \"%@\""
             " and identifier \"%@\"",
            teamID, identifier];
}

+ (BOOL)verifyPath:(NSString *)path
        identifier:(NSString *)identifier
             error:(NSError **)error {
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
        /* Fail closed: a release build must always pin an identifier. */
        if (identifier.length == 0) {
            CFRelease(code);
            if (error) *error = [NSError errorWithDomain:@"sudowhat.SignatureVerifier"
                                                    code:2
                                                userInfo:@{NSLocalizedDescriptionKey: @"empty expected identifier"}];
            return NO;
        }
        NSString *requirementText =
            [self requirementTextForTeamID:@SUDOWHAT_TEAM_ID
                                identifier:identifier];
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
