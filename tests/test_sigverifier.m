/*
 * test_sigverifier.m - guards the release-build code requirement.
 *
 * The requirement text is only ever exercised at runtime inside sudo on a
 * release-signed install, so a syntax error or an accidentally-permissive
 * clause would surface as bricked (or silently weakened) sudo auth. These
 * tests pin it offline, without needing a Developer ID certificate:
 *
 *   1. The text compiles under SecRequirementCreateWithString for every
 *      bundle identifier the plugins pin.
 *   2. A requirement for a nonexistent team does NOT validate an arbitrary
 *      Apple-signed binary (the check is not vacuously permissive).
 *   3. Positive control: the same validation machinery DOES pass that
 *      binary against a requirement it genuinely satisfies (anchor apple),
 *      so test 2's failure is the requirement rejecting, not the plumbing
 *      erroring.
 *
 * Dev-mode verifyPath behavior (no requirement) is compile-time selected
 * via SUDOWHAT_TEAM_ID and not reachable here; the requirement builder is
 * a pure function of its arguments, so it is testable in any build mode.
 */

#import "sw_test.h"
#import <Security/Security.h>
#import "../shared/SignatureVerifier.h"
#import "../shared/Constants.h"

/* An Apple-signed binary present on every macOS install. */
static NSString *const kAppleBinary = @"/bin/ls";

static SecStaticCodeRef static_code(NSString *path) {
    SecStaticCodeRef code = NULL;
    NSURL *url = [NSURL fileURLWithPath:path isDirectory:NO];
    OSStatus st = SecStaticCodeCreateWithPath((__bridge CFURLRef)url,
                                              kSecCSDefaultFlags, &code);
    return (st == errSecSuccess) ? code : NULL;
}

static SecRequirementRef compile_req(NSString *text) {
    SecRequirementRef req = NULL;
    OSStatus st = SecRequirementCreateWithString((__bridge CFStringRef)text,
                                                 kSecCSDefaultFlags, &req);
    return (st == errSecSuccess) ? req : NULL;
}

int main(void) {
    @autoreleasepool {
        /* (1) The requirement text compiles for each pinned identifier. */
        NSArray<NSString *> *idents = @[ @SUDOWHAT_PLUGIN_IDENT,
                                         @SUDOWHAT_PAM_IDENT,
                                         @SUDOWHAT_AUDIT_IDENT ];
        for (NSString *ident in idents) {
            NSString *text =
                [SW_SIGVERIFIER_CLASS requirementTextForTeamID:@"ABCDE12345"
                                                    identifier:ident];
            SecRequirementRef req = compile_req(text);
            NSString *name = [@"requirement compiles: "
                                 stringByAppendingString:ident];
            OK(req != NULL, name.UTF8String);
            if (req) CFRelease(req);
        }

        /* The text pins all five clauses (belt and braces against an edit
         * that drops one but still compiles). */
        NSString *text =
            [SW_SIGVERIFIER_CLASS requirementTextForTeamID:@"ABCDE12345"
                                                identifier:@SUDOWHAT_PLUGIN_IDENT];
        OK([text containsString:@"anchor apple generic"], "pins Apple anchor");
        OK([text containsString:@"certificate 1[field.1.2.840.113635.100.6.2.6]"],
           "pins Developer ID CA marker");
        OK([text containsString:@"certificate leaf[field.1.2.840.113635.100.6.1.13]"],
           "pins Developer ID Application leaf marker");
        OK([text containsString:@"certificate leaf[subject.OU] = \"ABCDE12345\""],
           "pins team ID");
        OK([text containsString:@"identifier \"" @SUDOWHAT_PLUGIN_IDENT @"\""],
           "pins signing identifier");

        /* (2) + (3): validate an Apple-signed binary against our requirement
         * (must fail: wrong team, wrong chain flavor, wrong identifier) and
         * against `anchor apple` (must pass: positive control).
         *
         * The positive control runs FIRST and gates the rejection test:
         * anchor evaluation needs trustd, which a sandboxed test runner may
         * block (every check then errors CSSMERR_TP_NOT_TRUSTED, and the
         * rejection test would "pass" vacuously). When the environment
         * cannot evaluate anchors at all, both are skipped loudly rather
         * than failed -- the syntax guards above are the always-on part. */
        SecStaticCodeRef code = static_code(kAppleBinary);
        OK(code != NULL, "SecStaticCode for /bin/ls");
        if (code != NULL) {
            SecCSFlags flags = kSecCSStrictValidate | kSecCSCheckAllArchitectures;

            SecRequirementRef apple = compile_req(@"anchor apple");
            OK(apple != NULL, "anchor-apple requirement compiles");
            BOOL trustEvalWorks = NO;
            if (apple) {
                trustEvalWorks =
                    (SecStaticCodeCheckValidityWithErrors(code, flags, apple,
                                                          NULL) == errSecSuccess);
                CFRelease(apple);
            }

            if (!trustEvalWorks) {
                fprintf(stderr,
                        "SKIP trust-evaluation tests: this environment cannot "
                        "evaluate `anchor apple` for /bin/ls (sandboxed "
                        "runner without trustd access?). Re-run unsandboxed "
                        "to exercise them.\n");
            } else {
                OK(YES, "positive control: anchor apple accepts /bin/ls");
                SecRequirementRef ours = compile_req(text);
                OK(ours != NULL, "our requirement compiles for validation");
                if (ours) {
                    OSStatus st = SecStaticCodeCheckValidityWithErrors(code, flags,
                                                                       ours, NULL);
                    OK(st != errSecSuccess,
                       "our requirement rejects an Apple-signed binary");
                    CFRelease(ours);
                }
            }
            CFRelease(code);
        }

        SW_SUMMARY("test_sigverifier");
    }
}
