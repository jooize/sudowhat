/*
 * SignatureVerifier — wraps SecStaticCodeCheckValidity so the plugin and the
 * PAM module can mutually verify each other's bundle. Single source of truth:
 * both bundles compile this one file (and shared/SignatureVerifier.m).
 *
 * In release builds (SUDOWHAT_TEAM_ID != "-") a Designated Requirement of
 *   anchor apple generic and certificate leaf[subject.OU] = "<TEAM_ID>"
 * is enforced. In dev builds the requirement is dropped and only signature
 * integrity is checked, allowing ad-hoc signing without an Apple Developer
 * account.
 *
 * Why a build-time class-name macro: sudo loads both bundles into the same
 * process, and two Objective-C classes with the same name trigger a runtime
 * "duplicate class" warning ("implemented in both ... one of the duplicates
 * must be removed or renamed") plus undefined dispatch — for the code that
 * anchors mutual trust, that ambiguity is unacceptable. So the class name is
 * injected per target via -DSW_SIGVERIFIER_CLASS: the plugin bundle compiles
 * this source as SudoWhatSignatureVerifier, the PAM bundle as
 * SudoWhatPamSigVerifier. One source, two distinct binary-level classes. The
 * #error below fails the build loudly if a target forgets to define it (which
 * would otherwise silently reintroduce the collision).
 */

#ifndef SUDOWHAT_SIGNATURE_VERIFIER_H
#define SUDOWHAT_SIGNATURE_VERIFIER_H

#import <Foundation/Foundation.h>

#ifndef SW_SIGVERIFIER_CLASS
#error "SW_SIGVERIFIER_CLASS must be defined per target (e.g. -DSW_SIGVERIFIER_CLASS=SudoWhatSignatureVerifier)"
#endif

@interface SW_SIGVERIFIER_CLASS : NSObject

+ (BOOL)verifyPath:(NSString *)path error:(NSError **)error;

@end

#endif
