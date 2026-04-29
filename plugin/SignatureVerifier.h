/*
 * SignatureVerifier — wraps SecStaticCodeCheckValidity so the plugin and the
 * PAM module can mutually verify each other's bundle.
 *
 * In release builds (TSUDO_TEAM_ID != "-") a Designated Requirement of
 *   anchor apple generic and certificate leaf[subject.OU] = "<TEAM_ID>"
 * is enforced. In dev builds the requirement is dropped and only signature
 * integrity is checked, allowing ad-hoc signing without an Apple Developer
 * account.
 */

#ifndef TSUDO_SIGNATURE_VERIFIER_H
#define TSUDO_SIGNATURE_VERIFIER_H

#import <Foundation/Foundation.h>

@interface TSudoSignatureVerifier : NSObject

+ (BOOL)verifyPath:(NSString *)path error:(NSError **)error;

@end

#endif
