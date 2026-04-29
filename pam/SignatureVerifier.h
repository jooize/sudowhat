/*
 * SignatureVerifier — see plugin/SignatureVerifier.h. This is a duplicate
 * kept in sync with the plugin copy. A static lib was rejected as added
 * build complexity for no audit benefit; reviewers should diff the two
 * files (they are identical except for the class name and file path
 * comment).
 *
 * The class is named SudoWhatPamSigVerifier rather than
 * SudoWhatSignatureVerifier to avoid an Objective-C runtime "duplicate
 * class" warning when sudo loads both bundles into the same process: each
 * .so registers its own copy of the class with the runtime, the runtime
 * keeps whichever was registered first, and warns about the other.
 * Distinct class names per bundle is the simplest fix.
 */

#ifndef SUDOWHAT_PAM_SIGNATURE_VERIFIER_H
#define SUDOWHAT_PAM_SIGNATURE_VERIFIER_H

#import <Foundation/Foundation.h>

@interface SudoWhatPamSigVerifier : NSObject

+ (BOOL)verifyPath:(NSString *)path error:(NSError **)error;

@end

#endif
