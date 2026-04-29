/*
 * SignatureVerifier — see plugin/SignatureVerifier.h. This is a duplicate
 * kept in sync with the plugin copy. A static lib was rejected as added
 * build complexity for no audit benefit; reviewers should diff the two
 * files (they are byte-identical except for the file path comment).
 */

#ifndef TSUDO_PAM_SIGNATURE_VERIFIER_H
#define TSUDO_PAM_SIGNATURE_VERIFIER_H

#import <Foundation/Foundation.h>

@interface TSudoSignatureVerifier : NSObject

+ (BOOL)verifyPath:(NSString *)path error:(NSError **)error;

@end

#endif
