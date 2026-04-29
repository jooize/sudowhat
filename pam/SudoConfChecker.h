/*
 * SudoConfChecker — confirms /etc/sudo.conf contains a non-comment Plugin
 * line naming the expected approval-plugin symbol at the expected absolute
 * path. Used by pam_tsudo so a missing or rerouted plugin entry fails sudo
 * at the PAM stage.
 */

#ifndef TSUDO_SUDO_CONF_CHECKER_H
#define TSUDO_SUDO_CONF_CHECKER_H

#import <Foundation/Foundation.h>

@interface TSudoSudoConfChecker : NSObject

+ (BOOL)verifyConfPath:(NSString *)confPath
        expectedSymbol:(NSString *)symbol
          expectedPath:(NSString *)pluginPath
                 error:(NSError **)error;

@end

#endif
