/*
 * SudoConfChecker — confirms /etc/sudo.conf contains a non-comment Plugin
 * line naming the expected approval-plugin symbol at the expected absolute
 * path. Used by pam_sudowhat so a missing or rerouted plugin entry fails
 * sudo at the PAM stage.
 */

#ifndef SUDOWHAT_SUDO_CONF_CHECKER_H
#define SUDOWHAT_SUDO_CONF_CHECKER_H

#import <Foundation/Foundation.h>

@interface SudoWhatConfChecker : NSObject

+ (BOOL)verifyConfPath:(NSString *)confPath
        expectedSymbol:(NSString *)symbol
          expectedPath:(NSString *)pluginPath
                 error:(NSError **)error;

@end

#endif
