/*
 * Minimal vendored subset of sudo's plugin API, sufficient for an approval
 * plugin. Cross-checked against sudo 1.9.x plugin interface.
 */

#ifndef TSUDO_SUDO_PLUGIN_H
#define TSUDO_SUDO_PLUGIN_H

#include <sys/types.h>

#define SUDO_API_VERSION_MAJOR  1
#define SUDO_API_VERSION_MINOR  18
#define SUDO_API_VERSION        ((SUDO_API_VERSION_MAJOR << 16) | SUDO_API_VERSION_MINOR)
#define SUDO_API_VERSION_GET_MAJOR(v) ((v) >> 16)

#define SUDO_APPROVAL_PLUGIN    4

#define SUDO_CONV_PROMPT_ECHO_OFF   0x0001
#define SUDO_CONV_PROMPT_ECHO_ON    0x0002
#define SUDO_CONV_ERROR_MSG         0x0003
#define SUDO_CONV_INFO_MSG          0x0004
#define SUDO_CONV_PROMPT_MASK       0x0005
#define SUDO_CONV_PROMPT_ECHO_OK    0x1000

struct sudo_conv_message {
    int msg_type;
    int timeout;
    const char *msg;
};

struct sudo_conv_reply {
    char *reply;
};

struct sudo_conv_callback;

typedef int (*sudo_conv_t)(int num_msgs,
                           const struct sudo_conv_message msgs[],
                           struct sudo_conv_reply replies[],
                           struct sudo_conv_callback *callback);

typedef int (*sudo_printf_t)(int msg_type, const char *fmt, ...);

struct approval_plugin {
    unsigned int type;
    unsigned int version;
    int (*open)(unsigned int version, sudo_conv_t conversation,
                sudo_printf_t plugin_printf, char * const settings[],
                char * const user_info[], int submit_optind,
                char * const submit_argv[], char * const submit_envp[],
                char * const plugin_options[], const char **errstr);
    void (*close)(void);
    int (*check)(char * const command_info[], char * const run_argv[],
                 char * const run_envp[], const char **errstr);
    int (*show_version)(int verbose);
};

#endif
