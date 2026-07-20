/*
 * Minimal vendored subset of sudo's plugin API, sufficient for an approval
 * plugin. Cross-checked against sudo 1.9.x plugin interface.
 */

#ifndef SUDOWHAT_SUDO_PLUGIN_H
#define SUDOWHAT_SUDO_PLUGIN_H

#include <sys/types.h>

#define SUDO_API_VERSION_MAJOR  1
#define SUDO_API_VERSION_MINOR  18
#define SUDO_API_VERSION        ((SUDO_API_VERSION_MAJOR << 16) | SUDO_API_VERSION_MINOR)
#define SUDO_API_VERSION_GET_MAJOR(v) ((v) >> 16)

#define SUDO_APPROVAL_PLUGIN    4
#define SUDO_AUDIT_PLUGIN       3

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

/* Audit plugin API (SUDO_AUDIT_PLUGIN, type 3). Cross-checked against
 * sudo-project/sudo include/sudo_plugin.h. The audit open() is called BEFORE
 * any other sudo plugin API function (sudo_plugin(8)), which is exactly why an
 * audit plugin is the single, earliest place to display the command on the tty:
 * it runs before the policy plugin's check_policy (where PAM collects the
 * password) on every path. Its signature is identical to approval open() plus
 * submit_optind — which the approval open() already receives — so the two share
 * one shape.
 *
 * accept() delivers the RESOLVED command_info[] / run_argv[] post-auth (the
 * future resolved-path last-look feature). reject()/error() report a denied or
 * errored run. close() gets the exit disposition.
 *
 * The struct tail (show_version, register_hooks, deregister_hooks, event_alloc)
 * MUST be present: sudo reads these members by offset at API >= 1.15, so a
 * truncated struct would have sudo read past our object. We vendor the full
 * layout and NULL the optional members we do not implement. sudo_hook and
 * sudo_plugin_event are only referenced through pointers here, so forward
 * declarations suffice. */
struct sudo_hook;
struct sudo_plugin_event;

struct audit_plugin {
    unsigned int type;
    unsigned int version;
    int (*open)(unsigned int version, sudo_conv_t conversation,
                sudo_printf_t plugin_printf, char * const settings[],
                char * const user_info[], int submit_optind,
                char * const submit_argv[], char * const submit_envp[],
                char * const plugin_options[], const char **errstr);
    void (*close)(int status_type, int status);
    int (*accept)(const char *plugin_name, unsigned int plugin_type,
                  char * const command_info[], char * const run_argv[],
                  char * const run_envp[], const char **errstr);
    int (*reject)(const char *plugin_name, unsigned int plugin_type,
                  const char *audit_msg, char * const command_info[],
                  const char **errstr);
    int (*error)(const char *plugin_name, unsigned int plugin_type,
                 const char *audit_msg, char * const command_info[],
                 const char **errstr);
    int (*show_version)(int verbose);
    void (*register_hooks)(int version,
                           int (*register_hook)(struct sudo_hook *hook));
    void (*deregister_hooks)(int version,
                             int (*deregister_hook)(struct sudo_hook *hook));
    struct sudo_plugin_event *(*event_alloc)(void);
};

#endif
