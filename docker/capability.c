//
// Created by FlagT on 2022/6/22.
//

#include "capability.h"
#include "../util/output.h"
#include <linux/capability.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <malloc.h>

char const *cap_name[__CAP_BITS] = {
        /* 0 */    "cap_chown",
        /* 1 */    "cap_dac_override",
        /* 2 */    "cap_dac_read_search",
        /* 3 */    "cap_fowner",
        /* 4 */    "cap_fsetid",
        /* 5 */    "cap_kill",
        /* 6 */    "cap_setgid",
        /* 7 */    "cap_setuid",
        /* 8 */    "cap_setpcap",
        /* 9 */    "cap_linux_immutable",
        /* 10 */    "cap_net_bind_service",
        /* 11 */    "cap_net_broadcast",
        /* 12 */    "cap_net_admin",
        /* 13 */    "cap_net_raw",
        /* 14 */    "cap_ipc_lock",
        /* 15 */    "cap_ipc_owner",
        /* 16 */    "cap_sys_module",
        /* 17 */    "cap_sys_rawio",
        /* 18 */    "cap_sys_chroot",
        /* 19 */    "cap_sys_ptrace",
        /* 20 */    "cap_sys_pacct",
        /* 21 */    "cap_sys_admin",
        /* 22 */    "cap_sys_boot",
        /* 23 */    "cap_sys_nice",
        /* 24 */    "cap_sys_resource",
        /* 25 */    "cap_sys_time",
        /* 26 */    "cap_sys_tty_config",
        /* 27 */    "cap_mknod",
        /* 28 */    "cap_lease",
        /* 29 */    "cap_audit_write",
        /* 30 */    "cap_audit_control",
        /* 31 */    "cap_setfcap",
        /* 32 */    "cap_mac_override",
        /* 33 */    "cap_mac_admin",
        /* 34 */    "cap_syslog",
        /* 35 */    "cap_wake_alarm",
        /* 36 */    "cap_block_suspend",
};

void get_current_process_capability(struct __user_cap_header_struct *header, struct __user_cap_data_struct *caps) {
    syscall(__NR_capget, header, caps);
}

int check_cap_sys_admin() {
    printf_wrapper(INFO, "Check if CAP_SYS_ADMIN exists in the current process Capabilities\n");
    printf_wrapper(INFO, "Current Process(%d) Capability:\n", getpid());
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, getpid()};
    struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3] = {};
    get_current_process_capability(&header, (struct __user_cap_data_struct *) &caps);
    printf_wrapper(INFO, "CapEff: 0x%016llx\n", caps->effective);
    printf_wrapper(INFO, "CapInh: 0x%016llx\n", caps->inheritable);
    printf_wrapper(INFO, "CapPrm: 0x%016llx\n", caps->permitted);
    cap_value_t cap;
    const char *sep = "";
    char *effective_capability_str = malloc(512 * sizeof(char));
    memset(effective_capability_str, 0x00 ,512);
    for (cap = 0; (cap < 64) && (caps->effective >> cap); ++cap) {
        if (caps->effective & (1ULL << cap)) {
            char *ptr;
            ptr = (char *) cap_name[cap];
            if (ptr != NULL) {
                strcat(effective_capability_str, sep);
                strcat(effective_capability_str, ptr);
            } else {
                printf_wrapper(WARNING, "Cap to name failed cap: %d\n", cap);
            }
            sep = ",";
        }
    }
    printf_wrapper(INFO, "Effective capability: %s\n", effective_capability_str);
    if (strstr(effective_capability_str, cap_name[21])) {
        free(effective_capability_str);
        printf_wrapper(INFO, "Current process has CAP_SYS_ADMIN\n");
        return 1;
    } else {
        free(effective_capability_str);
        printf_wrapper(INFO, "Current process don't have CAP_SYS_ADMIN\n");
        return 0;
    }
}

