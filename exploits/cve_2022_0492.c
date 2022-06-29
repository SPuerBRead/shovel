//
// Created by FlagT on 2022/6/22.
//

#define _GNU_SOURCE

#include "cve_2022_0492.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include "../util/output.h"
#include "../docker/capability.h"

#include <sched.h>
#include <string.h>

int check_max_user_namespace() {
    char *max_user_namespace_path = "/proc/sys/user/max_user_namespaces";
    int fd;
    char *max_user_namespace_path_buffer = malloc(64 * sizeof(char));
    fd = open(max_user_namespace_path, O_RDONLY);
    read(fd, max_user_namespace_path_buffer, 1024);
    int max_user_namespaces = strtol(max_user_namespace_path_buffer, NULL, 0);
    return max_user_namespaces;
}

void unshare_ns() {
    int flags = CLONE_NEWUSER | CLONE_NEWCGROUP | CLONE_NEWNS;
    int ret = unshare(flags);
    if (ret == -1)
        printf_wrapper(ERROR, "Create user namespace failed\n");
}

void set_uid() {
    const char *setgroups_path = "/proc/self/setgroups";
    const char *uid_map_path = "/proc/self/uid_map";
    const char *gid_map_path = "/proc/self/gid_map";
    int fd;
    fd = open(setgroups_path, O_WRONLY);
    write(fd, "deny", 5);
    close(fd);
    fd = open(uid_map_path, O_WRONLY);
    write(fd, "0 0 1", 5);
    close(fd);
    fd = open(gid_map_path, O_WRONLY);
    write(fd, "0 0 1", 5);
    close(fd);
}


int cve_2022_0294() {
    printf_wrapper(INFO, "Check max_user_namespace to see if user namespace creation is allowed\n");
    int max_user_namespaces = check_max_user_namespace();
    if (max_user_namespaces != 0) {
        printf_wrapper(INFO, "Number of max_user_namespace is: %d\n", max_user_namespaces);
        printf_wrapper(INFO, "Try create mount/user/cgroup namespace\n");
        unshare_ns();
        printf_wrapper(INFO, "Set current user nobody to root\n");
        set_uid();
        int sys_admin = check_cap_sys_admin();
        if (sys_admin == 0) {
            printf_wrapper(INFO, "Attack by CVE-2022-0492 failed\n");
            return 0;
        } else {
            return 1;
        }
    } else {
        printf_wrapper(ERROR, "Max user namespace is 0, can't create user namespace\n");
        return 0;
    }
}
