//
// Created by FlagT on 2022/8/20.
//

#include "security.h"
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include "../util/utils.h"


int apparmor_enable_check() {
    char *apparmor_check_path = "/proc/1/attr/apparmor/current";
    char *apparmor_status = (char *) malloc(1024 * 100 * sizeof(char));
    memset(apparmor_status, 0x00, 1024 * 100);
    int ret = read_file(apparmor_check_path, apparmor_status, O_RDONLY);
    if (ret == -1) {
        return -1;
    }
    if (strstr(apparmor_status, "unconfined")) {
        return 1;
    }
    return 0;
}


long int seccomp_enable_check() {
    char *seccomp_check_path = "/proc/1/status";
    char *process_status = (char *) malloc(1024 * 100 * sizeof(char));
    memset(process_status, 0x00, 1024 * 100);
    int ret = read_file(seccomp_check_path, process_status, O_RDONLY);
    if (ret == -1) {
        return -1;
    }
    char **status_line = {0x00};
    status_line = str_split(process_status, '\n');
    long int status = -1;
    while (*status_line) {
        if (strstr(*status_line, "Seccomp:")) {
            char *seccomp_status = malloc(128 * sizeof(char));
            char *ptr;
            memset(seccomp_status, 0x00, 128);
            seccomp_status = str_replace(*status_line, "Seccomp:", "");
            status = strtol(seccomp_status, &ptr, 10);
        }
        *status_line++;
    }
    return status;
}




