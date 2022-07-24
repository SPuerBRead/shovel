//
// Created by FlagT on 2022/7/10.
//

#include "dev.h"
#include "../util/mount_info.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "../util/custom_struts.h"
#include "../util/utils.h"

int get_host_dev_major_minor() {
    char *mount_resolv_keyword = "/resolv.conf";
    char *mount_hostname_keyword = "/hostname";
    char *mount_host_keyword = "/hosts";
    char *get_dev_major_minor_path = "/proc/1/mountinfo";

    char *mountinfo_buffer = malloc((1024 * 1024) * sizeof(char));
    memset(mountinfo_buffer, 0x00, (1024 * 1024));
    read_file(get_dev_major_minor_path, mountinfo_buffer, O_RDONLY);
    char **mountinfo_line = {0x00};
    mountinfo_line = str_split(mountinfo_buffer, '\n');
    while (*mountinfo_line) {
        char **mountinfo = {0x00};
        mountinfo = str_split(*mountinfo_line, ' ');
        if (strstr(mountinfo[3], mount_resolv_keyword) || strstr(mountinfo[3], mount_hostname_keyword) ||
            strstr(mountinfo[3], mount_host_keyword)) {
            char **major_minor = {0x00};
            major_minor = str_split(mountinfo[2], ':');
            host_dev_attribute.major = strtol(major_minor[0], NULL, 0);
            host_dev_attribute.minor = strtol(major_minor[1], NULL, 0);
            host_dev_attribute.fstype = malloc(10 * sizeof(char));
            strcpy(host_dev_attribute.fstype, mountinfo[7]);
            return 0;
        } else {
            *mountinfo_line++;
        }
    }
    return -1;
}