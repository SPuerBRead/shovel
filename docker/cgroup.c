//
// Created by FlagT on 2022/7/3.
//

#include <malloc.h>
#include "cgroup.h"
#include <string.h>
#include <fcntl.h>
#include "../util/utils.h"
#include "../util/regex_util.h"

int get_cgroup_id(char *cgroup_id) {
    char *cgroup_path = "/proc/1/cgroup";
    char *cgroup_data = (char *) malloc(1024 * 10 * sizeof(char));
    memset(cgroup_data, 0x00, 1024 * 10);
    read_file(cgroup_path, cgroup_data, O_RDONLY);
    regex_util(cgroup_data,
               "\\d+?:[a-zA-Z0-9]*?:/docker/([a-zA-Z0-9]{64})|(/kubepods\\.slice/kubepods-burstable\\.slice/kubepods-burstable-pod[a-zA-Z0-9_]*?\\.slice/docker-[a-zA-Z0-9]{64}\\.scope)",
               cgroup_id);
}
