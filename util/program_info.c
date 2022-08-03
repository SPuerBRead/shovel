//
// Created by FlagT on 2022/6/25.
//

#include "program_info.h"

#include <stdio.h>
#include <stdlib.h>

#define PROGRAM_NAME "Shovel"
#define VERSION "1.1"


void usage(char *args0) {
    printf("usage: %s [options ...]\n"
           "\n"
           "Options:\n"
           "Options of program\n"
           "    -h, --help                           show help message\n"
           "    -v, --version                        show program version\n"
           "Options of escape\n"
           "    -r, --release-agent                  escape by release-agent\n"
           "    -d, --devices-allow                  escape by devices-allow\n"
           "    -u, --cve-2022-0492                  get cap_sys_admin by cve-2022-0492 and return new namespace bash\n"
           "Options of other\n"
           "    -p, --container_path=xxx             manually specify path of container in host,use this parameter if program can't get it automatically\n"
           "    -m, --mode=xxx                       the mode that needs to be returned after a successful escape { exec | shell | reverse | backdoor }\n"
           "    -c, --command=xxx                    set command in exec mode\n"
           "    -I, --ip                             set ip address in reverse mode\n"
           "    -P, --port                           set port in reverse mode\n"
           "    -B, --backdoor_path                  set backdoor file path\n"
           "    -y, --assumeyes                      automatically answer yes for all questions"
           "\n"
           "Mode (-m) type guide\n"
           "    exec:     run a single command and return the result\n"
           "    shell:    get host shell in current console\n"
           "    reverse:  reverse shell to remote listening address\n"
           "    backdoor: put a backdoor to the host and execute\n",
           args0);
    exit(EXIT_SUCCESS);
}

void print_version() {
    printf("%s version: %s, %s %s\n", PROGRAM_NAME, VERSION, __DATE__, __TIME__);
    exit(EXIT_SUCCESS);
}