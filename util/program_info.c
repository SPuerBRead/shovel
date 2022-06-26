//
// Created by FlagT on 2022/6/25.
//

#include "program_info.h"

#include <stdio.h>
#include <stdlib.h>

#define PROGRAM_NAME "Shovel"
#define VERSION "1.0"


void usage(char *args0) {
    printf("usage: %s [args ...]\n"
           "args of program\n"
           "  -h, --help                                show help message\n"
           "  -v, --version                             show program version\n"
           "args of escape\n"
           "  -a, --auto-escape                         automatically select the escape method and complete the attack according to the actual situation\n"
           "  -r, --release-agent                       escape by release-agent\n"
           "  -d, --devices-allow                       escape by devices-allow\n"
           "  -u, --cve-2022-0492                       get cap_sys_admin by cve-2022-0492\n"
           "args of other\n"
           "  -p, --path=xxx                            manually specify path of container in host,use this parameter if program can't get it automatically\n"
           "  -m, --mode={exec | shell | reverse}       the mode that needs to be returned after a successful escape\n"
           "  -c, --command=xxx                            set command in exec mode\n"
           "  -I, --ip                                  set ip address in reverse mode\n"
           "  -P, --port                                set port in reverse mode\n"
           "  -b, --bash                                enter the new namespace bash after the attack is complete,only takes effect when the '-u' is specified\n"
           "\n"
           "mode(-m) type guide\n"
           "  exec: run a single command and return the result\n"
           "  shell:   get host shell in current console\n"
           "  reverse: reverse shell to remote listening address\n",
           args0);
    exit(EXIT_SUCCESS);
}

void print_version() {
    printf("%s version: %s, %s %s\n", PROGRAM_NAME, VERSION, __DATE__, __TIME__);
    exit(EXIT_SUCCESS);
}