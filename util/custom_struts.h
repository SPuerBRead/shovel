//
// Created by 陶琦 on 2022/6/26.
//

#ifndef SHOVEL_CUSTOM_STRUTS_H
#define SHOVEL_CUSTOM_STRUTS_H

#endif //SHOVEL_CUSTOM_STRUTS_H


enum ATTACK_TYPE {
    RELEASE_AGENT,
};

enum ATTACK_MODE {
    EXEC,
    SHELL,
    REVERSE
};

struct ATTACK_INFO {
    int attack_type;
    int attack_mode;
    char *command;
    char *ip;
    char *port;
} attack_info;


struct RELEASE_AGENT_ATTACK_INFO {
    char *exp_path;
    char *container_path_in_host;
    char *controller_path;
    char *mount_path;
    char *output_path_in_container;
} release_agent_attack_info;