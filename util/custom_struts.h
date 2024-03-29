//
// Created by FlagT on 2022/6/26.
//

#ifndef SHOVEL_CUSTOM_STRUTS_H
#define SHOVEL_CUSTOM_STRUTS_H

#endif //SHOVEL_CUSTOM_STRUTS_H


enum ATTACK_TYPE {
    RELEASE_AGENT,
    DEVICE_ALLOW,
    CVE_2022_0492,
};

enum ATTACK_MODE {
    EXEC,
    SHELL,
    REVERSE,
    BACKDOOR
};

struct ATTACK_INFO {
    int attack_type;
    int attack_mode;
    char *command;
    char *ip;
    char *port;
    char *backdoor_path;
    char *container_path;
} attack_info;


struct RELEASE_AGENT_ATTACK_INFO {
    char *exp_path;
    char *container_path_in_host;
    char *controller_path;
    char *mount_path;
    char *output_path_in_container;
    int use_cve_2022_0492;
} release_agent_attack_info;

struct DEVICE_ALLOW_ATTACK_INFO {
    char *cgroup_id;
    char *host_filesystem_mount_path;
    char *crontab_path;
    char *exp;
    char *host_dev_path;
    char *device_allow_path;
    char *mount_path;
} device_allow_attack_info;

struct HOST_DEV_ATTRIBUTE {
    int major;
    int minor;
    char *fstype;
} host_dev_attribute;