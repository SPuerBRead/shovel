//
// Created by FlagT on 2022/6/22.
//

#include "path.h"
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <mntent.h>
#include <sys/stat.h>
#include "../util/regex_util.h"
#include "../util/output.h"

enum STORAGE_DRIVERS{
    DEVICE_MAPPER = 1,
    AUFS = 2,
    BTRFS = 3,
    VFS = 4,
    ZFS = 5,
    OVERLAYFS = 6,
    UNKNOWN = 7
};

int load_mount_info(char *path) {
    struct mntent *ent;
    FILE *mounts_file;
    mounts_file = setmntent(path, "r");
    if (mounts_file == NULL) {
        perror("setmntent");
        exit(1);
    }
    int count = 0;
    while (NULL != (ent = getmntent(mounts_file))) {
        struct mntent *tmp_ent = (struct mntent *) malloc(sizeof(struct mntent));
        memcpy(tmp_ent, ent, sizeof(struct mntent));
        tmp_ent->mnt_dir = (char *) malloc(strlen(ent->mnt_dir) * sizeof(char));
        tmp_ent->mnt_fsname = (char *) malloc(strlen(ent->mnt_fsname) * sizeof(char));
        tmp_ent->mnt_type = (char *) malloc(strlen(ent->mnt_type) * sizeof(char));
        tmp_ent->mnt_opts = (char *) malloc(strlen(ent->mnt_opts) * sizeof(char));
        strcpy(tmp_ent->mnt_dir, ent->mnt_dir);
        strcpy(tmp_ent->mnt_fsname, ent->mnt_fsname);
        strcpy(tmp_ent->mnt_type, ent->mnt_type);
        strcpy(tmp_ent->mnt_opts, ent->mnt_opts);
        mounts_info[count] = tmp_ent;
        count += 1;
    }
    endmntent(mounts_file);
    return count;
}

int get_storage_driver_type() {
    char *proc_mounts_path = "/proc/mounts";
    char *mtab_path = "/etc/mtab";
    char *vfs_mount_path = "/proc/1/mountinfo";
    int length;
    if (access(proc_mounts_path, F_OK) == 0 && ((length = load_mount_info(proc_mounts_path)) != 0)) {
        for (int i = 0; i < length; i++) {
            if (strcmp(mounts_info[i]->mnt_type, "overlay") == 0) {
                printf_wrapper(INFO, "Storage driver type: overlayfs\n");
                return OVERLAYFS;
            } else if (strstr(mounts_info[i]->mnt_fsname, "/dev/mapper/docker")) {
                printf_wrapper(INFO, "Storage driver type: devicemapper\n");
                return DEVICE_MAPPER;
            } else if (strcmp(mounts_info[i]->mnt_type, "zfs") == 0) {
                printf_wrapper(INFO, "Storage driver type: zfs\n");
                return ZFS;
            } else if (strcmp(mounts_info[i]->mnt_type, "aufs") == 0) {
                printf_wrapper(INFO, "Storage driver type: aufs\n");
                return AUFS;
            } else if (strcmp(mounts_info[i]->mnt_type, "btrfs") == 0) {
                printf_wrapper(INFO, "Storage driver type: btrfs\n");
                return BTRFS;
            }
        }
    }
    if (access(mtab_path, F_OK) == 0 && ((length = load_mount_info(proc_mounts_path)) != 0)) {
        for (int i = 0; i < length; i++) {
            if (strcmp(mounts_info[i]->mnt_type, "overlay") == 0) {
                printf_wrapper(INFO, "Storage driver type: overlayfs\n");
                return OVERLAYFS;
            } else if (strstr(mounts_info[i]->mnt_fsname, "/dev/mapper/docker")) {
                printf_wrapper(INFO, "Storage driver type: devicemapper\n");
                return DEVICE_MAPPER;
            } else if (strcmp(mounts_info[i]->mnt_type, "zfs") == 0) {
                printf_wrapper(INFO, "Storage driver type: zfs\n");
                return ZFS;
            } else if (strcmp(mounts_info[i]->mnt_type, "aufs") == 0) {
                printf_wrapper(INFO, "Storage driver type: aufs\n");
                return AUFS;
            } else if (strcmp(mounts_info[i]->mnt_type, "btrfs") == 0) {
                printf_wrapper(INFO, "Storage driver type: btrfs\n");
                return BTRFS;
            }
        }
    }
    if (access(vfs_mount_path, F_OK) == 0 && ((length = load_mount_info(vfs_mount_path)) != 0)) {
        for (int i = 0; i < length; i++) {
            if (strstr(mounts_info[i]->mnt_opts, "/var/lib/docker/vfs")) {
                printf_wrapper(INFO,"Storage driver type: vfs\n");
                return VFS;
            }
        }

    }
    return UNKNOWN;
}

void get_container_path_in_host(char *container_path_in_host) {
    switch (get_storage_driver_type()) {
        case OVERLAYFS: {
            char *regex_match_result = (char *) malloc(256 * sizeof(char));
            for (int i = 0; i < 1024; i++) {
                if (mounts_info[i] != NULL) {
                    if (strcmp(mounts_info[i]->mnt_type, "overlay") == 0) {
                        regex_util(mounts_info[i]->mnt_opts, ".*?perdir=(.*?),", regex_match_result);
                        if (strcmp(regex_match_result, "") != 0) {
                            strcpy(container_path_in_host, regex_match_result);
                            printf_wrapper(INFO,"Container path in host: %s\n", container_path_in_host);
                            break;
                        } else {
                            continue;
                        }
                    }
                }
            }
            break;
        }
        case DEVICE_MAPPER: {
            char *regex_match_result = (char *) malloc(256 * sizeof(char));
            for (int i = 0; i < 1024; i++) {
                if (mounts_info[i] != NULL) {
                    if (strstr(mounts_info[i]->mnt_fsname, "/dev/mapper/docker")) {
                        regex_util(mounts_info[i]->mnt_fsname, "dev/mapper/docker-[0-9]*:[0-9]*-[0-9]*-(.*)",
                                   regex_match_result);
                        if (strcmp(regex_match_result, "") != 0) {
                            strcpy(container_path_in_host, "/var/lib/docker/devicemapper/mnt/");
                            strcat(container_path_in_host, regex_match_result);
                            strcat(container_path_in_host, "/rootfs");
                            printf_wrapper(INFO, "Container path in host: %s\n", container_path_in_host);
                            break;
                        } else {
                            continue;
                        }
                    }
                }
            }
            break;
        }
        case VFS: {
            for (int i = 0; i < 1024; i++) {
                if (mounts_info[i] != NULL) {
                    if (strstr(mounts_info[i]->mnt_opts, "/var/lib/docker/vfs")) {
                        strcpy(container_path_in_host, mounts_info[i]->mnt_opts);
                        printf_wrapper(INFO, "Container path in host: %s\n", container_path_in_host);
                        break;
                    } else {
                        continue;
                    }
                }
            }
            break;
        }
        case ZFS: {
            char *regex_match_result = (char *) malloc(512 * sizeof(char));
            for (int i = 0; i < 1024; i++) {
                if (mounts_info[i] != NULL) {
                    if (strcmp(mounts_info[i]->mnt_type, "zfs") == 0) {
                        regex_util(mounts_info[i]->mnt_fsname, "/([a-z0-9]*$)", regex_match_result);
                        if (strlen(regex_match_result) == 64) {
                            strcpy(container_path_in_host, "/var/lib/docker/zfs/graph/");
                            strcat(container_path_in_host, regex_match_result);
                            printf_wrapper(INFO,"Container path in host: %s\n", container_path_in_host);
                            break;
                        } else {
                            continue;
                        }
                    }
                }
            }
            break;
        }
        case AUFS: {
            char *regex_match_result = (char *) malloc(256 * sizeof(char));
            char *si_id = (char *) malloc(256 * sizeof(char));
            char *aufs_read_path = (char *) malloc(256 * sizeof(char));
            for (int i = 0; i < 1024; i++) {
                if (mounts_info[i] != NULL) {
                    if (strcmp(mounts_info[i]->mnt_type, "aufs") == 0) {
                        regex_util(mounts_info[i]->mnt_opts, "si=([a-z0-9]*),", si_id);
                        if (strcmp(si_id, "") != 0) {
                            strcpy(aufs_read_path, "/sys/fs/aufs/si_");
                            strcat(aufs_read_path, si_id);
                            strcat(aufs_read_path, "/br0");
                            int fd;
                            struct stat s;
                            stat(aufs_read_path, &s);
                            char *aufs_path_buffer = malloc(s.st_size * sizeof(char));
                            fd = open(aufs_read_path, O_RDONLY);
                            read(fd, aufs_path_buffer, s.st_size);
                            regex_util(aufs_path_buffer, "^(.*?)=", regex_match_result);
                            strcpy(container_path_in_host, regex_match_result);
                            printf_wrapper(INFO,"Container path in host: %s\n", container_path_in_host);
                            close(fd);
                            break;
                        } else {
                            continue;
                        }
                    }
                }
            }
            break;
        }
        case BTRFS: {
            char *regex_match_result = (char *) malloc(256 * sizeof(char));
            for (int i = 0; i < 1024; i++) {
                if (mounts_info[i] != NULL) {
                    if (strcmp(mounts_info[i]->mnt_type, "btrfs") == 0) {
                        regex_util(mounts_info[i]->mnt_opts, "subvol=(/btrfs/subvolumes/[a-z0-9]{64})",
                                   regex_match_result);
                        if (strcmp(regex_match_result, "") != 0) {
                            strcpy(container_path_in_host, "/var/lib/docker");
                            strcat(container_path_in_host, regex_match_result);
                            printf_wrapper(INFO,"Container path in host: %s\n", container_path_in_host);
                            break;
                        } else {
                            continue;
                        }
                    }
                }
            }
            break;
        }
    }
}
