//
// Created by 陶琦 on 2022/7/10.
//

#include <bits/types/FILE.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mount_info.h"
#include "utils.h"


int load_mount_info(char *path, struct mntent *mounts_info[]) {
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
        tmp_ent->mnt_dir = (char *) malloc((strlen(ent->mnt_dir) + 1) * sizeof(char));
        tmp_ent->mnt_fsname = (char *) malloc((strlen(ent->mnt_fsname) + 1) * sizeof(char));
        tmp_ent->mnt_type = (char *) malloc((strlen(ent->mnt_type) + 1) * sizeof(char));
        tmp_ent->mnt_opts = (char *) malloc((strlen(ent->mnt_opts) + 1) * sizeof(char));
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