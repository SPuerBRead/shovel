//
// Created by FlagT on 2022/6/25.
//

#include "utils.h"
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "output.h"


int remove_dir(const char *dir) {
    char cur_dir[] = ".";
    char up_dir[] = "..";
    char dir_name[128];
    DIR *dirp;
    struct dirent *dp;
    struct stat dir_stat;

    if (0 != access(dir, F_OK)) {
        printf_wrapper(ERROR, "No permission to access dir %s", dir);
        return -1;
    }

    if (0 > stat(dir, &dir_stat)) {
        printf_wrapper(ERROR, "Get directory %s stat error, remove %s failed", dir, dir);
        return -1;
    }

    if (S_ISREG(dir_stat.st_mode)) {
        remove(dir);
    } else if (S_ISDIR(dir_stat.st_mode)) {
        dirp = opendir(dir);
        while ((dp = readdir(dirp)) != NULL) {
            if ((0 == strcmp(cur_dir, dp->d_name)) || (0 == strcmp(up_dir, dp->d_name))) {
                continue;
            }

            sprintf(dir_name, "%s/%s", dir, dp->d_name);
            remove_dir(dir_name);
        }
        closedir(dirp);
        rmdir(dir);
    } else {
        printf_wrapper(ERROR, "Unknown dir %s type, remove %s failed", dir, dir);
        return -1;
    }
    return 0;
}

int remove_file(const char *file_path) {
    struct stat file_stat;

    if (0 != access(file_path, F_OK)) {
        printf_wrapper(ERROR, "No permission to access file %s", file_path);
        return -1;
    }

    if (0 > stat(file_path, &file_stat)) {
        printf_wrapper(ERROR, "Get file %s stat error, remove %s failed", file_path, file_path);
        return -1;
    }

    if (S_ISREG(file_stat.st_mode)) {
        remove(file_path);
    } else {
        return -1;
    }
    return 0;
}