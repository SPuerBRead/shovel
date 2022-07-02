//
// Created by FlagT on 2022/6/25.
//

#include "utils.h"
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "output.h"
#include <fcntl.h>

#define DEFAULT_READ_SIZE 4096


int remove_dir(char *dir) {
    char cur_dir[] = ".";
    char up_dir[] = "..";
    char dir_name[128];
    DIR *dirp;
    struct dirent *dp;
    struct stat dir_stat;

    if (0 != access(dir, F_OK)) {
        printf_wrapper(ERROR, "No permission to access dir %s\n", dir);
        return -1;
    }

    if (0 > stat(dir, &dir_stat)) {
        printf_wrapper(ERROR, "Get directory %s stat error, remove %s failed\n", dir, dir);
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
        printf_wrapper(ERROR, "Unknown dir %s type, remove %s failed\n", dir, dir);
        return -1;
    }
    return 0;
}

int remove_file(char *file_path) {
    struct stat file_stat;

    if (0 != access(file_path, F_OK)) {
        printf_wrapper(ERROR, "No permission to access file %s\n", file_path);
        return -1;
    }

    if (0 > stat(file_path, &file_stat)) {
        printf_wrapper(ERROR, "Get file %s stat error, remove %s failed\n", file_path, file_path);
        return -1;
    }

    if (S_ISREG(file_stat.st_mode)) {
        remove(file_path);
    } else {
        return -1;
    }
    return 0;
}

int output_bash_warning(char *escape_type, char *mode) {
    printf_wrapper(WARNING,
                   "Escape by %s in %s mode will call bash, may be caught by intrusion detection devices, are you sure use this mode? (y/n) ",
                   escape_type, mode);
    char *inputBuffer = malloc(sizeof(char) * 2);
    memset(inputBuffer, 0x00, 2);
    fgets(inputBuffer, 2, stdin);
    inputBuffer[strcspn(inputBuffer, "\n")] = 0x00;
    if ((strcmp(inputBuffer, "y") == 0) || (strcmp(inputBuffer, "Y") == 0)) {
        return 0;
    } else {
        return -1;
    }
}

int read_file(char *path, char *buffer, int flags) {
    int fd;
    fd = open(path, flags);
    if (fd == -1) {
        close(fd);
        return -1;
    }
    struct stat s;
    int size = DEFAULT_READ_SIZE;
    size_t stat_ret = stat(path, &s);
    if (stat_ret != -1 && s.st_size != 0) {
        size = (int)s.st_size;
    }
    size_t ret = read(fd, buffer, size);
    if (ret == -1) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}


int write_file(char *path, char *buffer, int flags) {
    int fd;
    fd = open(path, flags);
    if (!fd) {
        return -1;
    }
    size_t ret = write(fd, buffer, strlen(buffer));
    if (ret == -1) {
        return -1;
    }
    close(fd);
    return 0;
}