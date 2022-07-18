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
#include <assert.h>
#include <stdlib.h>

#define DEFAULT_READ_SIZE 1048576


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

    if (S_ISREG(file_stat.st_mode) || S_ISBLK(file_stat.st_mode)) {
        remove(file_path);
    } else {
        return -1;
    }
    return 0;
}

void clear_input() {
    char *buffer = malloc(sizeof(char) * 2);
    memset(buffer, 0x00, 2);
    fgets(buffer, 2, stdin);
}

void output_bash_warning(char *escape_type, char *mode) {
    printf_wrapper(WARNING,
                   "Escape by %s in %s mode will call bash, may be caught by intrusion detection devices, are you sure use this mode? (y/n) ",
                   escape_type, mode);
    char *inputBuffer = malloc(sizeof(char) * 2);
    memset(inputBuffer, 0x00, 2);
    fgets(inputBuffer, 2, stdin);
    inputBuffer[strcspn(inputBuffer, "\n")] = 0x00;
    clear_input();
    if ((strcmp(inputBuffer, "y") == 0) || (strcmp(inputBuffer, "Y") == 0)) {
        return;
    } else {
        printf_wrapper(INFO, "Exit\n");
        exit(EXIT_SUCCESS);
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
        size = (int) s.st_size;
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

int file_exist(char *path) {
    if (access(path, F_OK) == 0) {
        return 0;
    } else {
        return -1;
    }
}

char **str_split(char *str, const char a_delim) {
    char **result = 0;
    size_t count = 0;
    char *tmp = str;
    char *last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;
    while (*tmp) {
        if (a_delim == *tmp) {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }
    count += last_comma < (str + strlen(str) - 1);
    count++;
    result = malloc(sizeof(char *) * count);
    if (result) {
        size_t idx = 0;
        char *token = strtok(str, delim);
        while (token) {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }
    return result;
}

char *str_replace(char *orig, char *rep, char *with) {
    char *result;
    char *ins;
    char *tmp;
    unsigned long len_rep;
    unsigned long len_with;
    unsigned long len_front;
    unsigned long count;
    if (!orig || !rep)
        return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0)
        return NULL;
    if (!with)
        with = "";
    len_with = strlen(with);
    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }
    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);
    if (!result)
        return NULL;
    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

