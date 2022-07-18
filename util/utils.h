//
// Created by FlagT on 2022/6/25.
//

#ifndef SHOVEL_UTILS_H
#define SHOVEL_UTILS_H

#endif //SHOVEL_UTILS_H

int remove_dir(char *);

int remove_file(char *);

void output_bash_warning(char *, char *);

int write_file(char *, char *, int);

int read_file(char *, char*, int);

int file_exist(char *);

char **str_split(char *, char);

char *str_replace(char *orig, char *rep, char *with);