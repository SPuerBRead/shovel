//
// Created by FlagT on 2022/6/22.
//

#define _GNU_SOURCE

#include "regex_util.h"
#include <regex.h>
#include <string.h>
#include "output.h"


void regex_util(char *src, char *reg, char *result) {
    regex_t regex;
    char err_buf[1024];
    regmatch_t match_char[2];
    regcomp(&regex, reg, REG_EXTENDED);
    int match_result = regexec(&regex, src, 10, match_char, 0);
    if (!match_result) {
        if (match_char[1].rm_so != -1) {
            char cursorCopy[strlen(src) + 1];
            strcpy(cursorCopy, src);
            cursorCopy[match_char[1].rm_eo] = 0;
            strcpy(result, cursorCopy + match_char[1].rm_so);

        }
    } else if (match_result == REG_NOMATCH) {
    } else {
        regerror(match_result, &regex, err_buf, sizeof(err_buf));
        printf_wrapper(WARNING, "Regex match failed: %s\n", err_buf);
    }
}