//
// Created by FlagT on 2022/6/22.
//

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include "output.h"


void printf_info(char *format, va_list args_list) {
    char *info_msg_format = (char *) malloc((strlen("[info] ") + strlen(format)) * sizeof(char));
    strcpy(info_msg_format, "[INFO] ");
    strcat(info_msg_format, format);
    vprintf(info_msg_format, args_list);
}

void printf_warning(char *format, va_list args_list) {
    char *info_msg_format = (char *) malloc((strlen("[info] ") + strlen(format)) * sizeof(char));
    strcpy(info_msg_format, "[INFO] ");
    strcat(info_msg_format, format);
    vprintf(info_msg_format, args_list);
}

void printf_error(char *format, va_list args_list) {
    char *info_msg_format = (char *) malloc((strlen("[info] ") + strlen(format)) * sizeof(char));
    strcpy(info_msg_format, "[INFO] ");
    strcat(info_msg_format, format);
    vprintf(info_msg_format, args_list);
    exit(0);
}

void printf_wrapper(int type, char *format, ...) {
    va_list marker;
    va_start(marker, format);
    switch (type) {
        case INFO:
            printf_info(format, marker);
            break;
        case WARNING:
            printf_warning(format, marker);
            break;
        case ERROR:
            printf_error(format, marker);
            break;
        default:
            printf_info(format, marker);
            break;
    };
    va_end(marker);
}