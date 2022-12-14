//
// Created by FlagT on 2022/6/22.
//

#include "random_str.h"

#include <string.h>
#include <stdlib.h>

void rand_string(char *str, size_t size) {
    size_t n;
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
    if (size) {
        --size;
        for (n = 0; n < size; n++) {
            int key = (int) random() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
}
