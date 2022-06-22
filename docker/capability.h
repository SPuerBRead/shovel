//
// Created by FlagT on 2022/6/22.
//

#define __CAP_BITS   37
#include <linux/capability.h>

#ifndef SHOVEL_CAPABILITY_H
#define SHOVEL_CAPABILITY_H
#endif //SHOVEL_CAPABILITY_H

typedef int cap_value_t;

char const *cap_name[__CAP_BITS];

int check_cap_sys_admin();