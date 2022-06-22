//
// Created by FlagT on 2022/6/22.
//

#ifndef SHOVEL_OUTPUT_H
#define SHOVEL_OUTPUT_H

#endif //SHOVEL_OUTPUT_H


enum output_type {
    INFO = 1,
    ERROR = 2,
    WARNING= 3,
};

void printf_wrapper(int type, char* format, ...);