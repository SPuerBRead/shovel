cmake_minimum_required(VERSION 2.8.12.2)
project(shovel C)

set(CMAKE_C_STANDARD 99)

add_executable(shovel main.c payloads/release_agent.c payloads/release_agent.h docker/capability.c docker/capability.h util/output.c util/output.h payloads/cve_2022_0492.c payloads/cve_2022_0492.h docker/path.c docker/path.h util/regex_util.c util/regex_util.h util/random_str.c util/random_str.h payloads/devices_allow.c payloads/devices_allow.h util/program_info.c util/program_info.h util/utils.c util/utils.h)
