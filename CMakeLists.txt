cmake_minimum_required(VERSION 2.8.12.2)
project(shovel C)

set(CMAKE_C_STANDARD 99)

add_executable(shovel main.c exploits/release_agent.c exploits/release_agent.h docker/capability.c docker/capability.h util/output.c util/output.h exploits/cve_2022_0492.c exploits/cve_2022_0492.h docker/path.c docker/path.h util/regex_util.c util/regex_util.h util/random_str.c util/random_str.h exploits/devices_allow.c exploits/devices_allow.h util/program_info.c util/program_info.h util/utils.c util/utils.h util/custom_struts.c util/custom_struts.h docker/cgroup.c docker/cgroup.h docker/dev.c docker/dev.h util/mount_info.c util/mount_info.h)
