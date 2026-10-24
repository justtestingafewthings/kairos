#pragma once
#include "newpatch.h"

int watch_bootargs_patch(struct iboot64_img* img, const char* args);
int watch_debug_patch(struct iboot64_img* img);
int watch_command_patch(struct iboot64_img* img, const char* command, uint64_t target);
int watch_nvram_patch(struct iboot64_img* img);
int watch_freshnonce_patch(struct iboot64_img* img);
