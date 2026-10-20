#pragma once
#include "newpatch.h"

int watch_image_info(const uint8_t* buf, size_t len, uint32_t* base);
int watch_sigcheck_patch(struct iboot64_img* image);
