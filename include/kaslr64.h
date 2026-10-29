#pragma once
#include "newpatch.h"

/* Disable entropy in the kernel-load slide selection, retaining geometry. */
int arm64_disable_kaslr(struct iboot64_img *image);
