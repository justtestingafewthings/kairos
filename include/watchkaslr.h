#pragma once
#include "newpatch.h"

/* Disable the randomized Watch kernel slide, preserving required load alignment.
 * Returns zero on success, including an already-applied matching patch. */
int watch_disable_kaslr(struct iboot64_img *image);
