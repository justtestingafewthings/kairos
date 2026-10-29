#pragma once

#include <stddef.h>

/* Reject non-regular files and output paths that refer to the input. */
int kairos_check_paths(const char *input, const char *output);

/* Replace the output only after the complete buffer has been written. */
int kairos_write_image(const char *input, const char *output,
    const void *data, size_t size);
