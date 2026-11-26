#ifndef KAIROS_COMPAT_H
#define KAIROS_COMPAT_H

#include <stddef.h>
#include <string.h>

#if defined(__APPLE__) && defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && \
    __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 1070
static inline void *kairos_memmem(const void *data, size_t length,
                                  const void *needle, size_t size) {
    if (!size) return (void *)data;
    if (size > length) return NULL;
    const unsigned char *bytes = data;
    for (size_t i = 0; i <= length - size; i++) {
        if (bytes[i] == *(const unsigned char *)needle && !memcmp(bytes + i, needle, size))
            return (void *)(bytes + i);
    }
    return NULL;
}
#define memmem kairos_memmem
#endif

#endif
