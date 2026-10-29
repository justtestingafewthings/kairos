#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include "watchpatch.h"
#include "arm32.h"

int kairos_arm32_probe(const char *path) {
    struct stat info;
    if (stat(path, &info) || !S_ISREG(info.st_mode)) return 0;
    uint8_t header[0x340];
    FILE *input = fopen(path, "rb");
    if (!input) return 0;
    size_t size = fread(header, 1, sizeof(header), input);
    fclose(input);
    uint32_t reset;
    if (size != sizeof(header)) return 0;
    memcpy(&reset, header, sizeof(reset));
    return reset == 0xea00000e && !watch_image_target(header, sizeof(header));
}
