/* Kairos CLI for Merculous/iBoot32Patcher, GPL-3.0-or-later. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include "arm32.h"
#include "imageio.h"
#include "include/iBoot32Patcher.h"
#include "include/functions.h"
#include "include/patchers.h"
#include "dfuuart.h"
#include "watchkaslr.h"

int kairos_arm32_main(int argc, char **argv) {
    char *boot_args = NULL, *command = NULL;
    uint32_t address = 0;
    bool env = false, debug = false, partition = false;
    bool ramdisk = false, setenv = false, ticket = false, remote = false, local = false;
    bool kaslr = false, jump = false, logo = false, logo4 = false, dualboot = false, uart = false;
    bool rsa = false;
    for (int i = 3; i < argc; ++i) {
        const char *option = argv[i];
        if (!strcmp(option, "-b") && i + 1 < argc) boot_args = argv[++i];
        else if (!strcmp(option, "-a")) env = true;
        else if (!strcmp(option, "-c") && i + 2 < argc) {
            command = argv[++i];
            char *end; const char *text = argv[++i]; errno = 0;
            unsigned long long parsed = strtoull(text, &end, 0);
            if (errno || end == text || *end || text[0] < '0' || text[0] > '9' || parsed > UINT32_MAX || !parsed) {
                fprintf(stderr, "Invalid ARM32 command address: %s\n", text); return 1;
            }
            address = (uint32_t)parsed;
        } else if (!strcmp(option, "-r") || !strcmp(option, "--rsa")) rsa = true;
        else if (!strcmp(option, "-d") || !strcmp(option, "--debug")) debug = true;
        else if (!strcmp(option, "--boot-partition")) partition = true;
        else if (!strcmp(option, "--boot-ramdisk")) ramdisk = true;
        else if (!strcmp(option, "--setenv")) setenv = true;
        else if (!strcmp(option, "--ticket")) ticket = true;
        else if (!strcmp(option, "--local-boot")) local = true;
        else if (!strcmp(option, "--remote-boot")) remote = true;
        else if (!strcmp(option, "--disable-kaslr")) kaslr = true;
        else if (!strcmp(option, "--433")) jump = true;
        else if (!strcmp(option, "--logo")) logo = true;
        else if (!strcmp(option, "--logo4")) logo4 = true;
        else if (!strcmp(option, "--dualboot")) dualboot = true;
        else if (!strcmp(option, "--early-uart")) uart = true;
        else { fprintf(stderr, "Unsupported ARM32 option or missing argument: %s\n", option); return 1; }
    }
    if ((env && boot_args) || (local && remote) || (logo && logo4)) {
        fputs("Conflicting ARM32 patch options\n", stderr); return 1;
    }
    if (boot_args && strlen(boot_args) > 1023) {
        fputs("ARM32 boot arguments cannot exceed 1023 bytes\n", stderr); return 1;
    }
    if (command && (!*command || strlen(command) > 255)) {
        fputs("ARM32 command name must contain 1 to 255 bytes\n", stderr); return 1;
    }
    if (kairos_check_paths(argv[1], argv[2])) return 1;
    FILE *input = fopen(argv[1], "rb");
    if (!input) { perror(argv[1]); return 1; }
    long length;
    if (fseek(input, 0, SEEK_END) || (length = ftell(input)) < 0x340 || length > 16*1024*1024 ||
        fseek(input, 0, SEEK_SET)) { fclose(input); fputs("Invalid ARM32 image size\n", stderr); return 1; }
    struct iboot_img image = {0};
    image.len = (size_t)length;
    image.buf = malloc(image.len);
    if (!image.buf) { fclose(input); return 1; }
    int failed = fread(image.buf, 1, image.len, input) != image.len;
    if (fclose(input)) failed = 1;
    if (failed) {
        fputs("Could not read the complete ARM32 input image\n", stderr); goto failure;
    }
    uint32_t reset = 0; memcpy(&reset, image.buf, sizeof(reset));
    const unsigned char *bytes = image.buf;
    bool ios1 = ib32_ios1_info(&image);
    if (!ios1) {
        const char *version = (const char *)bytes + IBOOT_VERS_STR_OFFSET;
        if (reset != IBOOT32_RESET_VECTOR_BYTES || memcmp(bytes + 0x280, "iBoot-", 6) ||
            !memchr(version, 0, 0x2c0 - IBOOT_VERS_STR_OFFSET)) {
            fputs("Invalid unpacked ARM32 iBoot header\n", stderr); goto failure;
        }
        char *end;
        errno = 0;
        unsigned long parsed = strtoul(version, &end, 10);
        if (errno || version[0] < '0' || version[0] > '9' || end == version || parsed > UINT32_MAX) {
            fputs("Invalid ARM32 iBoot version\n", stderr); goto failure;
        }
        while (*end) {
            if (*end++ != '.' || *end < '0' || *end > '9') {
                fputs("Invalid ARM32 iBoot version\n", stderr); goto failure;
            }
            while (*end >= '0' && *end <= '9') ++end;
        }
        image.VERS = (uint32_t)parsed;
    }
    int os = ios1 ? 1 : ib32_get_os_version(&image);
    if (!os) {
        fputs("Unsupported ARM32 iBoot generation; expected iPhone OS 1 through iOS 10\n", stderr); goto failure;
    }
    if (kaslr && os < 6) {
        fputs("Kernel address randomization requires iOS 6 or later\n", stderr); goto failure;
    }
    if (ios1 && (env || partition || ramdisk || setenv || ticket || remote || local ||
                 jump || logo || logo4 || dualboot || uart)) {
        fputs("This option is not implemented for iPhone OS 1 IMG2 loaders\n", stderr); goto failure;
    }
    if (ios1 && !image.VERS)
        puts("[+] ARM32 iPhone OS 1 IMG2 loader, no embedded version banner");
    else
        printf("[+] ARM32 iBoot-%u, %s backend\n", image.VERS,
               ios1 ? "iPhone OS 1 IMG2" : "Merculous/iBoot32Patcher");
#define APPLY(call) do { if (!(call)) { fprintf(stderr, "ARM32 patch failed: %s\n", #call); goto failure; } } while (0)
    bool kernel = ib32_has_kernel_load(&image);
    if (!kernel && (boot_args || env || debug || kaslr || local || remote)) {
        fputs("Requested ARM32 options require a kernel-loading bootloader\n", stderr); goto failure;
    }
    if (kernel) {
        if (boot_args) APPLY(ios1 ? ib32_patch_ios1_bootargs(&image, boot_args) : ib32_patch_boot_args(&image, boot_args));
        if (env) APPLY(ib32_patch_env_boot_args(&image));
        if (debug) APPLY(ios1 ? ib32_patch_ios1_debug(&image) : ib32_patch_debug_enabled(&image));
        if (kaslr) {
            if (os >= 10) {
                /* iOS 10 uses entropy arithmetic instead of the PIE branch. */
                struct iboot64_img view = {0};
                view.buf = image.buf;
                view.len = image.len;
                view.base = ib32_get_iboot_base_address(image.buf);
                if (watch_disable_kaslr(&view) < 0) goto failure;
            } else APPLY(ib32_disable_kaslr(&image));
        }
        if (remote || local) APPLY(ib32_patch_boot_mode(&image, remote ? 1 : 0));
    }
    if (logo) APPLY(ib32_patch_logo(&image));
    if (logo4) APPLY(ib32_patch_logo4(&image));
    if (jump) APPLY(ib32_patch_433orlower_jumpiBoot(&image));
    if (ticket) APPLY(ib32_patch_ticket_check(&image));
    if (command) {
        if (!ib32_has_recovery_console(&image)) { fputs("ARM32 image has no recovery console\n", stderr); goto failure; }
        APPLY(ib32_patch_cmd_handler(&image, command, address));
    }
    if (rsa) APPLY(ios1 ? ib32_patch_ios1_img2(&image) : ib32_patch_rsa_check(&image));
    if (partition) APPLY(ib32_patch_boot_partition(&image, os == 9));
    if (ramdisk) APPLY(ib32_patch_boot_ramdisk(&image));
    if (setenv) APPLY(ib32_patch_setenv_cmd(&image));
    if (dualboot) APPLY(ib32_patch_dualboot(&image));
    if (uart && dfu_uart_patch(image.buf, image.len)) goto failure;
#undef APPLY
    failed = kairos_write_image(argv[1], argv[2], image.buf, image.len);
    free(image.buf);
    if (!failed) printf("[+] Wrote patched ARM32 image to %s\n", argv[2]);
    return failed;
failure:
    fputs("ARM32 patching failed; output was not written\n", stderr);
    free(image.buf);
    return 1;
}
