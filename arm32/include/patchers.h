/*
 * Copyright 2013-2016, iH8sn0w. <iH8sn0w@iH8sn0w.com>
 *
 * This file is part of iBoot32Patcher.
 *
 * iBoot32Patcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * iBoot32Patcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with iBoot32Patcher.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef PATCHERS_H
#define PATCHERS_H

#include "iBoot32Patcher.h"

#define DEBUG_ENABLED_DTRE_VAR_STR "debug-enabled"
#define DEFAULT_BOOTARGS_STR "rd=md0 nand-enable-reformat=1 -progress"
#define RELIANCE_CERT_STR "Reliance on this certificate"
#define IBOOT_TYPE_IBSS bswap32(0x69425353)
#define IBOOT_TYPE_IBEC bswap32(0x69424543)

int ib32_patch_boot_args(struct iboot_img* iboot_in, const char* boot_args);
int ib32_patch_env_boot_args(struct iboot_img* iboot_in);
int ib32_patch_cmd_handler(struct iboot_img* iboot_in, const char* cmd_str, uint32_t ptr);
int ib32_patch_debug_enabled(struct iboot_img* iboot_in);
int ib32_patch_rsa_check(struct iboot_img* iboot_in);
int ib32_patch_ticket_check(struct iboot_img* iboot_in);
int ib32_patch_boot_mode(struct iboot_img* iboot_in, int mode);
int ib32_disable_kaslr(struct iboot_img* iboot_in);
int ib32_patch_boot_partition(struct iboot_img* iboot_in, int ver);
int ib32_patch_boot_ramdisk(struct iboot_img* iboot_in);
int ib32_patch_setenv_cmd(struct iboot_img* iboot_in);
int ib32_patch_433orlower_jumpiBoot(struct iboot_img* iboot_in);
int ib32_patch_logo(struct iboot_img* iboot_in);
int ib32_patch_logo4(struct iboot_img* iboot_in);
int ib32_patch_dualboot_ibss(struct iboot_img* iboot_in);
int ib32_patch_dualboot_ibec(struct iboot_img* iboot_in);
int ib32_patch_dualboot(struct iboot_img* iboot_in);

int ib32_ios1_info(struct iboot_img *image);
int ib32_patch_ios1_img2(struct iboot_img *image);
int ib32_patch_ios1_bootargs(struct iboot_img *image, const char *args);
int ib32_patch_ios1_debug(struct iboot_img *image);
#endif
