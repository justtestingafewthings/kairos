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

#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "arm32_defs.h"
#include "iBoot32Patcher.h"

#define ENTERING_RECOVERY_CONSOLE "Entering recovery mode, starting command prompt"
#define KERNELCACHE_PREP_STRING "__PAGEZERO"

#ifndef memmem
#define memmem ib32__memmem
void* ib32__memmem(const void* mem, int size, const void* pat, int size2);
#endif

bool ib32_image_contains(const struct iboot_img* image, const void* pointer, size_t size);

void* ib32_bl_search_down(const void* start_addr, int len);
void* ib32_bl_search_up(const void* start_addr, int len);
void* ib32_iboot_memmem(struct iboot_img* iboot_in, void* pat);
void* ib32_Build_BL_Long(void* buff, uint32_t Target, uint32_t ins);
uint32_t ib32_Resolve_BL_Long(uint32_t Offset, void* buff);
void* ib32_find_last_LDR_rd(uintptr_t start, size_t len, const uint8_t rd);
void* ib32_find_next_bl_insn_to(struct iboot_img* iboot_in, uint32_t addr);
void* ib32_find_next_next_bl_insn_to(struct iboot_img* iboot_in, uint32_t addr);
void* ib32_find_next_CMP_insn_with_value(void* start, size_t len, const uint8_t val);
void* ib32_find_next_LDR_insn_with_value(struct iboot_img* iboot_in, uint32_t value);
void* ib32_find_next_MOVW_insn_with_value(void* start, size_t len, const uint16_t val);
void* ib32_find_next_MOV_insn(void* start, size_t len);
void* ib32_find_next_MOVT_insn(void* start, size_t len);
uint32_t ib32_get_iboot_base_address(void* iboot_buf);
uint16_t ib32_get_MOVT_W_val(struct arm32_thumb_MOVT_W* movt_w);
uint16_t ib32_get_MOVW_val(struct arm32_thumb_MOVW* movw);
int ib32_get_os_version(struct iboot_img* iboot_in);
bool ib32_has_kernel_load(struct iboot_img* iboot_in);
bool ib32_has_recovery_console(struct iboot_img* iboot_in);
bool ib32_is_BW_insn(void* offset);
bool ib32_is_LDRW_insn(void* offset);
bool ib32_is_MOV_insn(void* offset);
bool ib32_is_MOVT_insn(void* offset);
bool ib32_is_MOVW_insn(void* offset);
bool ib32_is_IT_insn(void* offset);
void* ib32_ldr_search_down(const void* start_addr, int len);
void* ib32_ldr_search_up(const void* start_addr, int len);
void* ib32_ldr_pcrel_search_up(const void* start_addr, int len);
void* ib32_ldr32_search_up(const void* start_addr, int len);
void* ib32_ldr_to(const void* loc);
void* ib32_memstr(const void* mem, size_t size, const char* str);
void* ib32_pattern_search(const void* addr, int len, int pattern, int mask, int step);
void* ib32_push_r4_r7_lr_search_up(const void* start_addr, int len);
void* ib32_push_r4_to_r7_lr_search_up(const void* start_addr, int len);
void* ib32_pop_search(const void* start_addr, int len, int searchup);
void* ib32_push_search(const void* start_addr, int len, int searchup);
void* ib32_branch_thumb_unconditional_search(const void* start_addr, int len, int searchup);
void* ib32_branch_thumb_conditional_search(const void* start_addr, int len, int searchup);
void* ib32_branch_search(const void* start_addr, int len, int searchup);
void* ib32_resolve_bl32(const void* bl);
void ib32_set_MOVT_W_insn_val(void* offset, uint8_t rd, uint16_t val);
void ib32_set_MOVW_insn_val(void* offset, uint8_t rd, uint16_t val);
void* ib32_find_next_LDR_insn_with_str(struct iboot_img* iboot_in, char* in);
void* ib32_Build_MOV(void* buff, uint8_t rd, uint8_t rs);
uint32_t ib32_get_iBoot_type(struct iboot_img* iboot_in);
#endif
