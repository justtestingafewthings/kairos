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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include "include/finders.h"
#include "include/functions.h"
#include "include/patchers.h"
#include "include/iBoot32Patcher.h"

#define MEMMEM_RELATIVE(iboot_in, bufstart, needle, needleLen) memmem(bufstart, iboot_in->len - ((char*)(bufstart) - (char*)iboot_in->buf), needle, needleLen)

#define INSN2_MOV_R0_0__MOV_R0_0    0x20002000
#define INSN2_MOV_R4_R3__MOV_R4_R3  0x64c164c1
#define INSN2_MOV_R1_0__MOV_R0_0    0x20002100
#define INSN2_MOV_R0_0__STR_R0_R3    0x60182000
#define INSN2_NOP__NOP              0xBF00BF00
#define INSN2_RETURN_0              0x47702000

#define INSNT_NOP                   0xBF00
#define INSNT_STR_R1_R4_R0          0x5021
#define INSNT_LDR_R0_R0             0x6800

// xerub's iloader
#define INSNT_LDR_R_PC(d, n)        (0x4800 | (((d) & 7) << 8) | ((n) / 4))
unsigned int
ib32_make_b_w(int pos, int tgt)
{
    int delta;
    unsigned short pfx;
    unsigned short sfx;

    unsigned int omask = 0xB800;
    unsigned int amask = 0x7FF;

    delta = tgt - pos - 4; /* range: 0x400000 */
    pfx = 0xF000 | ((delta >> 12) & 0x7FF);
    sfx =  omask | ((delta >>  1) & amask);

    return (unsigned int)pfx | ((unsigned int)sfx << 16);
}

/* Force the iOS 2 restore branch after validating both string loads. */
static int ib32_patch_ios2_bootargs_selection(struct iboot_img *image, void *load) {
    uint8_t *bytes = image->buf;
    size_t target = (uint8_t *)load - bytes;
    if (target < 8 || target + 2 > image->len || (target & 1)) return 0;
    uint16_t default_ldr;
    memcpy(&default_ldr, bytes + target, 2);
    if ((default_ldr & 0xf800) != 0x4800) return 0;
    size_t found = 0, matches = 0;
    size_t start = target > 0x104 ? target - 0x104 : 0;
    for (size_t at = start; at + 8 <= target; at += 2) {
        uint16_t cmp, branch, alternate, join;
        memcpy(&cmp, bytes + at, 2);
        memcpy(&branch, bytes + at + 2, 2);
        memcpy(&alternate, bytes + at + 4, 2);
        memcpy(&join, bytes + at + 6, 2);
        if ((cmp & 0xf8ff) != 0x2800 || (branch & 0xff00) != 0xd100 ||
            (alternate & 0xff00) != (default_ldr & 0xff00) ||
            (join & 0xf800) != 0xe000) continue;
        int displacement = (int8_t)(branch & 0xff) * 2;
        int join_displacement = (int)(join & 0x7ff);
        if (join_displacement & 0x400) join_displacement -= 0x800;
        if ((ptrdiff_t)at + 6 + displacement != (ptrdiff_t)target ||
            (ptrdiff_t)at + 10 + join_displacement * 2 != (ptrdiff_t)target + 2) continue;
        size_t literal = ((at + 8) & ~(size_t)3) + (alternate & 0xff) * 4;
        if (literal + 4 > image->len) continue;
        found = at + 2;
        ++matches;
    }
    if (matches != 1) {
        printf("%s: Expected one restore boot-args selector, found %zu\n", __FUNCTION__, matches);
        return 0;
    }
    uint16_t branch = 0xe000 | (((target - found - 4) / 2) & 0x7ff);
    memcpy(bytes + found, &branch, 2);
    printf("%s: Forced restore boot-args selection at %#zx\n", __FUNCTION__, found);
    return 1;
}

int ib32_patch_boot_args(struct iboot_img* iboot_in, const char* boot_args) {
	printf("%s: Entering...\n", __FUNCTION__);

	void* default_boot_args_str_loc = ib32_memstr(iboot_in->buf, iboot_in->len, DEFAULT_BOOTARGS_STR);
	if(!default_boot_args_str_loc) {
		printf("%s: Unable to find default boot-args string!\n", __FUNCTION__);
		return 0;
	}
	printf("%s: Default boot-args string is at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, default_boot_args_str_loc));

	void* default_boot_args_xref = ib32_iboot_memmem(iboot_in, default_boot_args_str_loc);
	if(!default_boot_args_xref) {
		printf("%s: Unable to find default boot-args string xref!\n", __FUNCTION__);
		return 0;
	}
	printf("%s: boot-args xref is at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, default_boot_args_xref));

	/* If new boot-args length exceeds the pre-defined one in iBoot, we need to point the xref somewhere else... */
	if(strlen(boot_args) > strlen(DEFAULT_BOOTARGS_STR)) {
		printf("%s: Relocating boot-args string...\n", __FUNCTION__);

		char* reliance_cert_str_loc = (char*) ib32_memstr(iboot_in->buf, iboot_in->len, RELIANCE_CERT_STR);
		if(!reliance_cert_str_loc) {
			printf("%s: Unable to find \"%s\" string!\n", __FUNCTION__, RELIANCE_CERT_STR);
			return 0;
		}
		printf("%s: \"%s\" string found at %p\n", __FUNCTION__, RELIANCE_CERT_STR, (void*) IB32_FILE_OFFSET(iboot_in, reliance_cert_str_loc));

		/* Point the boot-args xref to the "Reliance on this cert..." string. */
		printf("%s: Pointing default boot-args xref to %p...\n", __FUNCTION__, (void*) IB32_ADDRESS(iboot_in, reliance_cert_str_loc));
		*(uint32_t*)default_boot_args_xref = (uintptr_t) IB32_ADDRESS(iboot_in, reliance_cert_str_loc);

		default_boot_args_str_loc = reliance_cert_str_loc;
	}
	printf("%s: Applying custom boot-args \"%s\"\n", __FUNCTION__, boot_args);
    size_t available = iboot_in->len - ((uintptr_t)default_boot_args_str_loc - (uintptr_t)iboot_in->buf);
    const char *terminator = memchr(default_boot_args_str_loc, 0, available);
    if (!terminator || strlen(boot_args) > (size_t)(terminator - (char *)default_boot_args_str_loc)) {
        printf("%s: Replacement boot arguments exceed the available string storage\n", __FUNCTION__);
        return 0;
    }
    strcpy(default_boot_args_str_loc, boot_args);

	void* _ldr_rd_boot_args = ib32_ldr_to(default_boot_args_xref);
	if(!_ldr_rd_boot_args) {
		uintptr_t default_boot_args_str_loc_with_base = (uintptr_t) IB32_FILE_OFFSET(iboot_in, default_boot_args_str_loc) + ib32_get_iboot_base_address(iboot_in->buf);

		_ldr_rd_boot_args = ib32_find_next_LDR_insn_with_value(iboot_in, (uint32_t) default_boot_args_str_loc_with_base);
		if(!_ldr_rd_boot_args) {
			printf("%s: Error locating LDR Rx, =boot_args!\n", __FUNCTION__);
			return 0;
		}
	}

	struct arm32_thumb_LDR* ldr_rd_boot_args = (struct arm32_thumb_LDR*) _ldr_rd_boot_args;
	printf("%s: Found LDR R%d, =boot_args at %p\n", __FUNCTION__, ldr_rd_boot_args->rd, (void*) IB32_FILE_OFFSET(iboot_in, _ldr_rd_boot_args));

    if (ib32_get_os_version(iboot_in) == 2)
        return ib32_patch_ios2_bootargs_selection(iboot_in, _ldr_rd_boot_args);

	void* arm32_thumb_IT_insn = ldr_rd_boot_args;
    bool it_found = false;
    uint16_t* itPtrStart = (uint16_t*)arm32_thumb_IT_insn;
    uint16_t* itPtrEnd = itPtrStart + 0x30;

    for (uint16_t* itPtr = itPtrStart; itPtr != itPtrEnd; itPtr++) {
        if (*itPtr == ARM32_THUMB_IT_EQ || *itPtr == ARM32_THUMB_IT_NE || *itPtr == ARM32_THUMB_ITE_NE) {
            it_found = true;
            arm32_thumb_IT_insn = (void*)itPtr;
            break;
        }
    }

    if (it_found) {
        printf("%s: Found IT instruction at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, arm32_thumb_IT_insn));
    }

    void* _cmp_insn = NULL;

    int os_vers = ib32_get_os_version(iboot_in);
    if (os_vers >= 2 && os_vers <= 4) {
        if (it_found) {
            /* IT instruction found! CMP is right above the IT instruction */
            _cmp_insn = ib32_find_next_CMP_insn_with_value(arm32_thumb_IT_insn - 2, 0x10, 0);
        } else {
            if (os_vers == 2) {
                /* iOS 2 has the CMP farther away */
                _cmp_insn = ib32_find_next_CMP_insn_with_value(ldr_rd_boot_args - 0x40, 0x10, 0);
            } else {
                /* Images like iPod2,1 don't have IT instruction. It has the CMP above boot-args LDR */
                _cmp_insn = ib32_find_next_CMP_insn_with_value(ldr_rd_boot_args - 0x10, 0x20, 0);
            }
        }

        if (!_cmp_insn) {
            printf("%s: Failed to find CMP Rx, #0!\n", __FUNCTION__);
            return 0;
        }

        printf("%s: Found CMP Rx, #0 at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, _cmp_insn));
        struct arm32_thumb* cmp_insn = (struct arm32_thumb*)_cmp_insn;

        cmp_insn->offset = 1;
        return 1;
    } else {
        _cmp_insn = ib32_find_next_CMP_insn_with_value(ldr_rd_boot_args, 0x100, 0);
        if (!_cmp_insn) {
            printf("%s: Failed to find CMP Rx, #0!\n", __FUNCTION__);
            return 0;
        }

        printf("%s: Found CMP Rx, #0 at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, _cmp_insn));

        struct arm32_thumb* cmp_insn = (struct arm32_thumb*)_cmp_insn;
        cmp_insn->offset = 1;
    }

	/* MOV Rd, Rs instruction usually follows right after the IT instruction. */
	struct arm32_thumb_hi_reg_op* mov_insn = (struct arm32_thumb_hi_reg_op*) (arm32_thumb_IT_insn + 2);

	printf("%s: Found MOV R%d, R%d at %p\n", __FUNCTION__, mov_insn->rd, mov_insn->rs, (void*) IB32_FILE_OFFSET(iboot_in, arm32_thumb_IT_insn + 2));

	int null_str_reg = (ldr_rd_boot_args->rd == mov_insn->rs) ? mov_insn->rd : mov_insn->rs;

    /* + 0x10: Some iBoots have the null string load after the CMP instruction... */

	void* ldr_null_str = ib32_find_last_LDR_rd((uintptr_t) (_cmp_insn + 0x10), 0x200, null_str_reg);
	if(!ldr_null_str) {

        /* + 0x9 Some iBoots have the null string load after the CMP instruction... */

        ldr_null_str = ib32_find_last_LDR_rd((uintptr_t) (_cmp_insn + 0x9), 0x200, null_str_reg);
        if(!ldr_null_str) {
                printf("%s: Unable to find LDR R%d, =null_str\n", __FUNCTION__, null_str_reg);
                return 0;
        }
	}

	printf("%s: Found LDR R%d, =null_str at %p\n", __FUNCTION__, null_str_reg, (void*) IB32_FILE_OFFSET(iboot_in, ldr_null_str));

	/* Calculate the new PC relative load from the default boot args xref to the LDR Rd, =null_string location. */
	uint32_t diff = (uint32_t) (IB32_FILE_OFFSET(iboot_in, default_boot_args_xref) - IB32_FILE_OFFSET(iboot_in, ldr_null_str));

	/* T1 LDR PC-based instructions use the immediate 8 bits multiplied by 4. */
	struct arm32_thumb_LDR* ldr_rd_null_str = (struct arm32_thumb_LDR*) ldr_null_str;
	printf("%s: Pointing LDR R%d, =null_str to boot-args xref...\n", __FUNCTION__, ldr_rd_null_str->rd);
	ldr_rd_null_str->imm8 = (diff / 0x4);

	printf("%s: Leaving...\n", __FUNCTION__);
	return 1;
}

int ib32_patch_env_boot_args(struct iboot_img* iboot_in) {
    printf("%s: Finding rd=md0 LDR\n", __FUNCTION__);
    char* bootargs_ldr =  ib32_find_next_LDR_insn_with_str(iboot_in, DEFAULT_BOOTARGS_STR);
    if(!bootargs_ldr) {
        printf("%s: Failed to find rd=md0 LDR\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found rd=md0 LDR at %p\n", __FUNCTION__, (void*) IB32_ADDRESS(iboot_in, bootargs_ldr));
    struct arm32_thumb_LDR* ldr_rd_boot_args = (struct arm32_thumb_LDR*) bootargs_ldr;
    char* _cmp_insn = ib32_find_next_CMP_insn_with_value(ldr_rd_boot_args, 0x100, 0);
    if(!_cmp_insn) {
        printf("%s: Error locating next CMP instruction!\n", __FUNCTION__);
        return 0;
    }
    struct arm32_thumb* cmp_insn = (struct arm32_thumb*) _cmp_insn;
    printf("%s: Found CMP R%d, #%d at %p\n", __FUNCTION__, cmp_insn->rd, cmp_insn->offset, (void*) IB32_ADDRESS(iboot_in, _cmp_insn));

    char* _mov_insn = ib32_find_Boot_Args_MOV(_cmp_insn);
    if(!_mov_insn) {
        printf("%s: Error finding MOV instruction!\n", __FUNCTION__);
        return 0;
    }
    struct arm32_thumb_hi_reg_op* mov_insn = (struct arm32_thumb_hi_reg_op*) _mov_insn;
    printf("%s: Found mov r%d, r%d at: %p\n", __FUNCTION__, mov_insn->rd, mov_insn->rs, (void*) IB32_ADDRESS(iboot_in, _mov_insn));
    void* boot_args_str_loc = ib32_find_Boot_Args_String_Location(iboot_in);
    if(!boot_args_str_loc) {
        printf("%s: Error finding boot-args string location!\n", __FUNCTION__);
        return 0;
    }
    void* default_ldr_xref = ib32_find_ldr_xref(iboot_in);
    if(!default_ldr_xref) {
        printf("%s: Error finding rd=md0 xref!\n", __FUNCTION__);
        return 0;
    }
    uint32_t getenv_addr = ib32_find_GETENV_Addr(iboot_in);
    if(!getenv_addr) {
        printf("%s: Error finding getenv function!\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Pointing rd=md0 ldr to boot-args string location\n", __FUNCTION__);
    *(uint32_t*)default_ldr_xref = (uintptr_t) IB32_ADDRESS(iboot_in, boot_args_str_loc);
    int null_str_reg = (ldr_rd_boot_args->rd == mov_insn->rs) ? mov_insn->rd : mov_insn->rs;
    char* null_ins = ib32_find_null_str(_mov_insn, null_str_reg);
    if(!null_ins) {
        printf("%s: Failed to find ldr r%d, = null_str\n", __FUNCTION__, null_str_reg);
        return 0;
    }
    char* Current_ins = (_cmp_insn < null_ins) ? _cmp_insn : null_ins;
    printf("%s: Building mov r0, r%d at %p\n", __FUNCTION__, ldr_rd_boot_args->rd, (void*) IB32_ADDRESS(iboot_in, Current_ins));
    ib32_Build_MOV((void*)Current_ins, 0x0, ldr_rd_boot_args->rd);
    Current_ins += 0x2;
    printf("%s: Building bl 0x%x at %p\n", __FUNCTION__, getenv_addr, (void*) IB32_ADDRESS(iboot_in, Current_ins));
    ib32_Build_BL_Long((void*)Current_ins, getenv_addr, IB32_ADDRESS(iboot_in, Current_ins));
    Current_ins += 0x4;
    printf("%s: Building mov r%d, r0 at %p\n", __FUNCTION__, mov_insn->rd, (void*) IB32_ADDRESS(iboot_in, Current_ins));
    ib32_Build_MOV((void*)Current_ins, mov_insn->rd, 0x0);
    Current_ins += 0x2;
    printf("%s: Nopping extra instructions\n", __FUNCTION__);
    while(Current_ins <= _mov_insn ) {
        Current_ins[0] = 0x00;
        Current_ins[1] = 0xBF; //NOP
        Current_ins += 0x2;
    }
	printf("%s: Leaving\n", __FUNCTION__);
    return 1;
}

int ib32_disable_kaslr(struct iboot_img* iboot_in) {
	printf("%s: Entering...\n", __FUNCTION__);
	printf("%s: Finding __TEXT LDR\n", __FUNCTION__);
    char* text_ldr =  ib32_find_next_LDR_insn_with_str(iboot_in, "__TEXT");
    if(!text_ldr) {
        printf("%s: Failed to find __TEXT LDR\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found __TEXT LDR at %p\n", __FUNCTION__, (void*) IB32_ADDRESS(iboot_in, text_ldr));
    printf("%s: Finding push\n", __FUNCTION__);
    void* push = ib32_push_search(text_ldr, 0x200, 1);
    if(!push) {
        printf("%s: Failed to find push\n", __FUNCTION__);
        return 0;
    }
	printf("%s: Found push at %p\n", __FUNCTION__, (void*) IB32_ADDRESS(iboot_in, push));
    printf("%s: Finding bne\n", __FUNCTION__);
    char* bne = ib32_branch_thumb_conditional_search(push, 0x50, 0);
    if(!bne) {
        printf("%s: Failed to find bne\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found bne at %p\n", __FUNCTION__, (void*) IB32_ADDRESS(iboot_in, bne));
    printf("%s: nopping bne\n", __FUNCTION__);
    bne[0] = 0x00;
    bne[1] = 0xBF;
	printf("%s: Leaving\n", __FUNCTION__);
	return 1;
}

int ib32_patch_boot_partition(struct iboot_img* iboot_in, int ver) {
    printf("%s: Entering...\n", __FUNCTION__);

    void* boot_partition_ldr = ib32_find_boot_partition_ldr(iboot_in);

    if(!boot_partition_ldr) {
        printf("%s: Unable to find boot_partition_ldr!\n", __FUNCTION__);
        return 0;
    }

    char *bl_boot_partition = ib32_bl_search_down(boot_partition_ldr,0x100);
    if(!bl_boot_partition) {
        printf("%s: Unable to find the boot-partition BL! (Image may already be patched?)\n", __FUNCTION__);
        return 0;
    }

    printf("%s: Patching boot_partition BL at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, bl_boot_partition));

    /* BL boot-partition --> MOVS R0, #0; MOVS R0, #0 */
    *(uint32_t*)bl_boot_partition = bswap32(0x00200020);

    /* iOS 9 or later */
    if(ver == 1) {
        printf("%s: iOS 9 or later (for De Rebus Antiquis)\n", __FUNCTION__);
        void* boot_partition_loc = memmem(iboot_in -> buf, iboot_in -> len, "boot-partition", strlen("boot-partition"));
        if (!boot_partition_loc) {
            printf("%s: Failed to find boot-partition string\n", __FUNCTION__);
            return 0;
        }
        printf("%s: Found boot-partition string: %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, boot_partition_loc));
        printf("%s: Setting boot-partition to 2\n", __FUNCTION__);
        *(uint16_t*)boot_partition_loc = bswap16(0x3200);
    }

    printf("%s: Leaving...\n", __FUNCTION__);
    return 1;
}

int ib32_patch_boot_ramdisk(struct iboot_img* iboot_in) {
    void* boot_ramdisk_ldr = ib32_find_boot_ramdisk_ldr(iboot_in);

    if(!boot_ramdisk_ldr) {
        printf("%s: Unable to find boot_ramdisk_ldr!\n", __FUNCTION__);
        return 0;
    }

    char *bl_boot_ramdisk = ib32_bl_search_down(boot_ramdisk_ldr,0x100);
    if(!bl_boot_ramdisk) {
        printf("%s: Unable to find the boot-ramdisk BL! (Image may already be patched?)\n", __FUNCTION__);
        return 0;
    }

    printf("%s: Patching boot_ramdisk BL at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, bl_boot_ramdisk));

    /* BL ramdisk --> MOVS R0, #0; MOVS R0, #0 */
    *(uint32_t*)bl_boot_ramdisk = bswap32(0x00200020);

    printf("%s: Leaving...\n", __FUNCTION__);
    return 1;
}

int ib32_patch_logo(struct iboot_img* iboot_in) {
    printf("%s: Entering...\n", __FUNCTION__);
    uint8_t logo[] = {0x46, 0xF2, 0x6F, 0x70};
    uint8_t *logo_loc = memmem(iboot_in->buf, iboot_in->len, &logo, sizeof(logo));
    if (!logo_loc) {
        printf("%s: Failed to find AppleLogo\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found applelogo: %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, logo_loc));

    printf("%s: Patching logo -> logb ...\n", __FUNCTION__);
    *(uint32_t*)logo_loc = 0x7062f246;

    printf("%s: Leaving...\n", __FUNCTION__);
    return 1;
}

int ib32_patch_logo4(struct iboot_img* iboot_in) {
    printf("%s: Entering...\n", __FUNCTION__);
    void* logo_loc = memmem(iboot_in -> buf, iboot_in -> len, "ogol", strlen("ogol"));
    if (!logo_loc) {
        printf("%s: Failed to find logo string\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found main string: %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, logo_loc));

    printf("%s: Patching logo -> log4 ...\n", __FUNCTION__);
    *(uint8_t*)logo_loc = 0x34;

    printf("%s: Leaving...\n", __FUNCTION__);
    return 1;
}

static void ib32_store16(void *buffer, uint16_t value) {
    memcpy(buffer, &value, sizeof(value));
}

static void ib32_store32(void *buffer, uint32_t value) {
    memcpy(buffer, &value, sizeof(value));
}

/* Jump from iBoot to iOS 4.3.3 or lower iBoot via go command */
int ib32_patch_433orlower_jumpiBoot(struct iboot_img* iboot_in) {
    printf("%s: Entering...\n", __FUNCTION__);
    void* main_loc = memmem(iboot_in -> buf, iboot_in -> len, "main", strlen("main"));
    if (!main_loc) {
        printf("%s: Failed to find main string\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found main string: %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, main_loc));

    struct iboot32_cmd_t* main_function = (struct iboot32_cmd_t*) ib32_iboot_memmem(iboot_in, main_loc);
    if(!main_function || !ib32_image_contains(iboot_in, main_function, sizeof(*main_function))) {
        printf("%s: Unable to find a ref to \"%p\".\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, main_loc));
        return 0;
    }
    printf("%s: Found the main_function string reference at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, (void*) main_function));
    uint32_t main_function_loc = 4 + IB32_FILE_OFFSET(iboot_in, (void*) main_function);

    static const uint8_t patch_val[] = {0x00,0x28,0x08,0xbf,0x01,0x20,0x80,0xbd};
    void* patch_loc = memmem(iboot_in -> buf, iboot_in -> len, patch_val, sizeof(patch_val));
    if (!patch_loc) {
        printf("%s: Failed to find patch_offset string\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found patch_offset string: %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, patch_loc));
    uint32_t iBoot4_fix_offset = IB32_FILE_OFFSET(iboot_in, patch_loc);

    static const uint8_t search_payload_header[] = {0x10,0xff,0x2f,0xe1,0xfe,0xff,0xff,0xea};
    void* payload = memmem(iboot_in -> buf, iboot_in -> len, search_payload_header, sizeof(search_payload_header));
    if (!payload) {
        printf("%s: Failed to find payload_offset\n", __FUNCTION__);
        return 0;
    }
    payload = (uint8_t*)payload + sizeof(search_payload_header);
    if (!ib32_image_contains(iboot_in, payload, 44)) {
        printf("%s: Insufficient space for jump payload\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found payload_offset: %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, payload));
    uint32_t payload_loc = IB32_FILE_OFFSET(iboot_in, payload);
    uint32_t baseaddr = ib32_get_iboot_base_address(iboot_in->buf);

    uint32_t original[2];
    memcpy(original, patch_loc, sizeof(original));
    printf("%s: Writing payload\n", __FUNCTION__);
    ib32_store16(payload, INSNT_LDR_R_PC(4, 0x14)); payload+=2;
    ib32_store16(payload, INSNT_LDR_R_PC(0, 0x18)); payload+=2;
    ib32_store16(payload, INSNT_LDR_R_PC(1, 0x18)); payload+=2;
    ib32_store16(payload, INSNT_STR_R1_R4_R0); payload+=2;
    ib32_store16(payload, INSNT_LDR_R_PC(0, 0x18)); payload+=2;
    ib32_store16(payload, INSNT_LDR_R_PC(1, 0x1c)); payload+=2;
    ib32_store16(payload, INSNT_STR_R1_R4_R0); payload+=2;
    ib32_store32(payload, main_function->cmd_ptr); payload+=4;
    ib32_store32(payload, ib32_make_b_w(payload_loc+0x12, main_function_loc+4)); payload+=4;
    ib32_store16(payload, INSNT_NOP); payload+=2;
    ib32_store32(payload, baseaddr); payload+=4;
    ib32_store32(payload, iBoot4_fix_offset); payload+=4;
    ib32_store32(payload, original[0]); payload+=4;
    ib32_store32(payload, iBoot4_fix_offset+4); payload+=4;
    ib32_store32(payload, original[1]);

    /* hook main function */
    main_function->cmd_ptr = ib32_make_b_w(main_function_loc, payload_loc);

    /* fix jump to iBoot */
    ib32_store32(patch_loc, 0xbf982801);patch_loc+=4;
    ib32_store32(patch_loc, 0xbd802002);

    printf("%s: Leaving\n", __FUNCTION__);
    return 1;
}

int ib32_patch_setenv_cmd(struct iboot_img* iboot_in) {
	printf("%s: Entering...\n", __FUNCTION__);

	char* setenvstr = "setenv";

	size_t setenv_str_len = strlen(setenvstr);
	size_t setenv_bytes_len = setenv_str_len + 2;

	char* setenv_bytes = (char*)malloc(setenv_bytes_len);
	if(!setenv_bytes) {
		printf("%s: Out of memory.\n", __FUNCTION__);
		return 0;
	}

	memset(setenv_bytes, 0, setenv_bytes_len);

	for(int i = 0; i < setenv_str_len; i++) {
		setenv_bytes[i+1] = setenvstr[i];
	}

	printf("%s: Finding setenv command string\n", __FUNCTION__);
	void* setenv_ptr_str_loc = memmem(iboot_in->buf, iboot_in->len, setenv_bytes, setenv_bytes_len);
	free(setenv_bytes);
	if(!setenv_ptr_str_loc) {
		printf("%s: Unable to find the setenv command\n", __FUNCTION__);
		return 0;
	}
	setenv_ptr_str_loc++;

	printf("%s: Found the setenv command string at %p\n", __FUNCTION__, (void*) IB32_ADDRESS(iboot_in, setenv_ptr_str_loc));

	printf("%s: Finding setenv command\n", __FUNCTION__);

	struct iboot32_cmd_t* setenv = (struct iboot32_cmd_t*) ib32_iboot_memmem(iboot_in, setenv_ptr_str_loc);
	if(!setenv || !ib32_image_contains(iboot_in, setenv, sizeof(*setenv))) {
		printf("%s: Unable to find a ref to \"%p\".\n", __FUNCTION__, (void*) IB32_ADDRESS(iboot_in, setenv_ptr_str_loc));
		return 0;
	}
	size_t setenvptr = setenv->cmd_ptr - ib32_get_iboot_base_address(iboot_in->buf);
	printf("%s: Found the cmd string reference at %p\n", __FUNCTION__, (void*)(uintptr_t)setenv->cmd_ptr);
	if (ib32_get_os_version(iboot_in) == 2) {
        /* Skip the usage calls and force the com.apple.System. check unequal. */
        static const char prefix[] = "com.apple.System.";
        const unsigned char *bytes = iboot_in->buf;
        uint32_t base = ib32_get_iboot_base_address(iboot_in->buf);
        size_t entry = setenvptr & ~(size_t)1, limit = entry+0x200;
        if (!(setenvptr&1) || entry < 0x340 || entry+12 > iboot_in->len) return 0;
        if (limit > iboot_in->len) limit = iboot_in->len;
        size_t selected = 0, matches = 0;
        for (size_t at = entry+2; at+12 <= limit; at += 2) {
            uint16_t load, size, first, second, cmp, branch;
            memcpy(&load,bytes+at,2); memcpy(&size,bytes+at-2,2);
            memcpy(&first,bytes+at+2,2); memcpy(&second,bytes+at+4,2);
            memcpy(&cmp,bytes+at+6,2); memcpy(&branch,bytes+at+8,2);
            if ((load&0xff00) != 0x4900 || size != 0x2211 ||
                (first&0xf800) != 0xf000 || (second&0xf800) != 0xf800 ||
                cmp != 0x2800 || (branch&0xff00) != 0xd100) continue;
            size_t literal = ((at+4)&~(size_t)3)+(load&255)*4;
            if (literal+4 > iboot_in->len) continue;
            uint32_t pointer; memcpy(&pointer,bytes+literal,4);
            ptrdiff_t target = (ptrdiff_t)at+12+(int8_t)(branch&255)*2;
            if (pointer < base || pointer-base > iboot_in->len-sizeof(prefix) ||
                memcmp(bytes+pointer-base,prefix,sizeof(prefix)) ||
                target < (ptrdiff_t)entry || target >= (ptrdiff_t)limit) continue;
            selected = at+2; ++matches;
        }
        if (matches != 1) {
            fprintf(stderr,"Expected one iPhone OS 2 protected-variable check, found %zu\n",matches);
            return 0;
        }
        static const unsigned char allowed[] = {1,0x20,1,0x20};
        memcpy((char*)iboot_in->buf+selected,allowed,sizeof(allowed));
        printf("[+] Unlocked iPhone OS 2 protected-variable check at %#zx\n",selected);
        return 1;
    }
	char* p = iboot_in->buf;
	void* firstBL = ib32_bl_search_down((void*)p + setenvptr, 0x50);

	if(!firstBL) {
		printf("%s: Unable to find first bl\n", __FUNCTION__);
		return 0;
	}

	void* theCheck = ib32_bl_search_down(firstBL+0x4, 0x50);

	if(!theCheck) {
		printf("%s: Unable to find environment variable check\n", __FUNCTION__);
		return 0;
	}
	printf("%s Patching check to always allow env\n", __FUNCTION__);

	*(uint32_t*) theCheck = bswap32(0x00200020);

	printf("%s: Leaving\n", __FUNCTION__);
	return 1;
}
int ib32_patch_cmd_handler(struct iboot_img* iboot_in, const char* cmd_str, uint32_t ptr) {
	printf("%s: Entering...\n", __FUNCTION__);

	size_t cmd_str_len = strlen(cmd_str);
	size_t cmd_bytes_len = cmd_str_len + 2;

	char* cmd_bytes = (char*)malloc(cmd_bytes_len);
	if(!cmd_bytes) {
		printf("%s: Out of memory.\n", __FUNCTION__);
		return 0;
	}

	memset(cmd_bytes, 0, cmd_bytes_len);

	for(int i = 0; i < cmd_str_len; i++) {
		cmd_bytes[i+1] = cmd_str[i];
	}

	void* cmd_ptr_str_loc = memmem(iboot_in->buf, iboot_in->len, cmd_bytes, cmd_bytes_len);

	free(cmd_bytes);

	if(!cmd_ptr_str_loc) {
		printf("%s: Unable to find the cmd \"%s\".\n", __FUNCTION__, cmd_str);
		return 0;
	}
	cmd_ptr_str_loc++;

	printf("%s: Found the cmd string at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, cmd_ptr_str_loc));

	/* Resolve the cmd table referencing the cmd string... */
	struct iboot32_cmd_t* cmd = (struct iboot32_cmd_t*) ib32_iboot_memmem(iboot_in, cmd_ptr_str_loc);
	if(!cmd || !ib32_image_contains(iboot_in, cmd, sizeof(*cmd))) {
		printf("%s: Unable to find a ref to \"%p\".\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, cmd_ptr_str_loc));
		return 0;
	}

	printf("%s: Found the cmd string reference at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, (void*) cmd));

	printf("%s: Pointing \"%s\" from 0x%08x to 0x%08x...\n", __FUNCTION__, cmd_str, cmd->cmd_ptr, ptr);

	cmd->cmd_ptr = ptr;

	printf("%s: Leaving...\n", __FUNCTION__);

	return 1;
}

int ib32_patch_debug_enabled(struct iboot_img* iboot_in) {
	printf("%s: Entering...\n", __FUNCTION__);

	void* get_value_for_dtre_bl = ib32_find_dtre_get_value_bl_insn(iboot_in, DEBUG_ENABLED_DTRE_VAR_STR);
	if(!get_value_for_dtre_bl) {
		printf("%s: Unable to find appropriate BL insn.\n", __FUNCTION__);
		return 0;
	}

	printf("%s: Patching BL insn at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, get_value_for_dtre_bl));

	/* BL get_dtre_value --> MOVS R0, #1; MOVS R0, #1 */
	*(uint32_t*)get_value_for_dtre_bl = bswap32(0x01200120);

	printf("%s: Leaving...\n", __FUNCTION__);
	return 1;
}

static int ib32_thumb_literal_value(const struct iboot_img *image, size_t at, uint32_t *value) {
    const unsigned char *bytes = image->buf;
    if (at + 2 > image->len) return 0;
    uint16_t op; memcpy(&op, bytes + at, 2);
    if ((op & 0xf800) != 0x4800) return 0;
    size_t slot = ((at + 4) & ~(size_t)3) + (op & 255) * 4;
    if (slot + 4 > image->len) return 0;
    memcpy(value, bytes + slot, 4);
    return 1;
}

/* Match both iOS 2 console permission checks and their shared globals. */
static int ib32_patch_ios2_permissions(struct iboot_img *image) {
    if (!ib32_memstr(image->buf, image->len, "iBoot for ")) return 1;
    static const unsigned char permission[] = {
        0x10,0xb5,0x08,0x49,0x00,0x24,0x0a,0x68,0x13,0x1c,0x03,0x40,
        0x98,0x42,0x07,0xd1,0x01,0x24,0xc3,0x06,0x04,0xd5,0x04,0x4b,
        0x13,0x40,0x20,0x22,0x13,0x43,0x0b,0x60,0x20,0x1c,0x10,0xbd
    };
    static const unsigned char range[] = {
        0x09,0x4b,0x42,0x18,0x1b,0x68,0xd9,0x03,0x09,0xd4,0x90,0x42,
        0x09,0xd2,0x07,0x4b,0x1b,0x68,0x98,0x42,0x05,0xd3,0x06,0x4b,
        0x1b,0x68,0x9a,0x42,0x01,0xd8,0x01,0x20,0x00,0xe0,0x00,0x20,0x70,0x47
    };
    unsigned char *bytes = image->buf;
    size_t first = 0, second = 0, first_count = 0, second_count = 0;
    for (size_t at = 0x340; at + sizeof(range) <= image->len; at += 2) {
        size_t n;
        for (n = 0; n < sizeof(permission); ++n)
            if (n != 2 && n != 22 && bytes[at+n] != permission[n]) break;
        if (n == sizeof(permission)) { first = at; ++first_count; }
        for (n = 0; n < sizeof(range); ++n)
            if (n != 0 && n != 14 && n != 22 && bytes[at+n] != range[n]) break;
        if (n == sizeof(range)) { second = at; ++second_count; }
    }
    uint32_t state, mask, same_state, lower, upper;
    uint32_t base = ib32_get_iboot_base_address(image->buf);
    if (first_count != 1 || second_count != 1 ||
        !ib32_thumb_literal_value(image, first+2, &state) ||
        !ib32_thumb_literal_value(image, first+22, &mask) || mask != 0xdff3ffff ||
        !ib32_thumb_literal_value(image, second, &same_state) || same_state != state ||
        !ib32_thumb_literal_value(image, second+14, &lower) || lower != state+4 ||
        !ib32_thumb_literal_value(image, second+22, &upper) || upper != state+8 ||
        state < base || state-base > 16*1024*1024-12 || (state & 3)) {
        fputs("Cannot validate iPhone OS 2 console permission and memory-range checks\n", stderr);
        return 0;
    }
    bytes[first+14] = bytes[first+15] = 0; /* BNE -> Thumb-1 LSLS R0,R0,#0 */
    bytes[second+9] = 0xe0; /* BMI -> B, keep the validated success target */
    printf("[+] Relaxed iPhone OS 2 console permissions at %#zx and memory range at %#zx\n",
           first+14, second+8);
    return 1;
}

/* Preserve CERT/SHSH parsing by patching the PKCS#1 failure return. */
static int ib32_patch_ios2_rsa(struct iboot_img *image) {
    static const unsigned char code[] = {
        0x01,0x38,0x01,0x31,0x53,0x40,0x1c,0x43,
        0xa8,0x42,0xf7,0xd2,0x00,0x2c,0x01,0xd1,
        0x00,0x20,0x01,0xe0,0x01,0x20,0x40,0x42,
        0x88,0x23,0xdb,0x00,0x9d,0x44,0x04,0xbc,
        0x90,0x46,0xf0,0xbd
    };
    unsigned char *bytes = image->buf;
    size_t found = 0, matches = 0;
    for (size_t at = 0x340; at + sizeof(code) <= image->len; at += 2) {
        if (memcmp(bytes + at, code, sizeof(code))) continue;
        found = at + 22;
        ++matches;
    }
    if (matches != 1) {
        printf("%s: Expected one PKCS#1 verifier return, found %zu\n", __FUNCTION__, matches);
        return 0;
    }
    bytes[found] = 0;
    bytes[found + 1] = 0x20; /* NEG R0,R0 -> MOVS R0,#0 */
    printf("%s: Patched RSA verifier result at %#zx\n", __FUNCTION__, found);
    return ib32_patch_ios2_permissions(image);
}

int ib32_patch_rsa_check(struct iboot_img* iboot_in) {
    printf("%s: Entering...\n", __FUNCTION__);

    int os_vers = ib32_get_os_version(iboot_in);
    if (os_vers == 2) return ib32_patch_ios2_rsa(iboot_in);
    /* S5L8900 WTF (1.0-4.2.1): patch the SecureROM verifier and version marker.
     * The IMG1 certificate overflow (0x8be/0xb08 + 0x54-byte extension) is
     * applied separately in the Python pwnage 2.0 layer. Kairos handles only
     * the in-code verifier patch (SBCS → MOVS) and version-marker stub. */
    if (iboot_in->len >= 0x340 &&
        !memcmp((uint8_t *)iboot_in->buf + 0x200, "SecureROM for s5l8900xwtf",
                sizeof("SecureROM for s5l8900xwtf") - 1)) {
        uint8_t *bytes = iboot_in->buf;
        uint8_t *end = memchr(bytes + 0x280, 0, 0x40);
        uint8_t *rsa = ib32_find_rsa_check_3_4(iboot_in);
        if (!end || end < bytes + 0x280 + 3 || end[-3] != '.' ||
            end[-2] < '0' || end[-2] > '9' || end[-1] < '0' || end[-1] > '9' ||
            !rsa || rsa < bytes || (size_t)(rsa - bytes) > iboot_in->len - 4 ||
            memcmp(rsa, "\x01\x20\x40\x42", 4)) {
            fputs("Could not validate S5L8900 WTF verifier and version marker\n", stderr);
            return 0;
        }
        rsa[2] = 0; rsa[3] = 0x20;
        end[-1] = 'x';
        printf("%s: Patched S5L8900 WTF verifier at %#zx and version marker at %#zx\n",
               __FUNCTION__, (size_t)(rsa - bytes) + 2, (size_t)(end - bytes) - 1);
        return 1;
    }
    if(os_vers == 4 || os_vers == 3) {
        void* rsa_check_3_4 = ib32_find_rsa_check_3_4(iboot_in);
        if(!rsa_check_3_4) {
            return 0;
        }
        /* BL --> MOVS R0, #0; MOVS R0, #0 */
        printf("%s: Patching RSA at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, rsa_check_3_4));
        *(uint32_t*)rsa_check_3_4 = bswap32(0x00200020);

        void* ldr_ecid = ib32_find_ldr_ecid(iboot_in);
        if(!ldr_ecid) {
            printf("%s: Unable to find RSA check!\n", __FUNCTION__);
            return 0;
        }
        /* BL --> MOVS R0, #0; MOVS R0, #0 */
        printf("%s: Patching BL ECID at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, ldr_ecid));
        *(uint32_t*)ldr_ecid = bswap32(0x00200020);

        void* ldr_bord = ib32_find_ldr_bord(iboot_in);
        if(!ldr_bord) {
            printf("%s: Unable to find BL BORD!\n", __FUNCTION__);
            return 0;
        }
        /* BL --> MOVS R0, #0; MOVS R0, #0 */
        printf("%s: Patching BL BORD at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, ldr_bord));
        *(uint32_t*)ldr_bord = bswap32(0x00200020);

        void* ldr_prod = ib32_find_ldr_prod(iboot_in);
        if(!ldr_prod) {
            printf("%s: Unable to find BL PROD!\n", __FUNCTION__);
            return 0;
        }
        /* BL --> MOVS R0, #0; MOVS R0, #0 */
        printf("%s: Patching BL PROD at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, ldr_prod));
        *(uint32_t*)ldr_prod = bswap32(0x00200020);

        void* ldr_sepo = ib32_find_ldr_sepo(iboot_in);
        if(!ldr_sepo) {
            printf("%s: Unable to find BL SEPO!\n", __FUNCTION__);
            return 0;
        }
        /* BL --> MOVS R0, #0; MOVS R0, #0 */
        printf("%s: Patching BL SEPO at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, ldr_sepo));
        *(uint32_t*)ldr_sepo = bswap32(0x00200020);

        return 1;
    }

    void* bl_verify_shsh = ib32_find_bl_verify_shsh(iboot_in);
    if(!bl_verify_shsh) {
        printf("%s: Unable to find BL verify_shsh!\n", __FUNCTION__);
        return 0;
    }

    printf("%s: Patching BL verify_shsh at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, bl_verify_shsh));

    /* BL verify_shsh --> MOVS R0, #0; STR R0, [R3] */
    *(uint32_t*)bl_verify_shsh = bswap32(0x00201860);

    printf("%s: Leaving...\n", __FUNCTION__);
    return 1;
}

int ib32_patch_boot_mode(struct iboot_img* iboot_in, int mode) {
    printf("%s: Entering...\n", __FUNCTION__);
    char* var_str_loc = ib32_memstr(iboot_in->buf, iboot_in->len, "debug-uarts");
    if(!var_str_loc) {
        printf("%s: Unable to find %s string!\n", __FUNCTION__, "debug-uarts");
        return 0;
    }
    printf("%s: %s string is at %p\n", __FUNCTION__, "debug-uarts", (void*) IB32_FILE_OFFSET(iboot_in, var_str_loc));

    uint32_t* var_xref = ib32_iboot_memmem(iboot_in, var_str_loc);
    if(!var_xref) {
        printf("%s: Unable to find %s string xref!\n", __FUNCTION__, "debug-uarts");
        return 0;
    }

    void* var_ldr = ib32_ldr_to(var_xref);
    if(!var_ldr) {
        printf("%s: Unable to find %s string LDR from xref!\n", __FUNCTION__, "debug-uarts");
        return 0;
    }

    void* firstBL = ib32_bl_search_down(var_ldr+4, 0x10);
    if(!firstBL) {
        printf("%s: Unable to find firstBL!\n", __FUNCTION__);
        return 0;
    }
    void* secondBL = ib32_bl_search_down(firstBL+4, 0x10);
    if(!secondBL) {
        printf("%s: Unable to find secondBL!\n", __FUNCTION__);
        return 0;
    }
    void* thefunc = ib32_bl_search_down(secondBL+4, 0x10);
    if(!thefunc) {
        printf("%s: Unable to find thefunc!\n", __FUNCTION__);
        return 0;
    }

    void *afterBL = ib32_bl_search_down(thefunc+4, 0x10);
    if(!afterBL) {
        printf("%s: Unable to find afterBL!\n", __FUNCTION__);
        return 0;
    }

    if (afterBL-4 == thefunc) {
        printf("%s: afterbl is too close!\n", __FUNCTION__);
        return 0;
    }

    void *target = ib32_resolve_bl32(thefunc);
    uint32_t *dst = (uint32_t*)((uintptr_t)target & ~(uintptr_t)1);
    if(!ib32_image_contains(iboot_in, dst, sizeof(*dst))) {
        printf("%s: Boot-mode target lies outside the image\n", __FUNCTION__);
        return 0;
    }
    printf("%s: dst is at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, (void*)dst));
    if(mode == 0) { /* local (iBoot) mode */
        ib32_store32(dst, 0x47702000); // return 0;
    }
    if(mode == 1) { /* remote (iBEC) mode */
        ib32_store32(dst, 0x47702001); // return 1;
    }

    return 1;
}

static uint16_t ib32_ticket_halfword(const unsigned char *p) {
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

static bool ib32_ticket_call_shape(const unsigned char *p) {
    uint16_t load = ib32_ticket_halfword(p);
    unsigned int reg = (load >> 8) & 7;
    if ((load & 0xf800) != 0x4800 || reg > 1) return false;

    bool stack_arg = false, size_arg = false, dereference = false;
    for (size_t i = 2; i <= 6; i += 2) {
        uint16_t insn = ib32_ticket_halfword(p + i);
        if ((insn & 0xff00) == 0xa900) stack_arg = true;
        if (insn == 0x2240 || insn == 0x2280) size_arg = true;
        if (insn == (uint16_t)(0x6800 | (reg << 3))) dereference = true;
    }
    return stack_arg && size_arg && dereference;
}

int ib32_patch_ticket_check(struct iboot_img* iboot_in) {
#define pointer(p) (__pointer[0] = (uint32_t)p & 0xff, __pointer[1] = ((uint32_t)p/0x100) & 0xff, __pointer[2] = ((uint32_t)p/0x10000) & 0xff, __pointer[3] = ((uint32_t)p/0x1000000) & 0xff, _pointer)
    char __pointer[4];
    char *_pointer = __pointer;
    printf("%s: Entering...\n", __FUNCTION__);
    char *NOPstart = NULL;
    char *NOPstop = NULL;

    const char* iboot_vers_str = ib32_memstr(iboot_in->buf, iboot_in->len, "iBoot-");
    if (!iboot_vers_str) {
        printf("%s: Unable to find iboot_vers_str!\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found iBoot baseaddr %p\n", __FUNCTION__, (void*)(uintptr_t)ib32_get_iboot_base_address(iboot_in->buf));
    printf("%s: Found iboot_vers_str at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, iboot_vers_str));

    uint32_t vers_str_iboot = (uint32_t)IB32_ADDRESS(iboot_in,iboot_vers_str);
    char *str_pointer = MEMMEM_RELATIVE(iboot_in, iboot_vers_str, pointer(vers_str_iboot), 4);
    if (!str_pointer) {
        printf("%s: Unable to find str_pointer!\n", __FUNCTION__);
        return 0;
    }

    printf("%s: Found str_pointer at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, str_pointer));

    uint32_t str_pointer_iboot = (uint32_t)IB32_ADDRESS(iboot_in,str_pointer);
    unsigned char *bytes = iboot_in->buf;
    char *iboot_str_xref = NULL;
    char *ldr_intruction = NULL;
    const char *needle = pointer(str_pointer_iboot);
    /* The version pointer has several users. Select the verifier's literal
       load by checking its exact target and the following call sequence. */
    for (size_t ref = 0; ref + 4 <= iboot_in->len; ref++) {
        if (memcmp(bytes + ref, needle, 4)) continue;
        size_t first = ref > 0x100 ? ref - 0x100 : 0;
        first = (first + 1) & ~(size_t)1;
        for (size_t at = first; at + 12 <= iboot_in->len && at + 2 <= ref; at += 2) {
            uint16_t load = ib32_ticket_halfword(bytes + at);
            if (!ib32_ticket_call_shape(bytes + at) ||
                ((at + 4) & ~(size_t)3) + (size_t)(load & 0xff) * 4 != ref ||
                ib32_bl_search_down(bytes + at + 8, 4) != bytes + at + 8)
                continue;
            if (ldr_intruction) {
                printf("%s: Ambiguous ticket verifier references!\n", __FUNCTION__);
                return 0;
            }
            iboot_str_xref = (char *)bytes + ref;
            ldr_intruction = (char *)bytes + at;
        }
    }
    if (!ldr_intruction) {
        printf("%s: Unable to find ticket verifier reference!\n", __FUNCTION__);
        return 0;
    }

    printf("%s: Found ticket verifier reference at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, iboot_str_xref));
    printf("%s: Found ldr_intruction at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, ldr_intruction));

    char *last_good_bl = ldr_intruction + 8;
    if (!ib32_image_contains(iboot_in, last_good_bl, 0x106)) {
        printf("%s: Ticket verifier call lies too close to image end!\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found last_good_bl at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, last_good_bl));
    last_good_bl +=4;

    char *next_pop = ib32_pop_search(last_good_bl,0x100,0);
    if (!next_pop) {
        printf("%s: Unable to find next_pop!\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found next_pop at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, next_pop));
    printf("%s: Found next_pop at %p...\n", __FUNCTION__, (void*) IB32_ADDRESS(iboot_in, next_pop));

    if (next_pop < (char *)iboot_in->buf + 0x20) {
        printf("%s: Ticket verifier return lies too close to image start!\n", __FUNCTION__);
        return 0;
    }
    char *last_branch = ib32_branch_search(next_pop,0x20,1);
    char *prev_mov_r0_fail = ib32_pattern_search(next_pop, 0x20, bswap32(0x4ff0ff30), bswap32(0x4ff0ff30), -2);

    if (prev_mov_r0_fail && (!last_branch || prev_mov_r0_fail > last_branch)) {
        printf("%s: Detected prev_mov_r0_fail at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, prev_mov_r0_fail));
        last_branch = prev_mov_r0_fail-2; //last branch is a BL
    }

    if (!last_branch) {
        printf("%s: Unable to find last_branch!\n", __FUNCTION__);
        return 0;
    }
    if (last_branch + 2 < last_good_bl + 8 || last_branch >= next_pop ||
        !ib32_image_contains(iboot_in, last_branch + 2, 4)) {
        printf("%s: Invalid ticket verifier patch span!\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found last_branch at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, last_branch));

    printf("%s: Patching in mov.w r0, #0 at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, last_good_bl));
    *(uint32_t*)last_good_bl = bswap32(0x4ff00000);
    last_good_bl +=4;

    printf("%s: Patching in mov.w r1, #0 at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, last_good_bl));
    *(uint32_t*)last_good_bl = bswap32(0x4ff00001);
    last_good_bl +=4;

    NOPstart = last_good_bl;
    NOPstop = last_branch+2;

    printf("%s: NOPing useless stuff at %p to %p ...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, NOPstart),  (void*) IB32_FILE_OFFSET(iboot_in, NOPstop));

    while (NOPstart<NOPstop) {
        NOPstart[0] = 0x00;
        NOPstart[1] = 0xBF; //NOP
        NOPstart +=2;
    }

    if (*(uint32_t*)NOPstop == bswap32(0x4ff0ff30)){ //mov.w      r0, #0xffffffff
        printf("%s: Detected mov r0, #0xffffffff at NOPstop\n", __FUNCTION__);
        printf("%s: Applying additional mov.w r0, #0 patch at %p...\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, NOPstop));
        /* mov.w      r0, #0xffffffff -->  mov.w      r0, #0x0 */
        *(uint32_t*)NOPstop = bswap32(0x4ff00000);
    }

    printf("%s: Leaving...\n", __FUNCTION__);
    return 1;
}

int ib32_patch_dualboot_ibss(struct iboot_img* iboot_in) {
    printf("%s: Entering...\n", __FUNCTION__);

    uint32_t iBootType = ib32_get_iBoot_type(iboot_in);
    if (iBootType != IBOOT_TYPE_IBSS) {
        printf("%s: This image is not an iBSS!\n", __FUNCTION__);
        return 0;
    }

    int osVersion = ib32_get_os_version(iboot_in);
    if (osVersion < 5 && ib32_has_kernel_load(iboot_in)) {
        printf("%s: Detected iBSS is pre-iOS 5! Please use an iBEC instead!\n", __FUNCTION__);
        return 0;
    }

    void* kloader_addr = ib32_find_kloader_addr(iboot_in);
    if (!kloader_addr) {
        printf("%s: Failed to find kloader MOV!\n", __FUNCTION__);
        return 0;
    }

    printf("%s: Found kloader MOV at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, kloader_addr));

    void* platform_str = ib32_find_platform(iboot_in);
    if (!platform_str) {
        printf("%s: Failed to get platform!\n", __FUNCTION__);
        return 0;
    }

    uint32_t platform = *(uint32_t*)(platform_str + strlen(PLATFORM_INIT_STR));

    if (platform == PLATFORM_8920 || platform == PLATFORM_8922) {
        printf("%s: Using 920 patch!\n", __FUNCTION__);
        *(uint32_t*)kloader_addr = bswap32(0xC6F6D071);
    } else if (platform == PLATFORM_8930 || platform == PLATFORM_8950 || platform == PLATFORM_8955) {
        printf("%s: Image is not 920 or 940. Using default patch!\n", __FUNCTION__);
        *(uint32_t*)kloader_addr = bswap32(0xC7F6D074);
    } else if (platform == PLATFORM_8940 || platform == PLATFORM_8942 || platform == PLATFORM_8945 || platform == PLATFORM_8947) {
        printf("%s: Using 940 patch!\n", __FUNCTION__);
        *(uint32_t*)kloader_addr = bswap32(0xCBF6D074);
    } else {
        printf("%s: Unsupported platform %x\n", __FUNCTION__, platform);
        return 0;
    }

    void* usb = ib32_find_usb_wait_for_image(iboot_in);
    if (!usb) {
        printf("%s: Failed to find usb_wait_for_image()!\n", __FUNCTION__);
        return 0;
    }

    printf("%s: Found usb_wait_for_image() at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, usb));

    *(uint32_t*)usb = bswap32(0x00BF00BF);

    void* blt = ib32_branch_thumb_conditional_search(usb, 10, 0);
    if (!blt) {
        printf("%s: Failed to find BLT to patch!\n", __FUNCTION__);
        return 0;
    }

    printf("%s: Found BLT at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, blt));

    *(uint16_t*) blt = bswap16(0x00BF);

    return 1;
}

int ib32_patch_dualboot_ibec(struct iboot_img* iboot_in) {
    printf("%s: Entering...\n", __FUNCTION__);

    uint32_t iBootType = ib32_get_iBoot_type(iboot_in);
    if (iBootType != IBOOT_TYPE_IBEC) {
        printf("%s: This image is not an iBEC!\n", __FUNCTION__);
        return 0;
    }

    void* fsboot = ib32_find_fsboot_boot_command(iboot_in);
    if (!fsboot) {
        printf("%s: Failed to find fsboot!\n", __FUNCTION__);
        return 0;
    }

    void* upgrade = ib32_memstr(iboot_in->buf, iboot_in->len, "upgrade");
    if (!upgrade) {
        printf("%s: Failed to find upgrade str!\n", __FUNCTION__);
        return 0;
    }

    printf("%s: Found upgrade at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, upgrade));

    *(uint32_t*)fsboot = IB32_ADDRESS(iboot_in, upgrade);

    void* auto_boot_false = ib32_find_auto_boot(iboot_in);
    if (!auto_boot_false) {
        printf("%s: Failed to find auto-boot=false!\n", __FUNCTION__);
        return 0;
    }

    void* true_str = ib32_memstr(iboot_in->buf, iboot_in->len, "true");
    if (!true_str) {
        printf("%s: Failed to find true str!\n", __FUNCTION__);
        return 0;
    }

    printf("%s: Found true str at %p\n", __FUNCTION__, (void*) IB32_FILE_OFFSET(iboot_in, true_str));

    *(uint32_t*)auto_boot_false = IB32_ADDRESS(iboot_in, true_str);

    return 1;
}

int ib32_patch_dualboot(struct iboot_img* iboot_in) {
    printf("%s: Entering...\n", __FUNCTION__);

    uint32_t imageType = ib32_get_iBoot_type(iboot_in);
    int ret = 0;

    if (imageType == IBOOT_TYPE_IBSS) {
        ret = ib32_patch_dualboot_ibss(iboot_in);
    } else if (imageType == IBOOT_TYPE_IBEC) {
        ret = ib32_patch_dualboot_ibec(iboot_in);
    } else {
        printf("%s: Image must be either iBSS or iBEC!\n", __FUNCTION__);
        return 0;
    }

    if (!ret) {
        printf("%s: Failed to apply dualboot patches!\n", __FUNCTION__);
        return 0;
    }

    return 1;
}

/* IMG2 authentication checks share a byte comparator. Keep CRC checks intact. */
static uint16_t ios1_h(const struct iboot_img *i, size_t p) {
    const unsigned char *b=i->buf; return b[p]|(uint16_t)b[p+1]<<8;
}
static uint32_t ios1_w(const struct iboot_img *i,size_t p) {
    return ios1_h(i,p)|(uint32_t)ios1_h(i,p+2)<<16;
}
static size_t ios1_bl(const struct iboot_img *i,size_t p) {
    if(p>i->len || i->len-p<4) return SIZE_MAX;
    uint16_t a=ios1_h(i,p),b=ios1_h(i,p+2);
    if((a&0xf800)!=0xf000 || (b&0xf800)!=0xf800) return SIZE_MAX;
    int32_t delta=((a&0x7ff)<<12)|((b&0x7ff)<<1);
    if(delta&0x400000) delta-=0x800000;
    int64_t target=(int64_t)p+4+delta;
    return target>=0x340 && (uint64_t)target+40<=i->len ? (size_t)target:SIZE_MAX;
}
static int ios1_memcmp(const struct iboot_img *i,size_t p) {
    static const unsigned char code[]={0x70,0xb5,0x04,0x1c,0x16,0x1c,0x00,0x20,0x00,0x25,0x08,0xe0,
        0x22,0x78,0x0b,0x78,0x01,0x35,0xd0,0x1a,0xc0,0xb2,0x00,0x28,0x03,0xd1,
        0x01,0x34,0x01,0x31,0xae,0x42,0xf4,0xd1,0x40,0xb2,0x70,0xbd};
    return p<=i->len && sizeof(code)<=i->len-p && !memcmp((char*)i->buf+p,code,sizeof(code));
}
static int ios1_checks(const struct iboot_img *i,size_t *header,size_t *data) {
    size_t a=SIZE_MAX,b=SIZE_MAX,callee=SIZE_MAX;
    for(size_t p=0x348;p+12<=i->len;p+=2) {
        uint16_t size=ios1_h(i,p);
        if((size!=0x2220 && size!=0x2240) || ios1_h(i,p+6)!=0x2800) continue;
        size_t dest=ios1_bl(i,p+2);
        if(dest==SIZE_MAX || !ios1_memcmp(i,dest)) continue;
        if(size==0x2220) {
            uint16_t mov=ios1_h(i,p-8),shift=ios1_h(i,p-6),add=ios1_h(i,p-4);
            unsigned r=(mov>>8)&7;
            if((mov&0xf8ff)!=0x20f8 || shift!=(0x0080|(r<<3)|r) ||
               add!=(0x1800|(r<<6)|(4<<3)) || (ios1_h(i,p-2)&0xff00)!=0xa900 ||
               (ios1_h(i,p+8)&0xff00)!=0xd000) continue;
            if(a!=SIZE_MAX || (callee!=SIZE_MAX && callee!=dest)) return 0;
            a=p+2;callee=dest;
        } else {
            if(ios1_h(i,p-4)!=0x3020 || (ios1_h(i,p-2)&0xff00)!=0xa900 ||
               (ios1_h(i,p+8)&0xff00)!=0xd100 ||
               !((ios1_h(i,p-6)&0xffc7)==0x1c00 && ((ios1_h(i,p-6)>>3)&7)>=4)) continue;
            if(b!=SIZE_MAX || (callee!=SIZE_MAX && callee!=dest)) return 0;
            b=p+2;callee=dest;
        }
    }
    /* Fallback for iBoot-159: the size encoding and surrounding instructions
     * differ from iBoot-204. Search for any BL to the memcmp byte-comparator
     * that is immediately followed by CMP R0,#0 and a conditional branch. */
    if(a==SIZE_MAX || b==SIZE_MAX) {
        a=b=SIZE_MAX;
        for(size_t p=0x348;p+8<=i->len;p+=2) {
            size_t dest=ios1_bl(i,p);
            if(dest==SIZE_MAX || !ios1_memcmp(i,dest)) continue;
            if(ios1_h(i,p+4)!=0x2800) continue;        /* CMP R0,#0 */
            uint16_t branch=ios1_h(i,p+6);
            if((branch&0xf000)!=0xd000) continue;       /* BCc */
            if(a==SIZE_MAX) a=p;
            else if(b==SIZE_MAX) b=p;
            else return 0;
        }
    }
    if(a==SIZE_MAX || b==SIZE_MAX || b<=a || b-a>0x1000) return 0;
    *header=a;*data=b;return 1;
}
int ib32_ios1_info(struct iboot_img *i) {
    if(i->len<0x340 || ios1_w(i,0)!=0xea00000e || ios1_w(i,4)!=0xe59ff018) return 0;
    uint32_t entry=ios1_w(i,0x20);
    if(entry!=0x18000040 && entry!=0x22000040) return 0;
    unsigned count=0;uint32_t version=0;
    const unsigned char *b=i->buf;
    for(size_t p=0x40;p+9<i->len;p++) if(!memcmp(b+p,"iBoot-",6)) {
        unsigned v=0,n=0;size_t q=p+6;
        while(q<i->len && b[q]>='0' && b[q]<='9' && n++<6) v=v*10+b[q++]-'0';
        if(!n || v<159 || v>204 || q==i->len || (b[q]!='.' && b[q]!=0)) return 0;
        version=v;++count;
    }
    if(count>1) return 0;
    size_t h,d;
    if(!ios1_checks(i,&h,&d)) return 0;
    i->VERS=version;return 1; /* LLB has no embedded version banner. */
}
static int ios1_pwnage(struct iboot_img *i);
int ib32_patch_ios1_img2(struct iboot_img *i) {
    size_t h,d;
    if(!ios1_checks(i,&h,&d)) { fprintf(stderr,"Cannot validate unique IMG2 authentication checks\n"); return 0; }
    const unsigned char op[]={0x00,0x20,0xc0,0x46}; /* MOVS R0,#0; ARMv6 NOP */
    memcpy((char*)i->buf+h,op,4);memcpy((char*)i->buf+d,op,4);
    printf("[+] Patched IMG2 authenticated header/data checks at 0x%zx / 0x%zx\n",h,d);
    return !ib32_has_kernel_load(i) || ios1_pwnage(i);
}
static size_t ios1_literal(const struct iboot_img *i,size_t p,unsigned *reg) {
    uint16_t h=ios1_h(i,p);
    if((h&0xf800)!=0x4800) return SIZE_MAX;
    size_t at=((p+4)&~(size_t)3)+(h&255)*4;
    if(at>i->len || i->len-at<4) return SIZE_MAX;
    *reg=(h>>8)&7;return at;
}

/* Patch storage must lie within the startup copy, before BSS/padding. */
static size_t ios1_initialized_limit(const struct iboot_img *i) {
    uint32_t base = ib32_get_iboot_base_address(i->buf);
    size_t limit = 0, count = 0;
    for (size_t at = 0x40; at + 24 <= 0x200; at += 4) {
        uint32_t first = ios1_w(i,at), second = ios1_w(i,at+4);
        if ((first&0xfffff000) != 0xe59f1000 || (second&0xfffff000) != 0xe59f2000 ||
            ios1_w(i,at+8) != 0xe4903004 || ios1_w(i,at+12) != 0xe2522004 ||
            ios1_w(i,at+16) != 0xe4813004 || ios1_w(i,at+20) != 0x1afffffb) continue;
        size_t dest = at+8+(first&0xfff), size = at+12+(second&0xfff);
        if (dest+4 > i->len || size+4 > i->len || ios1_w(i,dest) != base) continue;
        uint32_t value = ios1_w(i,size);
        if (value < 0x340 || value > i->len || (value&3)) continue;
        limit = value; ++count;
    }
    return count == 1 ? limit : 0;
}

static size_t ios1_usage_storage(const struct iboot_img *i) {
    static const char prefix[] = "Usage: \n\0\0\0\0\t%s init\n";
    static const char suffix[] = "parameters in square '[]' brackets are optional\n";
    const unsigned char *bytes = i->buf;
    size_t limit = ios1_initialized_limit(i), found = SIZE_MAX, count = 0;
    for (size_t at = 0x340; at+412 <= limit; at += 4) {
        if (memcmp(bytes+at,prefix,sizeof(prefix)-1)) continue;
        size_t end = at;
        while (end+sizeof(suffix) <= limit && end-at < 0x1000 &&
               memcmp(bytes+end,suffix,sizeof(suffix))) ++end;
        if (end-at < 412 || end+sizeof(suffix) > limit || end-at >= 0x1000) continue;
        int printable = 1;
        for (size_t n = at; n < end; ++n)
            if (bytes[n] && bytes[n] != '\t' && bytes[n] != '\n' &&
                (bytes[n] < 32 || bytes[n] > 126)) printable = 0;
        if (printable) { found = at; ++count; }
    }
    return count == 1 ? found : SIZE_MAX;
}

static int ios1_pwnage(struct iboot_img *i) {
    unsigned char *bytes = i->buf;
    uint32_t base = ib32_get_iboot_base_address(i->buf);
    size_t guard = SIZE_MAX, header = 0, table = 0, count = 0;
    /* The CRC/count/table descriptor identifies the S5L8900 ROM. */
    for (size_t at = 0x344; at + 18 <= i->len; at += 2) {
        unsigned reg;
        size_t literal = ios1_literal(i, at, &reg);
        if (literal == SIZE_MAX || reg != 1 || ios1_bl(i, at-4) == SIZE_MAX ||
            ios1_h(i,at+2) != 0x680b || ios1_h(i,at+4) != 0x1c02 ||
            ios1_h(i,at+6) != 0x4298 || (ios1_h(i,at+8)&0xff00) != 0xd100 ||
            ios1_h(i,at+10) != 0x688c || ios1_h(i,at+12) != 0x684d ||
            ios1_h(i,at+14) != 0x2c00 || (ios1_h(i,at+16)&0xff00) != 0xd000) continue;
        uint32_t pointer = ios1_w(i,literal);
        if (pointer < base || pointer-base > i->len-12) continue;
        size_t desc = pointer-base;
        uint32_t source = ios1_w(i,desc+8);
        if (ios1_w(i,desc) != 0xb8ffefce || ios1_w(i,desc+4) != 11 ||
            source < base || source-base > i->len-11*12) continue;
        size_t data = source-base;
        if (ios1_w(i,data) || ios1_w(i,data+4) != 0x770 || ios1_w(i,data+8) != 0xe3500440 ||
            ios1_w(i,data+12) || ios1_w(i,data+16) != 0x940 || ios1_w(i,data+20) != 0xe3500440) continue;
        int valid = 1;
        for (size_t n = 0; n < 11; ++n) {
            uint32_t kind = ios1_w(i,data+n*12), offset = ios1_w(i,data+n*12+4);
            uint32_t value = ios1_w(i,data+n*12+8);
            if (kind > 1 || (offset & 3) || offset >= 0x10000 ||
                (kind && (value < base || value-base >= i->len))) valid = 0;
        }
        if (!valid) continue;
        guard = at+8; header = desc; table = data; ++count;
    }
    if (count != 1) {
        fprintf(stderr,"Expected one S5L8900 ROM patch table, found %zu\n",count);
        return 0;
    }

    size_t epoch = SIZE_MAX, outer = SIZE_MAX, epochs = 0, outers = 0;
    unsigned inner_epoch = 0, outer_epoch = 0;
    static const char message[] = "Ignoring image with mismatching security epoch\n";
    static const unsigned char outer_code[] = {
        0x52,0x46,0x00,0x23,0x04,0x93,0xd3,0x8f,0x03,0x2b,0x01,0xd0,0x01,0x23,0x04,0x93
    };
    for (size_t at = 0x340; at + 16 <= i->len; at += 2) {
        if (ios1_h(i,at) == 0x8963 && (ios1_h(i,at+2)&0xfffe) == 0x2b02 &&
            ios1_h(i,at+4) == 0xd003 && ios1_bl(i,at+8) != SIZE_MAX &&
            (ios1_h(i,at+12)&0xf800) == 0xe000) {
            unsigned reg; size_t literal = ios1_literal(i,at+6,&reg);
            if (literal != SIZE_MAX && reg == 0) {
                uint32_t pointer = ios1_w(i,literal);
                if (pointer >= base && pointer-base <= i->len-sizeof(message) &&
                    !memcmp(bytes+pointer-base,message,sizeof(message))) {
                    epoch = at+12; inner_epoch = ios1_h(i,at+2)&255; ++epochs;
                }
            }
        }
        if (!memcmp(bytes+at,outer_code,8) &&
            (ios1_h(i,at+8)&0xfffe) == 0x2b02 &&
            !memcmp(bytes+at+10,outer_code+10,sizeof(outer_code)-10)) {
            outer = at+10; outer_epoch = ios1_h(i,at+8)&255; ++outers;
        }
    }
    /* Later IMG2 loaders need one epoch check per IMG2/8900 path. */
    if ((i->VERS >= 204 && (epochs != 1 || outers != 1 || inner_epoch != outer_epoch)) ||
        (i->VERS < 204 && (epochs || outers))) {
        fputs("Cannot validate IMG2/8900 security-epoch checks\n",stderr);
        return 0;
    }
    size_t destination = ios1_usage_storage(i), limit = ios1_initialized_limit(i);
    static const char diagnostic[] = "[FTL:ERR]  there is error on WMR_MALLOC!\n";
    size_t diagnostics = 0;
    for (size_t at = 0x340; at+13*12 <= limit; at += 4) {
        if (!memcmp(bytes+at,diagnostic,sizeof(diagnostic))) { destination = at; ++diagnostics; }
    }
    if (diagnostics > 1 || destination == SIZE_MAX || destination+13*12 > limit) {
        fputs("Cannot validate initialized storage for the extended ROM patch table\n",stderr);
        return 0;
    }
    memcpy(bytes+destination,bytes+table,11*12);
    const uint32_t extra[] = {0,0x77c,0xe3a00001,0,0x57f4,0xe3a00001};
    memcpy(bytes+destination+11*12,extra,sizeof(extra));
    uint32_t n = 13, pointer = base+(uint32_t)destination;
    memcpy(bytes+header+4,&n,4); memcpy(bytes+header+8,&pointer,4);
    uint16_t nop = 0x46c0, branch = 0xe001;
    memcpy(bytes+guard,&nop,2);
    if (epochs) {
        memcpy(bytes+epoch,&nop,2); memcpy(bytes+outer,&branch,2);
        printf("[+] Relaxed IMG2/8900 security epochs at %#zx / %#zx\n",epoch,outer);
    }
    printf("[+] Extended S5L8900 ROM patch table at %#zx, CRC guard at %#zx\n",destination,guard);
    return 1;
}

int ib32_patch_ios1_bootargs(struct iboot_img *i,const char *args) {
    if(strlen(args)>255) { fputs("iPhone OS 1 boot arguments must fit 255 bytes\n",stderr); return 0; }
    size_t selected=SIZE_MAX,slot=SIZE_MAX;
    uint32_t base=ib32_get_iboot_base_address(i->buf);
    for(size_t p=0x340;p+14<=i->len;p+=2) {
        unsigned reg;size_t l=ios1_literal(i,p,&reg);
        if(l==SIZE_MAX || reg!=0) continue;
        uint32_t pointer=ios1_w(i,l);
        if(pointer<base || pointer-base>i->len-10 || memcmp((char*)i->buf+pointer-base,"boot-args",10)) continue;
        for(size_t q=p+2;q<=p+8;q+=2) {
            if(ios1_bl(i,q)==SIZE_MAX || (ios1_h(i,q+4)!=0x1c03 && ios1_h(i,q+4)!=0x1e03) ||
               (ios1_h(i,q+6)&0xff00)!=0xd100) continue;
            size_t pc=(q+4)&~(size_t)3;
            if(l<pc || l-pc>1020 || ((l-pc)&3) || selected!=SIZE_MAX) return 0;
            selected=q;slot=l;
        }
    }
    if(selected==SIZE_MAX) { fputs("Cannot validate iPhone OS 1 boot-argument lookup\n",stderr); return 0; }
    size_t usage=ios1_usage_storage(i);
    if(usage==SIZE_MAX) { fputs("Cannot validate initialized boot-argument storage\n",stderr); return 0; }
    /* Reserve 156 bytes for the ROM table, then up to 255 for arguments. */
    size_t dest=usage+156;
    memcpy((char*)i->buf+dest,args,strlen(args)+1);
    uint32_t pointer=base+(uint32_t)dest;memcpy((char*)i->buf+slot,&pointer,4);
    uint16_t code=0x4800|(uint16_t)((slot-((selected+4)&~(size_t)3))/4),nop=0x46c0;
    memcpy((char*)i->buf+selected,&code,2);memcpy((char*)i->buf+selected+2,&nop,2);
    printf("[+] Forced iPhone OS 1 boot arguments at 0x%zx\n",selected);return 1;
}
int ib32_patch_ios1_debug(struct iboot_img *i) {
    uint32_t base=ib32_get_iboot_base_address(i->buf);size_t selected=SIZE_MAX;
    for(size_t p=0x340;p+44<=i->len;p+=2) {
        unsigned reg;size_t l=ios1_literal(i,p,&reg);
        if(l==SIZE_MAX || reg!=3) continue;
        uint32_t pointer=ios1_w(i,l);
        if(pointer<base || pointer-base>i->len-14 || memcmp((char*)i->buf+pointer-base,"debug-enabled",14)) continue;
        for(size_t q=p+8;q<p+36;q+=2) if(ios1_h(i,q)==0x2020 && ios1_bl(i,q+2)!=SIZE_MAX &&
                ios1_h(i,q+6)==0x2800 && (ios1_h(i,q+8)&0xff00)==0xd000) {
            if(selected!=SIZE_MAX) return 0;selected=q+2;
        }
    }
    if(selected==SIZE_MAX) { fputs("Cannot validate iPhone OS 1 debug-property lookup\n",stderr); return 0; }
    const unsigned char op[]={1,0x20,0xc0,0x46};memcpy((char*)i->buf+selected,op,4);
    printf("[+] Enabled iPhone OS 1 kernel debugging at 0x%zx\n",selected);return 1;
}
