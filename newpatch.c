/*
 * newpatch.c - functions patching unpacked iOS IM4P bootloader files
 *
 * Copyright 2020 dayt0n
 *
 * This file is part of kairos.
 *
 * kairos is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * kairos is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with kairos.  If not, see <https://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#include "newpatch.h"

#ifdef _WIN32
void *memmem(const void *haystack, size_t haystack_len, 
    const void * const needle, const size_t needle_len)
{
    if (haystack == NULL) return NULL; // or assert(haystack != NULL);
    if (haystack_len == 0) return NULL;
    if (needle == NULL) return NULL; // or assert(needle != NULL);
    if (needle_len == 0) return NULL;

    for (const char *h = haystack;
            haystack_len >= needle_len;
            ++h, --haystack_len) {
        if (!memcmp(h, needle, needle_len)) {
            return h;
        }
    }
    return NULL;
}
#endif

static uint32_t a64_word(const struct iboot64_img* image, size_t p) {
	uint32_t value;
	memcpy(&value, (const uint8_t *)image->buf + p, sizeof(value));
	return value;
}

static uint64_t a64_pointer(const struct iboot64_img* image, size_t p) {
	uint64_t value;
	memcpy(&value, (const uint8_t *)image->buf + p, sizeof(value));
	return value;
}

static int64_t a64_signed(uint32_t value, unsigned bits) {
	return (int64_t)(value & ((1u << bits) - 1)) -
		((value & (1u << (bits - 1))) ? (1LL << bits) : 0);
}

static int a64_address(const struct iboot64_img* image, size_t p,
	unsigned* reg, size_t* address, size_t* width) {
	if(p > image->len || image->len - p < 4)
		return 0;
	uint32_t op = a64_word(image, p);
	int64_t displacement = a64_signed(((op >> 5) & 0x7ffff) << 2 |
		((op >> 29) & 3), 21), target;
	*reg = op & 31;
	*width = 4;
	if((op & 0x9f000000) == 0x10000000) {
		target = (int64_t)p + displacement;
	} else if((op & 0x9f000000) == 0x90000000 && image->len - p >= 8) {
		uint32_t add = a64_word(image, p + 4);
		if((add & 0xffc00000) != 0x91000000 ||
			((add >> 5) & 31) != *reg || (add & 31) != *reg)
			return 0;
		target = (int64_t)((image->base + p) & ~(uint64_t)0xfff) -
			(int64_t)image->base + displacement * 4096 + ((add >> 10) & 0xfff);
		*width = 8;
	} else {
		return 0;
	}
	if(*reg == 31 || target < 0 || (uint64_t)target >= image->len)
		return 0;
	*address = (size_t)target;
	return 1;
}

static size_t a64_xref(const struct iboot64_img* image, size_t target) {
	for(size_t p = 0; p + 4 <= image->len; p += 4) {
		unsigned reg;
		size_t address, width;
		if(a64_address(image, p, &reg, &address, &width) && address == target)
			return p;
	}
	return 0;
}

static int a64_prologue(uint32_t op) {
	return (op & 0xffc003ff) == 0xd10003ff || // SUB SP,SP,#imm
		(op & 0xffc003e0) == 0xa98003e0; // STP Xn,Xm,[SP,#-imm]!
}

static size_t a64_function(const struct iboot64_img* image, size_t ref) {
	if(ref >= image->len || (ref & 3))
		return 0;
	size_t limit = ref > 0x2000 ? ref - 0x2000 : 0x340;
	for(size_t p = ref; p >= limit && p >= 0x340; p -= 4) {
		if((a64_word(image, p) & 0xffc003ff) != 0x910003fd)
			continue; // ADD X29,SP,#imm
		for(size_t q = p; q >= 0x344 && p - q < 128; q -= 4)
			if(a64_prologue(a64_word(image, q - 4))) {
				size_t start = q - 4;
				if(start >= 4 && a64_word(image, start - 4) == 0xd503237f)
					start -= 4; // Include PACIBSP.
				return start;
			}
		return 0;
	}
	return 0;
}

static size_t a64_bl_target(const struct iboot64_img* image, size_t p) {
	if(p > image->len || image->len - p < 4)
		return 0;
	uint32_t op = a64_word(image, p);
	if((op & 0xfc000000) != 0x94000000)
		return 0;
	int64_t target = (int64_t)p + a64_signed(op & 0x03ffffff, 26) * 4;
	return target >= 0x340 && (uint64_t)target < image->len ? (size_t)target : 0;
}

static int a64_mov_address(const struct iboot64_img* image, size_t p,
	unsigned* reg, uint64_t* address, size_t* width) {
	if(p > image->len || image->len - p < 4)
		return 0;
	uint32_t op = a64_word(image, p), kind = op & 0xff800000;
	if(kind != 0xd2800000 && kind != 0x92800000)
		return 0; // MOVZ/MOVN Xn,#imm{,LSL #shift}
	*reg = op & 31;
	*address = (uint64_t)((op >> 5) & 0xffff) << (((op >> 21) & 3) * 16);
	if(kind == 0x92800000)
		*address = ~*address;
	*width = 4;
	while(*width < 16 && p + *width + 4 <= image->len) {
		op = a64_word(image, p + *width);
		if((op & 0xff80001f) != (0xf2800000 | *reg))
			break;
		unsigned shift = ((op >> 21) & 3) * 16;
		*address = (*address & ~((uint64_t)0xffff << shift)) |
			((uint64_t)((op >> 5) & 0xffff) << shift);
		*width += 4;
	}
	return *reg != 31;
}

// iOS 7 loads cached words before the reader, using separate absolute addresses.
static size_t a64_nonce_cache_early(const struct iboot64_img* image, size_t call) {
	if(call < 0x380 || image->len - call < 68)
		return 0;
	for(size_t branch = call - 4; branch + 128 > call && branch >= 0x344; branch -= 4) {
		uint32_t test = a64_word(image, branch), flag = a64_word(image, branch - 4);
		if((test & 0xfff80000) != 0x36080000 || // TBZ Wn,#1,reader
			(int64_t)branch + a64_signed((test >> 5) & 0x3fff, 14) * 4 != (int64_t)call ||
			(flag & 0xffc00000) != 0xb9400000 || (flag & 31) != (test & 31))
			continue;
		unsigned low_base, high_base, store_base, second_base;
		uint64_t low, high, stored_low, stored_high;
		size_t width, p = branch + 4;
		if(!a64_mov_address(image, p, &low_base, &low, &width))
			continue;
		p += width;
		if(p + 4 > call || a64_word(image, p) != (0xb9400000 | (low_base << 5)))
			continue;
		p += 4;
		if(!a64_mov_address(image, p, &high_base, &high, &width))
			continue;
		p += width;
		if(p + 8 != call)
			continue;
		uint32_t high_load = a64_word(image, p), skip = a64_word(image, p + 4),
			split = a64_word(image, call + 4);
		unsigned high_reg = split & 31;
		if((split & 0xffffffe0) != 0xd360fc00 ||
			high_reg == 0 || high_reg == 31 ||
			high_load != (0xb9400000 | (high_base << 5) | high_reg) ||
			(skip & 0xfc000000) != 0x14000000 || high != low + 4)
			continue;
		size_t skip_at = p + 4;
		p = call + 8;
		if(!a64_mov_address(image, p, &store_base, &stored_low, &width))
			continue;
		p += width;
		if(p + 4 > image->len || a64_word(image, p) != (0xb9000000 | (store_base << 5)))
			continue;
		p += 4;
		if(!a64_mov_address(image, p, &second_base, &stored_high, &width))
			continue;
		p += width;
		if(p + 16 > image->len ||
			a64_word(image, p) != (0xb9000000 | (second_base << 5) | high_reg) ||
			stored_low != low || stored_high != high)
			continue;
		uint32_t load_flag = a64_word(image, p + 4), set_flag = a64_word(image, p + 8),
			store_flag = a64_word(image, p + 12);
		unsigned flag_reg = load_flag & 31;
		if((load_flag & ~31u) != (flag & ~31u) ||
			(set_flag & 0xfffffc00) != 0x321f0000 ||
			((set_flag >> 5) & 31) != flag_reg || (set_flag & 31) != flag_reg ||
			store_flag != (load_flag & ~0x00400000u) ||
			(int64_t)skip_at + a64_signed(skip & 0x03ffffff, 26) * 4 != (int64_t)p + 16)
			continue;
		return branch;
	}
	return 0;
}

// Require both cache paths to use the same PMGR scratch words.
static size_t a64_nonce_cache(const struct iboot64_img* image, size_t call) {
	if(call < 12 || image->len - call < 44)
		return 0;
	size_t branch = call - 4;
	if(a64_word(image, branch) == 0x52800000) // MOV W0,#0 (force_random = false)
		branch -= 4;
	uint32_t test = a64_word(image, branch), flag = a64_word(image, branch - 4);
	if((test & 0xfff80000) != 0x37080000 || // TBNZ Wn,#1,cached
		(flag & 0xffc00000) != 0xb9400000 || (flag & 31) != (test & 31))
		return 0;
	unsigned base = (flag >> 5) & 31;
	if(base == 31)
		return 0;
	int64_t cached = (int64_t)branch + a64_signed((test >> 5) & 0x3fff, 14) * 4;
	if(cached != (int64_t)call + 32 || (uint64_t)cached + 8 > image->len)
		return 0;
	uint32_t high = a64_word(image, call + 4), low_store = a64_word(image, call + 8),
		high_store = a64_word(image, call + 12), load_flag = a64_word(image, call + 16),
		set_flag = a64_word(image, call + 20), store_flag = a64_word(image, call + 24),
		join = a64_word(image, call + 28), low_load = a64_word(image, cached),
		high_load = a64_word(image, cached + 4);
	unsigned high_reg = high & 31, flag_reg = load_flag & 31;
	if((high & 0xffffffe0) != 0xd360fc00 || // LSR Xn,X0,#32
		high_reg == 0 || high_reg == 31 || flag_reg == 31 ||
		(low_store & 0xffc003ff) != (0xb9000000 | (base << 5)) ||
		(high_store & 0xffc003ff) != (0xb9000000 | (base << 5) | high_reg) ||
		((high_store >> 10) & 0xfff) != ((low_store >> 10) & 0xfff) + 1 ||
		(load_flag & ~31u) != (flag & ~31u) ||
		(set_flag & 0xfffffc00) != 0x321f0000 || // ORR Wn,Wn,#2
		((set_flag >> 5) & 31) != flag_reg || (set_flag & 31) != flag_reg ||
		store_flag != ((load_flag & ~0x00400000u)) ||
		join != 0x14000003 || // B past the two cached loads
		low_load != (low_store | 0x00400000u) ||
		high_load != (high_store | 0x00400000u))
		return 0;
	return branch;
}

// Preserve the generator so repeated nonce queries remain deterministic.
static int a64_nonce_keep_generator(const struct iboot64_img* image, size_t reader,
	size_t string, size_t getter, size_t* removal, size_t* join) {
	size_t refs[3], count = 0, end = reader + 0x600;
	if(end < reader || end > image->len)
		end = image->len;
	// Cleanup blocks can be reached by branches beyond the first RET.
	uint8_t seen[0x600 / 4] = {0};
	size_t work[0x600 / 4], work_count = 1;
	work[0] = reader;
	while(work_count) {
		size_t p = work[--work_count];
		while(p >= reader && p + 4 <= end) {
			size_t index = (p - reader) / 4;
			if(seen[index])
				break;
			seen[index] = 1;
			uint32_t op = a64_word(image, p);
			unsigned reg;
			size_t address, width;
			int direct = a64_address(image, p, &reg, &address, &width) && address == string;
			if(direct || (getter && a64_bl_target(image, p) == getter)) {
				if((direct && reg != 0) || count == 3)
					return -1;
				refs[count++] = p;
			}
			if(op == 0xd65f03c0 || op == 0xd65f0fff || op == 0xd65f0bff ||
				(op & 0xfffffc1f) == 0xd61f0000) // RET or BR
				break;
			int64_t target = -1;
			if((op & 0xfc000000) == 0x14000000) {
				target = (int64_t)p + a64_signed(op & 0x03ffffff, 26) * 4;
			} else if((op & 0xff000010) == 0x54000000) {
				target = (int64_t)p + a64_signed((op >> 5) & 0x7ffff, 19) * 4;
			} else if((op & 0x7e000000) == 0x34000000) {
				target = (int64_t)p + a64_signed((op >> 5) & 0x7ffff, 19) * 4;
			} else if((op & 0x7e000000) == 0x36000000) {
				target = (int64_t)p + a64_signed((op >> 5) & 0x3fff, 14) * 4;
			}
			if(target >= (int64_t)reader && target < (int64_t)end && !(target & 3)) {
				if(work_count == sizeof(work) / sizeof(work[0]))
					return -1;
				work[work_count++] = (size_t)target;
			}
			if((op & 0xfc000000) == 0x14000000)
				break;
			p += 4;
		}
	}
	if(!count || count > 2)
		return -1;
	if(count == 2 && refs[0] > refs[1]) {
		size_t first = refs[0];
		refs[0] = refs[1];
		refs[1] = first;
	}
	*removal = *join = 0;
	if(count == 1)
		return 0;
	unsigned reg;
	size_t address, width;
	if(!a64_address(image, refs[1], &reg, &address, &width))
		return -1;
	size_t p = refs[1] + width;
	if(p + 4 <= end && a64_word(image, p) == 0xd503201f)
		p += 4;
	if(p + 16 > end || !a64_bl_target(image, p) || !a64_bl_target(image, p + 8))
		return -1;
	uint32_t unset_result = a64_word(image, p + 4), save_result = a64_word(image, p + 12);
	if((unset_result & 0xff00001f) != 0x34000000 ||
		(save_result & 0xff00001f) != 0x34000000)
		return -1; // CBZ W0,diagnostic; BL save; CBZ W0,return
	int64_t target = (int64_t)p + 12 + a64_signed((save_result >> 5) & 0x7ffff, 19) * 4;
	if(target <= (int64_t)p + 12 || target >= (int64_t)end ||
		!seen[((size_t)target - reader) / 4])
		return -1;
	uint32_t result = a64_word(image, target);
	unsigned saved = (result >> 16) & 31;
	if((result & 0xff000000) == 0xb5000000 && (result & 31) >= 19 && (result & 31) <= 28) {
		// iOS 7 returns the saved seed or generates a random one.
		int64_t success = target + a64_signed((result >> 5) & 0x7ffff, 19) * 4;
		if(success <= target || success >= (int64_t)end ||
			!seen[((size_t)success - reader) / 4])
			return -1;
		saved = result & 31;
		int parsed = 0;
		for(size_t q = reader; q + 4 < refs[1]; q += 4)
			if((a64_word(image, q) & 0xffc003ff) == 0xf80003a0 &&
				(a64_word(image, q + 4) & 0x9f00001f) == (0x90000000 | saved))
				parsed = 1; // STUR X0,[X29,#seed]; ADRP Xsaved,success marker.
		if(!parsed)
			return -1;
		*removal = refs[1];
		*join = (size_t)target;
		return 0;
	}
	if((result & 0xffe0ffff) != 0xaa0003e0 || saved < 19 || saved > 28)
		return -1; // MOV X0,Xsaved returns the parse result.
	int success = 0;
	for(size_t q = reader; q < refs[1]; q += 4)
		if(a64_word(image, q) == (0x52800020 | saved) ||
			a64_word(image, q) == (0x320003e0 | saved))
			success = 1; // MOV Wsaved,#1
	if(!success)
		return -1;
	size_t epilogue_end = (size_t)target + 4;
	while(epilogue_end + 4 <= end &&
		a64_word(image, epilogue_end) != 0xd65f03c0 &&
		a64_word(image, epilogue_end) != 0xd65f0fff &&
		a64_word(image, epilogue_end) != 0xd65f0bff)
		epilogue_end += 4;
	if(epilogue_end + 4 > end)
		return -1;
	for(size_t q = target + 4; q < epilogue_end; q += 4) {
		uint32_t op = a64_word(image, q);
		if((op & 0xffc003ff) != 0x910003ff && // ADD SP,SP,#imm
			(op & 0xffc003ff) != 0xd10003bf && // SUB SP,X29,#imm
			(op & 0xffc003e0) != 0xa94003e0 && // LDP ..., [SP,#imm]
			(op & 0xffc003e0) != 0xa8c003e0 && // LDP ..., [SP],#imm
			op != 0xd50323ff) // AUTIBSP
			return -1;
	}
	*removal = refs[1];
	*join = (size_t)target;
	return 0;
}

int freshnonce_patch(struct iboot64_img* image) {
	const char name[] = "com.apple.System.boot-nonce";
	const uint8_t* found = memmem(image->buf, image->len, name, sizeof(name));
	if(!found) {
		WARN("Could not find ARM64 boot-nonce generator\n");
		return -1;
	}
	size_t string = found - (const uint8_t *)image->buf, selected = 0,
		selected_removal = 0, selected_join = 0;
	uint32_t selected_opcode = 0;
	for(size_t ref = 0x340; ref + 12 <= image->len; ref += 4) {
		unsigned reg;
		size_t address, width;
		if(!a64_address(image, ref, &reg, &address, &width) || address != string || reg != 0)
			continue;
		size_t readers[32], getters[32], count = 0;
		size_t direct = a64_function(image, ref);
		if(direct && ref - direct < 0x600) {
			readers[count] = direct;
			getters[count++] = 0;
		}
		// Outlined getenv stubs have no stack frame.
		size_t tail = ref + width;
		if(a64_word(image, tail) == 0xd503201f)
			tail += 4;
		if(tail + 4 <= image->len && (a64_word(image, tail) & 0xfc000000) == 0x14000000) {
			for(size_t p = 0x340; p + 4 <= image->len; p += 4) {
				if(a64_bl_target(image, p) != ref)
					continue;
				size_t caller = a64_function(image, p);
				if(!caller || p - caller > 0x600)
					continue;
				if(count == 32) {
					WARN("Too many ARM64 generator-reader candidates\n");
					return -1;
				}
				readers[count] = caller;
				getters[count++] = ref;
			}
		}
		for(size_t candidate = 0; candidate < count; candidate++) {
			size_t reader = readers[candidate];
			size_t removal, join;
			if(a64_nonce_keep_generator(image, reader, string, getters[candidate], &removal, &join) < 0)
				continue;
			for(size_t call = 0x340; call + 4 <= image->len; call += 4) {
				if(a64_bl_target(image, call) != reader)
					continue;
				size_t wrapper = a64_function(image, call);
				if(!wrapper || call - wrapper > 0x200)
					continue;
				for(size_t q = 0x340; q + 4 <= image->len; q += 4) {
					if(q != call && a64_bl_target(image, q) != wrapper)
						continue;
					size_t branch = a64_nonce_cache(image, q);
					uint32_t opcode = 0xd503201f;
					if(!branch) {
						branch = a64_nonce_cache_early(image, q);
						opcode = 0x14000000 | (uint32_t)((q - branch) / 4);
					}
					if(!branch)
						continue;
					if(selected && (selected != branch || selected_removal != removal)) {
						WARN("Ambiguous ARM64 nonce cache path\n");
						return -1;
					}
					selected = branch;
					selected_removal = removal;
					selected_join = join;
					selected_opcode = opcode;
				}
			}
		}
	}
	if(!selected) {
		WARN("Could not validate ARM64 nonce cache and generator retention\n");
		return -1;
	}
	write_opcode(image->buf, selected, selected_opcode);
	LOG("Patched ARM64 nonce cache at 0x%zx\n", selected);
	if(selected_removal) {
		uint32_t branch = 0x14000000 | (uint32_t)((selected_join - selected_removal) / 4);
		write_opcode(image->buf, selected_removal, branch);
		LOG("Preserved ARM64 boot-nonce generator at 0x%zx (join 0x%zx)\n",
			selected_removal, selected_join);
	}
	return 0;
}

static int a64_tag(const struct iboot64_img* image, size_t start,
	size_t end, uint32_t tag) {
	for(size_t p = start; p + 8 <= end; p += 4) {
		uint32_t a = a64_word(image, p), z = a64_word(image, p + 4);
		if((a & 0xffe00000) == 0x52800000 &&
			(z & 0xffe0001f) == (0x72a00000 | (a & 31)) &&
			((a >> 5) & 0xffff) == (tag & 0xffff) &&
			((z >> 5) & 0xffff) == (tag >> 16))
			return 1;
	}
	return 0;
}

static int a64_sigcheck(struct iboot64_img* image) {
	size_t selected = 0;
	for(size_t p = 0x340; p + 4 <= image->len; p += 4) {
		unsigned reg;
		size_t table, width;
		if(!a64_address(image, p, &reg, &table, &width) || reg != 2 ||
			(table & 7) || image->len - table < 24 || a64_pointer(image, table + 16))
			continue;
		uint64_t pointer = a64_pointer(image, table), next = a64_pointer(image, table + 8);
		if(pointer < image->base || pointer - image->base >= image->len ||
			next < image->base || next - image->base >= image->len || (pointer & 3) || (next & 3))
			continue;
		size_t callback = (size_t)(pointer - image->base);
		if(image->len - callback < 8 ||
			(!a64_prologue(a64_word(image, callback)) && a64_word(image, callback) != 0xd503237f))
			continue;
		size_t end = (size_t)(next - image->base);
		if(end <= callback || end - callback > 0x2000)
			continue;
		if(!a64_tag(image, callback, end, 0x454b4559) || // EKEY
			!a64_tag(image, callback, end, 0x414d4e4d) || // AMNM
			!a64_tag(image, callback, end, 0x424f5244)) // BORD
			continue;
		int stack_context = 0, call = 0;
		for(size_t q = p + width; q + 4 <= image->len && q < p + width + 32; q += 4) {
			uint32_t op = a64_word(image, q);
			if((op & 0xffc003ff) == 0x910003e4)
				stack_context = 1; // ADD X4,SP,#context
			if((op & 0xfc000000) == 0x94000000) {
				call = 1;
				break;
			}
		}
		if(!stack_context || !call)
			continue;
		if(selected && selected != callback) {
			WARN("Ambiguous ARM64 IMG4 property callback\n");
			return -1;
		}
		selected = callback;
	}
	if(!selected) {
		WARN("Could not validate ARM64 IMG4 property callback\n");
		return -1;
	}
	write_opcode(image->buf, selected, 0xd2800000); // MOV X0,#0
	write_opcode(image->buf, selected + 4, 0xd65f03c0); // RET
	LOG("Patched ARM64 IMG4 property callback at 0x%zx\n", selected);
	return 0;
}

static int a64_bootargs_context(const struct iboot64_img* image, size_t copy) {
	const uint8_t* b = image->buf;
	size_t restore = 0, ramdisk = 0;
	size_t start = copy > 0x800 ? copy - 0x800 : 0x340;
	for(size_t p = start; p < copy; p += 4) {
		unsigned reg;
		size_t target, width;
		if(!a64_address(image, p, &reg, &target, &width))
			continue;
		if(reg == 4 && image->len - target >= 6 && !memcmp(b + target, "rd=md0", 6))
			ramdisk = p;
		if(reg == 1 && image->len - target >= 10 && !memcmp(b + target, " -restore\0", 10))
			restore = p;
	}
	size_t function = a64_function(image, copy);
	return ramdisk && restore > ramdisk && function &&
		a64_function(image, ramdisk) == function && a64_function(image, restore) == function;
}

static int a64_bootargs(struct iboot64_img* image, const char* args) {
	const uint8_t* b = image->buf;
	size_t length = strlen(args), selected = 0, selected_width = 0;
	if(length > 270) {
		WARN("Boot arguments exceed 270 bytes\n");
		return -1;
	}
	for(size_t p = 0x340; p + 12 <= image->len; p += 4) {
		unsigned reg;
		size_t target, width;
		if(!a64_address(image, p, &reg, &target, &width) || reg != 4 ||
			image->len - target < 3 || memcmp(b + target, "%s\0", 3))
			continue;
		size_t store = p + width;
		if(a64_word(image, store) == 0xd503201f)
			store += 4;
		if(store + 12 > image->len ||
			(a64_word(image, store) & 0xffffffe0) != 0xf90003e0)
			continue; // STR Xn,[SP]
		size_t call = store + 4;
		if((a64_word(image, call) & 0xffe0ffff) == 0xaa0003e0)
			call += 4; // MOV X0,Xn
		if((a64_word(image, call) & 0xfc000000) != 0x94000000)
			continue;
		if(!a64_bootargs_context(image, p))
			continue;
		if(selected) {
			WARN("Ambiguous ARM64 boot-args formatting call\n");
			return -1;
		}
		selected = p;
		selected_width = width;
	}
	if(!selected) {
		WARN("Could not validate ARM64 boot-args formatting call\n");
		return -1;
	}
	char format[541];
	size_t used = 0;
	for(size_t i = 0; i < length; i++) {
		format[used++] = args[i];
		if(args[i] == '%')
			format[used++] = '%'; // Escape format specifiers.
	}
	format[used++] = 0;
	size_t run = 0, storage = 0, reserve = used < 270 ? 270 : used;
	for(size_t p = 0x340; p < image->len; p++) {
		if(!b[p]) {
			run++;
			continue;
		}
		if(!(p & 0x7ff) && run >= 512 && run >= reserve + 32) { // 2 KiB alignment
			storage = p - reserve - 16;
			break;
		}
		run = 0;
	}
	if(!storage || (int64_t)storage - (int64_t)selected < -(1LL << 20) ||
		(int64_t)storage - (int64_t)selected >= (1LL << 20)) {
		WARN("No reachable padding for ARM64 boot arguments\n");
		return -1;
	}
	memcpy((uint8_t *)image->buf + storage, format, used);
	write_opcode(image->buf, selected, new_insn_adr(selected, 4, storage));
	if(selected_width == 8)
		write_opcode(image->buf, selected + 4, 0xd503201f);
	LOG("Patched ARM64 boot-args format at 0x%zx, string at 0x%zx\n", selected, storage);
	return 0;
}

static int a64_debug(struct iboot64_img* image) {
	const uint8_t* b = image->buf;
	size_t selected = 0;
	for(size_t p = 0x340; p + 4 <= image->len; p += 4) {
		unsigned reg;
		size_t target, width;
		if(!a64_address(image, p, &reg, &target, &width) ||
			image->len - target < 14 || memcmp(b + target, "debug-enabled\0", 14))
			continue;
		unsigned calls = 0;
		for(size_t q = p + width; q + 8 <= image->len && q < p + width + 48; q += 4) {
			uint32_t op = a64_word(image, q);
			if(op == 0xd65f03c0 || (op & 0xfc000000) == 0x14000000)
				break;
			if((op & 0xfc000000) != 0x94000000 || ++calls != 2)
				continue;
			uint32_t branch = a64_word(image, q + 4);
			if((branch & 0x7e00001f) != 0x34000000)
				break; // CBZ/CBNZ W0 or X0
			if(selected && selected != q)
				return -1;
			selected = q;
			break;
		}
	}
	if(!selected) {
		WARN("Could not validate ARM64 debug permission call\n");
		return -1;
	}
	write_opcode(image->buf, selected, 0xd2800020); // MOV X0,#1
	LOG("Patched ARM64 debug permission call at 0x%zx\n", selected);
	return 0;
}

static int a64_nvram(struct iboot64_img* image) {
	const uint8_t* b = image->buf;
	const char name[] = "debug-uarts";
	size_t functions[3] = {0};
	for(size_t p = 0; p + 8 <= image->len; p += 8) {
		uint64_t pointer = a64_pointer(image, p);
		if(pointer < image->base || pointer - image->base >= image->len)
			continue;
		size_t s = pointer - image->base;
		if(image->len - s < sizeof(name) || memcmp(b + s, name, sizeof(name)))
			continue;
		size_t start = p, end = p;
		while(start >= 8 && p - start < 2048 && a64_pointer(image, start - 8))
			start -= 8;
		if(start < 8 || a64_pointer(image, start - 8))
			continue;
		while(end + 16 <= image->len && end - p < 2048 && a64_pointer(image, end))
			end += 8;
		if(end + 16 > image->len || a64_pointer(image, end))
			continue;
		size_t first = a64_function(image, a64_xref(image, start));
		size_t second = a64_function(image, a64_xref(image, end + 8));
		if(!first || !second || first == second)
			continue;
		if(functions[0] && (functions[0] != first || functions[1] != second))
			return -1;
		functions[0] = first;
		functions[1] = second;
	}
	const char system[] = "com.apple.System.";
	for(size_t p = 0; p + sizeof(system) <= image->len; p++) {
		if(memcmp(b + p, system, sizeof(system)))
			continue;
		size_t ref = a64_xref(image, p), function = a64_function(image, ref);
		if(functions[2] && function && functions[2] != function)
			return -1;
		if(function)
			functions[2] = function;
	}
	for(size_t i = 0; i < 3; i++)
		if(!functions[i] || image->len - functions[i] < 8)
			return -1;
	if(functions[0] == functions[1] || functions[0] == functions[2] || functions[1] == functions[2])
		return -1;
	for(size_t i = 0; i < 3; i++) {
		write_opcode(image->buf, functions[i], 0xd2800000);
		write_opcode(image->buf, functions[i] + 4, 0xd65f03c0);
		LOG("Patched ARM64 NVRAM restriction at 0x%zx\n", functions[i]);
	}
	return 0;
}

/* begin functions from iBoot32Patcher by iH8sn0w*/
bool has_magic(uint8_t* buf) {
	uint32_t magic;
	memcpy(&magic, buf + 7, sizeof(magic));
	if(memcmp(&magic,IMAGE4_MAGIC,4) == 0) {
		return true;
	}
	return false;
}

bool has_kernel_load_k(struct iboot64_img* iboot_in) {
	void* debug_enabled_str = memmem(iboot_in->buf, iboot_in->len, KERNELCACHE_PREP_STRING,strlen(KERNELCACHE_PREP_STRING));
	return (bool) (debug_enabled_str != NULL);
}

bool has_recovery_console_k(struct iboot64_img* iboot_in) {
	void* entering_recovery_str = memmem(iboot_in->buf, iboot_in->len, ENTERING_RECOVERY_CONSOLE,strlen(ENTERING_RECOVERY_CONSOLE));
	return (bool) (entering_recovery_str != NULL);
}

void* iboot64_memmem(struct iboot64_img* iboot_in, void* pat) { // slightly modified from ih8sn0w's iboot_memmem()
	uint64_t new_pat = (uint64_t)GET_IBOOT64_ADDR(iboot_in, pat);
	return (void*) memmem(iboot_in->buf,iboot_in->len,&new_pat,sizeof(uint64_t));
}

bool iboot64_pac_check(struct iboot64_img* iboot_in) {
	void *pacibsp = memmem(iboot_in->buf,iboot_in->len,PACIBSP,0x4);
	if (!pacibsp) {
		return false;
	}
	WARN("PAC bootloader detected\n");
	return true;
}

uint64_t get_iboot64_base_address(struct iboot64_img* iboot_in) {  // modified from ih8sn0w's get_iboot_base_address()
	uint32_t offset = 0x318;
	get_iboot64_version(iboot_in);
	if(iboot_in->buf) {
		if(iboot_in->VERS >= 6603) // as of iOS 14, the base address appears to have been moved to 0x300
			offset = 0x300;
		iboot_in->base = *(uint64_t*)(iboot_in->buf + offset);
		return iboot_in->base;
	}
	return 0;
}
/* end functions from iBoot32Patcher */

uint32_t get_iboot64_version(struct iboot64_img* iboot_in) {
	const char* version = memmem(iboot_in->buf, iboot_in->len, "iBoot-", 6);
	iboot_in->VERS = 0;
	iboot_in->minor_vers = 0;
	if(!version)
		return 0;
	size_t offset = (const uint8_t *)version - (const uint8_t *)iboot_in->buf + 6;
	char text[64] = {0};
	size_t count = iboot_in->len - offset;
	if(count >= sizeof(text))
		count = sizeof(text) - 1;
	memcpy(text, (const uint8_t *)iboot_in->buf + offset, count);
	unsigned major = 0, minor = 0;
	if(sscanf(text, "%u.%u", &major, &minor) < 1)
		return 0;
	iboot_in->VERS = major;
	iboot_in->minor_vers = minor;
	return major;
}

uint64_t iboot64_ref(struct iboot64_img* iboot_in, void* pat) {
	uint64_t new_pat = (uintptr_t) GET_IBOOT64_ADDR(iboot_in, pat);
	if(iboot_in->VERS >= 7429)
		return a64_xref(iboot_in, new_pat - iboot_in->base);
	addr_t ref = xref64(iboot_in->buf,0,iboot_in->len,new_pat-iboot_in->base);
	if(!ref) {
		return 0;
	}
	return ref;
}

// inspiration for these functions from tihmstar/ih8sn0w
int change_bootarg_adr_xref_addr(struct iboot64_img* iboot_in, addr_t dest, addr_t address) {
	// get instruction type
	uint32_t insn = get_insn(iboot_in->buf,dest);
	insn_type_t type = get_type(insn);
	if(type == unknown) {
		return -1;
	}
	if(type == adr || type == nop) {
		uint32_t newAdr = 0;
		if ((iboot_in->VERS == 6723 && iboot_in->minor_vers >= 100) || iboot_in->VERS >= 7429) {
			int reg = 24;
            void* default_loc = NULL;
            default_loc = memmem(iboot_in->buf,iboot_in->len," -restore",strlen(" -restore"));
			if (!default_loc) {
				WARN("Failed to find restore bootarg string!\n");
				WARN("Defaulting to the x24 register!\n");
			} else {
				uint64_t restore_string_xref = iboot64_ref(iboot_in,default_loc);
				while(get_type(get_insn(iboot_in->buf,restore_string_xref)) != sub)
					restore_string_xref += -4;
				uint32_t subInsn = get_insn(iboot_in->buf,restore_string_xref);
				reg = (int)(subInsn & 0xFF) - 160;
			}
            newAdr = new_insn_adr(dest,reg,address-(addr_t)iboot_in->buf);
		}
		else
			newAdr = replace_adr_addr(dest,insn,address-(addr_t)iboot_in->buf);
		if (newAdr == -1) {
			WARN("Address too far away\n");
			return -1;
		}
		write_opcode(iboot_in->buf,dest,newAdr);
	}
	return 0;
}

int doFinalBootArgs(struct iboot64_img* iboot_in, addr_t xref, addr_t default_args_loc) {
	if ((iboot_in->VERS == 6723 && iboot_in->minor_vers >= 100) || iboot_in->VERS >= 7429) // not necessary as of iOS 14.5
		return 0;
	uint32_t adrInsn = get_insn(iboot_in->buf,xref);
	uint8_t rd = get_rd(adrInsn);
	// find next csel
	addr_t temp = xref;
	while(get_type(get_insn(iboot_in->buf,temp)) != csel)
		temp += 4;
	uint32_t cselInsn = get_insn(iboot_in->buf,temp);
	if(get_rn(cselInsn) != rd && get_rm(cselInsn) != rd) {
		WARN("CSEL instruction does not compare the same register as the previous ADR instruction\n");
		return -1;
	}
	uint32_t movInsn = new_mov_register_insn(get_rd(cselInsn),-1,rd,0); // change csel to mov, no conditions here. mov x# boot-arg-addr
	write_opcode(iboot_in->buf,temp,movInsn);
	LOG("Changed CSEL to MOV\n");
	// now we need to look for the bl instruction before this entire method
	temp -=4; // keep our distance
	while(get_supertype(get_insn(iboot_in->buf,temp)) != supertype_branch_immediate || get_type(get_insn(iboot_in->buf,temp)) == bl)
		temp -=4;
	int64_t bImmediate = 0;
	if(get_type(get_insn(iboot_in->buf,temp)) == cbz || get_type(get_insn(iboot_in->buf,temp)) == bcond )
		bImmediate = get_addr_for_cbz(temp,get_insn(iboot_in->buf,temp));
	else {
		WARN("Something went wrong when finding branch instructions\n");
		return -1;
	}
	LOG("Found branch pointing to 0x%llx at 0x%llx\n",((bImmediate-(temp/4))+temp)+iboot_in->base,temp);
	temp = ((bImmediate-(temp/4))+temp); // set temp to the addr that bl goes to
	for(int i = 0; i < 15; i++) {
		if (temp > iboot_in->len)
			break;
		if(get_type(get_insn(iboot_in->buf,temp)) != adr)
			temp += 4;
		else {
			int64_t oldAddr = get_addr_for_adr(temp,get_insn(iboot_in->buf,temp));
			uint8_t oldRD = get_rd(get_insn(iboot_in->buf,temp));
			uint32_t newAdr = replace_adr_addr(temp,get_insn(iboot_in->buf,temp),default_args_loc-(addr_t)iboot_in->buf); // replace with boot-arg location
			write_opcode(iboot_in->buf,temp,newAdr);
			LOG("Changed ADR X%d, 0x%llx to ADR X%d, 0x%llx\n",oldRD,((oldAddr-(temp/4))+temp)+iboot_in->base,get_rd(newAdr),(default_args_loc-(addr_t)iboot_in->buf)+iboot_in->base);
			break;
		}
	}
	return 0;
}

void do_kdbg_mov(struct iboot64_img* iboot_in, addr_t xref) {
	// find second bl instruction
	xref = get_next_nth_insn(iboot_in->buf,xref,2,bl);
	LOG("Found second bl after debug-enabled xref at 0x%llx\n",xref);
	// now we need to change this bl to movz x0, #1
	uint32_t movOp = new_mov_immediate_insn(0,1,1);
	write_opcode(iboot_in->buf,xref,movOp);
	LOG("Wrote MOVZ X0, #1 to 0x%llx\n",xref+iboot_in->base);
}

static bool checkIMG4Ref(uint8_t* buf, addr_t xref) {
	// Find ADD X3,SP,#imm before the IMG4 call.
	for(int i = 0; i < 10 && xref >= 4; i++) {
		xref -= 4;
		if((get_type(get_insn(buf,xref)) == add) && (get_rd(get_insn(buf,xref)) == 3) && (get_rn(get_insn(buf,xref)) == 0x1f)) {
			return true;
		}
	}
	return false;
}

static int do_rsa_sigcheck_patch(struct iboot64_img* iboot_in, addr_t img4Xref, bool pac) {
	if(iboot_in->len < 8 || img4Xref > iboot_in->len - 4 || (img4Xref & 3))
		return -1;
	addr_t img4refFtop = bof64(iboot_in->buf, 0, img4Xref);
	if (pac == true) {
		if(img4refFtop < 4)
			return -1;
		img4refFtop = img4refFtop - 0x4;
	}
	if(!img4refFtop || img4refFtop >= iboot_in->len)
		return -1;
	LOG("Found beginning of _image4_get_partial at 0x%llx\n",img4refFtop);
	// Use iPatcher's IMG4 check patch for older iBoots.
	if (iboot_in->VERS < 3406) { // iOS 7-9
		void* movkLoc = NULL;
		uint32_t movkInsn = 0;
		if (iboot_in->VERS < 2261) // iOS 7
			movkInsn = new_movk_insn(11,0x4348,0,0); // MOVK W11, #0x4348
		else if (iboot_in->VERS < 2817) // iOS 8
			movkInsn = new_movk_insn(10,0x4348,0,0); // MOVK W10, #0x4348
		else // otherwise, it is iOS 9
			movkInsn = new_movk_insn(8,0x4348,0,0); // MOVK W8, #0x4348
		movkLoc = memmem(iboot_in->buf,iboot_in->len,&movkInsn,sizeof(movkInsn));
		if (!movkLoc) {
			WARN("Could not find MOVK W%llu, #0x4348 instruction for old iBoot\n", BIT_RANGE(movkInsn,0,4));
			WARN("RSA PATCH FAILED\n");
			return -1;
		}
		addr_t movkOffset = (addr_t)GET_IBOOT_FILE_OFFSET(iboot_in,movkLoc);
		LOG("Found MOVK W%llu, #0x4348 at 0x%llx\n",BIT_RANGE(movkInsn,0,4), movkOffset);
		addr_t funcStart = bof64(iboot_in->buf,0,movkOffset); // find beginning of img4 check function
		if(!funcStart || funcStart > iboot_in->len - 8)
			return -1;
		LOG("Patching RSA check at 0x%llx\n",funcStart + iboot_in->base);
		uint32_t finalMovInsn = new_mov_immediate_insn(0,0,1);
		uint32_t retInsn = new_ret_insn(-1);
		write_opcode(iboot_in->buf,funcStart,finalMovInsn); // mov x0, #0
		write_opcode(iboot_in->buf,funcStart+4,retInsn);    // ret
		LOG("Did MOV r0, #0 and RET\n");
		return 0;
	}
	addr_t img4GetPartialRef = xref64code(iboot_in->buf, 0, iboot_in->len, img4refFtop);
	if(!img4GetPartialRef || img4GetPartialRef >= iboot_in->len)
		return -1;
	for(int i = 0; i < 20; i++) {
		if(checkIMG4Ref(iboot_in->buf,img4GetPartialRef))
			break;
		if(img4GetPartialRef > iboot_in->len - 4)
			return -1;
		img4GetPartialRef = xref64code(iboot_in->buf,img4GetPartialRef+4,
			iboot_in->len,img4refFtop);

		if(!img4GetPartialRef || i == 19) {
			WARN("Could not find correct xref for _image4_get_partial.\n");
			WARN("RSA PATCH FAILED\n");
			return -1;
		}
	}
	LOG("Found xref to _image4_get_partial at 0x%llx\n",img4GetPartialRef);
	addr_t getPartialRefFtop = bof64(iboot_in->buf,0,img4GetPartialRef);
	if(!getPartialRefFtop)
		return -1;
	LOG("Found start of sub_%llx\n",iboot_in->base+getPartialRefFtop);
	addr_t x2_adr = 0;
	addr_t x3_adr = 0;

	while(getPartialRefFtop <= iboot_in->len - 8) {
		getPartialRefFtop += 4;
		if(get_type(get_insn(iboot_in->buf,getPartialRefFtop)) == adr && get_rd(get_insn(iboot_in->buf,getPartialRefFtop)) == 2)
			x2_adr = getPartialRefFtop;
		else if(get_type(get_insn(iboot_in->buf,getPartialRefFtop)) == adr && get_rd(get_insn(iboot_in->buf,getPartialRefFtop)) == 3)
			x3_adr = getPartialRefFtop;
		else if(get_type(get_insn(iboot_in->buf,getPartialRefFtop)) == bl) {
			if(x2_adr && x3_adr)
				break;
			else {
				x2_adr = 0;
				x3_adr = 0;
			}
		}
	}
	if(!x2_adr || !x3_adr || getPartialRefFtop > iboot_in->len - 8) {
		WARN("Could not find the IMG4 verification arguments\n");
		return -1;
	}
	int64_t verifyRef = get_addr_for_adr(x2_adr,get_insn(iboot_in->buf,x2_adr));
	int64_t verifyTarget = verifyRef - (int64_t)(x2_adr / 4) + (int64_t)x2_adr;
	if(verifyTarget < 0 || (uint64_t)verifyTarget >= iboot_in->len) {
		WARN("IMG4 verification target is outside the bootloader\n");
		return -1;
	}
	LOG("Found ADR X2, 0x%llx at 0x%llx\n",verifyTarget+iboot_in->base,x2_adr);
	addr_t verifyFunc = (addr_t)verifyTarget;
	if(iboot_in->len - (size_t)verifyTarget >= sizeof(uint64_t)) {
		uint64_t pointer;
		memcpy(&pointer, (uint8_t *)iboot_in->buf + verifyTarget, sizeof(pointer));
		if(pointer >= iboot_in->base && pointer - iboot_in->base < iboot_in->len)
			verifyFunc = (addr_t)(pointer - iboot_in->base);
	}
	if((verifyFunc & 3) || verifyFunc > iboot_in->len - 4)
		return -1;
	LOG("Call to sub_%llx\n",verifyFunc+iboot_in->base);
	addr_t crawl = verifyFunc;
	if (iboot_in->VERS < 5540) { // iOS 10-12
		crawl += 4;
		while(crawl <= iboot_in->len - 4 && get_type(get_insn(iboot_in->buf,crawl)) != ret)
			crawl += 4;
		if(crawl > iboot_in->len - 4) {
			WARN("Could not find the end of the IMG4 verification function\n");
			return -1;
		}
		LOG("RET found for sub_%llx at 0x%llx\n",verifyFunc+iboot_in->base,crawl);
	}
	uint32_t movInsn = new_mov_immediate_insn(0,0,1);
	uint32_t retInsn = new_ret_insn(-1);
	
	void* mov_x0_0__ret = NULL;
	uint32_t search[2];
	search[0] = movInsn;
	search[1] = retInsn;
	mov_x0_0__ret = memmem(iboot_in->buf, iboot_in->len, &search, sizeof(search));
	if(mov_x0_0__ret) {
		addr_t ret0_gadget = (addr_t)(mov_x0_0__ret - iboot_in->buf);
		LOG("ret0 gadget at 0x%llx\n", ret0_gadget);
		write_opcode(iboot_in->buf, crawl, new_branch(crawl, ret0_gadget));
		LOG("Did MOV r0, #0 and RET\n");
	} else {
		void* nop_region = NULL;
		uint32_t search_nop_region[16];
		for(int i=0; i<16;i++) {
			search_nop_region[i] = new_nop();
		}
		nop_region = memmem(iboot_in->buf, iboot_in->len, &search_nop_region, sizeof(search_nop_region));
		if(nop_region) {
			LOG("NOP region at 0x%llx\n", (addr_t)(nop_region - iboot_in->buf));
			addr_t new_ret0 = (addr_t)(nop_region - iboot_in->buf + (4*8));
			write_opcode(iboot_in->buf, new_ret0, movInsn);
			write_opcode(iboot_in->buf, new_ret0+4, retInsn);
			LOG("new ret0 gadget at 0x%llx\n", new_ret0);
			write_opcode(iboot_in->buf, crawl, new_branch(crawl, new_ret0));
			LOG("Did MOV r0, #0 and RET\n");
		} else {
			if(crawl > iboot_in->len - 8)
				return -1;
			write_opcode(iboot_in->buf,crawl,movInsn);
			write_opcode(iboot_in->buf,crawl+4,retInsn);
			LOG("Did MOV r0, #0 and RET\n");
		}
	}
	return 0;
}

int patch_boot_args64(struct iboot64_img* iboot_in, char* bootargs) {
	if(iboot_in->VERS >= 7429)
		return a64_bootargs(iboot_in, bootargs);
	// find current boot-args
	void* default_loc = NULL;
	int num = 1;
	LOG("Image base address at 0x%llx\n",iboot_in->base);
	if ((iboot_in->VERS == 6723 && iboot_in->minor_vers >= 100) || iboot_in->VERS >= 7429) // 14.5 and up
		default_loc = memmem(iboot_in->buf,iboot_in->len,"rd=md0",strlen("rd=md0"));
	else
		default_loc = memmem(iboot_in->buf,iboot_in->len,DEFAULT_BOOTARGS_STRING,strlen(DEFAULT_BOOTARGS_STRING));
	if(!default_loc) { // if those are not found, try for the other possible string
		LOG("Searching for alternate boot-args\n");
		if ((iboot_in->VERS == 6723 && iboot_in->minor_vers >= 100) || iboot_in->VERS >= 7429)
			default_loc = memmem(iboot_in->buf,iboot_in->len," -progress",strlen(" -progress"));
		else
			default_loc = memmem(iboot_in->buf,iboot_in->len,OTHER_DEFAULT_BOOTARGS_STRING,strlen(OTHER_DEFAULT_BOOTARGS_STRING));
		if(!default_loc) { // failed, uh oh
			WARN("Could not find boot-arg string\n");
			return -1;
		}
	}
	LOG("Found boot-arg string at %p\n",GET_IBOOT_FILE_OFFSET(iboot_in,default_loc));
	uint64_t default_args_xref = iboot64_ref(iboot_in,default_loc);
	if ((iboot_in->VERS == 6723 && iboot_in->minor_vers >= 100) || iboot_in->VERS >= 7429) {
		LOG("Relocating from 0x%llx...\n",iboot_in->base+default_args_xref);
		default_args_xref = get_next_nth_insn(iboot_in->buf,default_args_xref,5,nop);
	}
	if(!default_args_xref) {
		WARN("Could not find boot-arg xref\n");
		return -1;
	}
	LOG("Found boot-arg xref at 0x%llx\n",iboot_in->base+default_args_xref);
	if(strlen(bootargs) > 270) {
		char bootargCpy[271] = { '\0' }; // sorry, gotta shorten it
		strncpy(bootargCpy,bootargs,270);
		bootargs = bootargCpy;
		num = 0;
		WARN("Truncated boot-args: %s\n",bootargs);
	}
	void* new_loc = NULL;
	char zeros[270] = {0};
	// cryptiiiic boot arg location
	// https://github.com/Cryptiiiic/liboffsetfinder64/blob/4d034e5102178177e1bf9f5cc024a95651bed22b/liboffsetfinder64/ibootpatchfinder64_base.cpp#L225
	new_loc = memmem(iboot_in->buf,iboot_in->len,zeros,270);
	if(!new_loc) {
		if (strlen(bootargs) >= 180) {
			WARN("Boot arg string too long, truncating...\n");
			char largerBootargCpy[180] = { '\0' };
			strncpy(largerBootargCpy,bootargs,179);
			bootargs = largerBootargCpy;
			num = 0;
			WARN("Truncated boot-args again: %s\n",bootargs);
		}
		new_loc = memmem(iboot_in->buf,iboot_in->len,CERT_STRING,strlen(CERT_STRING));
		if(!new_loc) {
			WARN("Could not find long string to override\n");
			return -1; // no Reliance string or dart_ctrr. update code
		}
		memset(new_loc,'\0',179);
	} else {
		new_loc += 0x10;
		memset(new_loc,'\0',270); // zero out new_loc
	}
	LOG("Pointing boot-arg xref to large string at: %p\n",GET_IBOOT64_ADDR(iboot_in,new_loc));
	int ret = change_bootarg_adr_xref_addr(iboot_in,default_args_xref,(unsigned long long)new_loc);
	if (ret < 0)
		return -1;
	strncpy(new_loc,bootargs,strlen(bootargs)+num); // main part done. also no null terminator. don't like those
	// now to patch up
	return doFinalBootArgs(iboot_in,default_args_xref,(unsigned long long)new_loc);
}

int enable_kernel_debug(struct iboot64_img* iboot_in) {
	if(iboot_in->VERS >= 7429)
		return a64_debug(iboot_in);
	void* debugLoc = NULL;
	debugLoc = memmem(iboot_in->buf,iboot_in->len,"debug-enabled",strlen("debug-enabled"));
	if(!debugLoc) {
		WARN("Could not find debug-enabled string\n");
		return -1;
	}
	LOG("Found debug-enabled string at %p\n",GET_IBOOT_FILE_OFFSET(iboot_in,debugLoc));
	uint64_t debugEnabledXref = iboot64_ref(iboot_in,debugLoc);
	if(!debugEnabledXref) {
		WARN("Could not find debug-enabled xref\n");
		return -1;
	}
	LOG("Found debug-enabled xref at 0x%llx\n",debugEnabledXref);
	// now hand off ctrl to patchfinder to get rid of bl and replace with an unconditional mov
	do_kdbg_mov(iboot_in,debugEnabledXref);
	LOG("Enabled kernel debug\n");
	return 0;
}

int rsa_sigcheck_patch(struct iboot64_img* iboot_in, bool pac) {
	if(iboot_in->VERS >= 7429)
		return a64_sigcheck(iboot_in);
	void* img4Loc = NULL;
	img4Loc = memmem(iboot_in->buf,iboot_in->len,"IMG4\0",5);
	if(!img4Loc) {
		WARN("Could not find IMG4 string\n");
		return -1;
	}
	LOG("Found IMG4 string at %p\n",GET_IBOOT_FILE_OFFSET(iboot_in,img4Loc));
	uint64_t img4Ref = iboot64_ref(iboot_in,img4Loc);
	if(!img4Ref) {
		WARN("Could not find IMG4 xref\n");
		return -1;
	}
	LOG("Found IMG4 xref at 0x%llx\n",img4Ref);
	return do_rsa_sigcheck_patch(iboot_in, img4Ref, pac);
}

int do_command_handler_patch(struct iboot64_img* iboot_in, char* command, uintptr_t ptr) { // useful for kicking off iBoot payloads
	char* realCmd = (char*)malloc(strlen(command)+2); // nulls all around
	memset(realCmd,0,strlen(command)+2); 
	// need to search for null-surrounded \0__cmd__\0
	for(int i = 0; i < (strlen(command)); i++)
		realCmd[i+1] = command[i];
	void* cmdLoc = memmem(iboot_in->buf,iboot_in->len,realCmd,strlen(command)+2);
	if(!cmdLoc) {
		WARN("Unable to find \"%s\" in image\n",command);
		free(realCmd);
		return -1;
	}
	free(realCmd); // into the garbage
	cmdLoc++; // because we had a null char at the beginning, advance one to get real location
	LOG("Found command \"%s\" at %p looking for 0x%llx\n",command,GET_IBOOT_FILE_OFFSET(iboot_in,cmdLoc),(uint64_t)GET_IBOOT64_ADDR(iboot_in,cmdLoc));
	void* cmdRef = iboot64_memmem(iboot_in,cmdLoc);
	if(!cmdRef) {
		WARN("Unable to find reference to command \"%s\"\n",command);
		return -1;
	}
	addr_t ref = (addr_t)GET_IBOOT_FILE_OFFSET(iboot_in,cmdRef);
	if((ref & 7) || ref > iboot_in->len || iboot_in->len - ref < 16) {
		WARN("Invalid command table entry\n");
		return -1;
	}
	uint64_t handler = a64_pointer(iboot_in, ref + 8);
	if((handler & 3) || handler < iboot_in->base ||
		handler - iboot_in->base >= iboot_in->len || (ptr & 3)) {
		WARN("Invalid ARM64 command handler\n");
		return -1;
	}
	LOG("Found reference to %s command at 0x%llx\n",command,ref);
	// now do patch
	LOG("Pointing %s to 0x%lx\n",command,ptr);
	*(uint64_t*)(iboot_in->buf+ref+8) = ptr; // plus 8 because we don't want to overwrite the ref itself, but what it executes
	return 0;
}

int unlock_nvram(struct iboot64_img* iboot_in) {
	if(iboot_in->VERS >= 7429)
		return a64_nvram(iboot_in);
	void* debuguartLoc = memmem(iboot_in->buf,iboot_in->len,"debug-uarts",strlen("debug-uarts"));
	if(!debuguartLoc) {
		WARN("Unable to find debug-uarts string\n");
		return -1;
	}
	LOG("Found debug-uarts string at %p\n",GET_IBOOT64_ADDR(iboot_in,debuguartLoc));
	void* debuguartRef = iboot64_memmem(iboot_in,debuguartLoc);
	if(!debuguartRef) {
		WARN("Unable to find debug-uarts reference\n");
		return -1;
	}
	addr_t debugRef = (addr_t)GET_IBOOT_FILE_OFFSET(iboot_in,debuguartRef);
	LOG("Found debug-uarts reference at 0x%llx\n",debugRef);
	addr_t setenvWhitelist = debugRef;
	while(setenvWhitelist >= 8 && a64_pointer(iboot_in, setenvWhitelist - 8))
		setenvWhitelist -= 8;
	if(setenvWhitelist < 8 || a64_pointer(iboot_in, setenvWhitelist - 8)) {
		WARN("Invalid setenv whitelist\n");
		return -1;
	}
	LOG("setenv whitelist begins at 0x%llx\n",setenvWhitelist);
	addr_t blacklistFunc = xref64(iboot_in->buf,0,iboot_in->len,setenvWhitelist);
	if(!blacklistFunc) {
		WARN("Could not find reference to setenv whitelist\n");
		return -1;
	}
	LOG("Found ref to setenv whitelist at 0x%llx\n",blacklistFunc);
	addr_t blacklistFuncBegin = bof64(iboot_in->buf,0,blacklistFunc);
	if(!blacklistFuncBegin) {
		WARN("Could not find beginning of blacklist function\n");
		return -1;
	}
	addr_t envWhitelist = setenvWhitelist;
	while(envWhitelist <= iboot_in->len - 8 && a64_pointer(iboot_in, envWhitelist))
		envWhitelist += 8;
	if(envWhitelist > iboot_in->len - 16) {
		WARN("Invalid end of setenv whitelist\n");
		return -1;
	}
	envWhitelist += 8;
	LOG("Found env whitelist at 0x%llx\n",envWhitelist);
	addr_t blacklistFunc2 = xref64(iboot_in->buf,0,iboot_in->len,envWhitelist);
	int legacy_shared_list = 0;
	if(!blacklistFunc2 && iboot_in->VERS < 2261) {
		static const char* const legacy[] = {"auto-boot", "boot-args", "debug-uarts", "filesize"};
		size_t count = sizeof(legacy) / sizeof(legacy[0]);
		legacy_shared_list = envWhitelist - setenvWhitelist == (count + 1) * 8;
		for(size_t i = 0; legacy_shared_list && i < count; i++) {
			uint64_t pointer = a64_pointer(iboot_in, setenvWhitelist + i * 8);
			size_t length = strlen(legacy[i]) + 1;
			if(pointer < iboot_in->base || pointer - iboot_in->base >= iboot_in->len ||
				iboot_in->len - (pointer - iboot_in->base) < length ||
				memcmp((const char *)iboot_in->buf + pointer - iboot_in->base, legacy[i], length)) {
				legacy_shared_list = 0;
				break;
			}
		}
	}
	if(!blacklistFunc2 && !legacy_shared_list) {
		WARN("Could not find reference to env whitelist\n");
		return -1;
	}
	addr_t blacklistFunc2Begin = 0;
	if(blacklistFunc2) {
		LOG("Found ref to env whitelist at 0x%llx\n",blacklistFunc2);
		blacklistFunc2Begin = bof64(iboot_in->buf,0,blacklistFunc2);
		if(!blacklistFunc2Begin) {
			WARN("Could not find beginning of second blacklist function\n");
			return -1;
		}
	}
	void* comAppleSystemLoc = memmem(iboot_in->buf,iboot_in->len,"com.apple.System.",strlen("com.apple.System.")+1);
	if(!comAppleSystemLoc) {
		WARN("Could not find string \"com.apple.System.\"\n");
		return -1;
	}
	LOG("Found \"com.apple.System.\" string at %p\n",GET_IBOOT64_ADDR(iboot_in,comAppleSystemLoc));
	addr_t comAppleSystemRef = iboot64_ref(iboot_in,comAppleSystemLoc);
	if(!comAppleSystemRef) {
		WARN("Could not find reference to \"com.apple.System.\"\n");
		return -1;
	}
	LOG("Found reference to \"com.apple.System.\" at 0x%llx\n",comAppleSystemRef);
	addr_t appleSystemFuncBegin = bof64(iboot_in->buf,0,comAppleSystemRef);
	if(!appleSystemFuncBegin) {
		WARN("Unable to find beginning of function where \"com.apple.System.\" is referenced\n");
		return -1;
	}
	uint32_t movZeroZero = new_mov_immediate_insn(0,0,1);
	uint32_t retInsn = new_ret_insn(-1);
	LOG("Forcing sub_%llx to return immediately\n",blacklistFuncBegin+iboot_in->base);
	write_opcode(iboot_in->buf,blacklistFuncBegin,movZeroZero);
	write_opcode(iboot_in->buf,blacklistFuncBegin+4,retInsn);
	if(blacklistFunc2Begin) {
		LOG("Forcing sub_%llx to return immediately\n",blacklistFunc2Begin+iboot_in->base);
		write_opcode(iboot_in->buf,blacklistFunc2Begin,movZeroZero);
		write_opcode(iboot_in->buf,blacklistFunc2Begin+4,retInsn);
	} else {
		LOG("Using the shared legacy ARM64 NVRAM whitelist\n");
	}
	LOG("Forcing sub_%llx to return immediately\n",appleSystemFuncBegin+iboot_in->base);
	write_opcode(iboot_in->buf,appleSystemFuncBegin,movZeroZero);
	write_opcode(iboot_in->buf,appleSystemFuncBegin+4,retInsn);
	return 0;
}
