#include "watchoptions.h"

static uint16_t rd16(const struct iboot64_img* img, size_t off) {
	const uint8_t* b = img->buf;
	return b[off] | (uint16_t)b[off + 1] << 8;
}

static uint32_t rd32(const struct iboot64_img* img, size_t off) {
	return rd16(img, off) | (uint32_t)rd16(img, off + 2) << 16;
}

static void wr16(struct iboot64_img* img, size_t off, uint16_t value) {
	uint8_t* b = img->buf;
	b[off] = value;
	b[off + 1] = value >> 8;
}

static void wr32(struct iboot64_img* img, size_t off, uint32_t value) {
	wr16(img, off, value);
	wr16(img, off + 2, value >> 16);
}

static size_t find_string(const struct iboot64_img* img, const char* s) {
	size_t n = strlen(s) + 1;
	const uint8_t* b = img->buf;
	for(size_t p = 0; n <= img->len && p <= img->len - n; p++)
		if(!memcmp(b + p, s, n))
			return p;
	return SIZE_MAX;
}

static size_t width(uint16_t h) {
	return (h & 0xf800) >= 0xe800 ? 4 : 2;
}

static int is_bl(const struct iboot64_img* img, size_t p) {
	return p + 4 <= img->len && (rd16(img, p) & 0xf800) == 0xf000 &&
		(rd16(img, p + 2) & 0xd000) == 0xd000;
}

static size_t literal(const struct iboot64_img* img, size_t p, unsigned* reg) {
	if(p + 2 > img->len)
		return SIZE_MAX;
	uint16_t h = rd16(img, p);
	size_t pc = (p + 4) & ~(size_t)3, loc;
	if((h & 0xf800) == 0x4800) {
		loc = pc + (h & 0xff) * 4;
		*reg = (h >> 8) & 7;
	} else if((h == 0xf8df || h == 0xf85f) && p + 4 <= img->len) {
		uint16_t l = rd16(img, p + 2);
		if(h == 0xf85f && (l & 0xfff) > pc)
			return SIZE_MAX;
		loc = h == 0xf8df ? pc + (l & 0xfff) : pc - (l & 0xfff);
		*reg = l >> 12;
	} else
		return SIZE_MAX;
	return loc <= img->len - 4 ? loc : SIZE_MAX;
}

static size_t ref(const struct iboot64_img* img, size_t target, size_t start, unsigned* reg,
	size_t* lit) {
	if(target >= img->len)
		return SIZE_MAX;
	for(size_t p = start; p + 4 <= img->len; p += 2) {
		size_t l = literal(img, p, reg);
		if(l != SIZE_MAX && rd32(img, l) == img->base + target) {
			*lit = l;
			return p;
		}
	}
	return SIZE_MAX;
}

static size_t function_start(const struct iboot64_img* img, size_t at) {
	size_t lower = at > 128 ? at - 128 : 0;
	for(size_t p = at & ~(size_t)1; p >= lower + 2;) {
		p -= 2;
		// PUSH {...,lr}; ADD r7,sp,#frame.
		if((rd16(img, p) & 0xff00) == 0xb500 && (rd16(img, p + 2) & 0xff00) == 0xaf00)
			return p;
		// Early S0 wrappers set arguments before the frame pointer.
		if((rd16(img, p) & 0xff00) == 0xb500) {
			for(size_t q = p + 2; q + 2 <= img->len && q <= p + 8;
				q += width(rd16(img, q))) {
				uint16_t h = rd16(img, q);
				if((h & 0xff00) == 0xaf00 || (rd16(img, p) == 0xb580 && h == 0x466f))
					return p;
				if((h & 0xf800) != 0x4800 && (h & 0xf800) != 0x2000 &&
					(h & 0xff00) != 0x4600)
					break;
			}
		}
	}
	return SIZE_MAX;
}

int watch_debug_patch(struct iboot64_img* img) {
	size_t str = find_string(img, "debug-enabled"), l;
	unsigned reg;
	size_t x = ref(img, str, 0, &reg, &l);
	if(x == SIZE_MAX)
		return -1;
	size_t limit = x + 64 < img->len ? x + 64 : img->len;
	unsigned calls = 0;
	for(size_t p = x; p + 6 <= limit; p += width(rd16(img, p))) {
		if(!is_bl(img, p))
			continue;
		if(++calls != 2)
			continue;
		// The second call checks the 0x20 debug permission.
		int permission_arg = p >= 2 && rd16(img, p - 2) == 0x2020;
		if(!permission_arg && p >= 4 && rd16(img, p - 4) == 0x2020 &&
			rd16(img, p - 2) == 0x2100)
			permission_arg = 1;
		uint16_t after = rd16(img, p + 4);

		int cbz_update = p + 12 <= img->len && (after & 0xfd07) == 0xb100 &&
			(rd16(img, p + 6) & 0xff00) == 0x9800 &&
			rd16(img, p + 8) == 0x2101 &&
			rd16(img, p + 10) == 0x6001 &&
			p + 8 + ((after >> 3) & 31) * 2 +
				((after >> 9) & 1) * 64 == p + 12;
		if(!permission_arg || (after != 0x2801 && !cbz_update))
			return -1;
		wr16(img, p, 0x2001); // movs r0, #1
		wr16(img, p + 2, 0xbf00);
		LOG("Enabled Thumb kernel debug at 0x%zx\n", p);
		return 0;
	}
	return -1;
}

static size_t bl_target(const struct iboot64_img* img, size_t p) {
	if(!is_bl(img, p))
		return SIZE_MAX;
	uint16_t h = rd16(img, p), l = rd16(img, p + 2);
	unsigned sign = (h >> 10) & 1;
	uint32_t bits = sign << 24 | (((l >> 13) & 1) ^ sign ^ 1) << 23 |
		(((l >> 11) & 1) ^ sign ^ 1) << 22 |
		(h & 0x3ff) << 12 | (l & 0x7ff) << 1;
	int32_t displacement = (int32_t)(bits << 7) >> 7;
	int64_t target = (int64_t)p + 4 + displacement;
	return target >= 0 && target < (int64_t)img->len ? (size_t)target : SIZE_MAX;
}

// Reuse the watchOS 7.4+ boot-args builder for the custom string.
static int split_bootargs_patch(struct iboot64_img* img, const char* args) {
	size_t rd = find_string(img, "rd=md0"), progress = find_string(img, " -progress"),
		restore = find_string(img, " -restore"), lit, unused;
	unsigned reg;
	size_t x = ref(img, rd, 0, &reg, &lit);
	if(x == SIZE_MAX || x < 4 || x + 58 > img->len || reg != 0 ||
		(rd16(img, x) & 0xff00) != 0x4800 ||
		ref(img, rd, x + 2, &reg, &unused) != SIZE_MAX)
		return -1;
	unsigned dst = (rd16(img, x + 38) >> 8) & 7;
	if(rd16(img, x - 4) != 0x2800 || (rd16(img, x - 2) & 0xff00) != 0xd000 ||
		rd16(img, x + 2) != 0x2120 || rd16(img, x + 4) != 0x9000 ||
		(rd16(img, x + 6) & 0xff00) != 0xa800 || rd16(img, x + 8) != 0x2200 ||
		rd16(img, x + 10) != 0x2320 || !is_bl(img, x + 12) ||
		!is_bl(img, x + 16) || rd16(img, x + 20) != 0xb128 ||
		rd16(img, x + 22) != rd16(img, x + 6) ||
		rd16(img, x + 26) != 0x2220 || rd16(img, x + 28) != 0x2320 ||
		!is_bl(img, x + 30) || !is_bl(img, x + 34) ||
		(rd16(img, x + 38) & 0xf8ff) != (0xa800 | (rd16(img, x + 6) & 0xff)) ||
		rd16(img, x + 40) != 0x07c0 || (rd16(img, x + 42) & 0xff00) != 0xd100 ||
		rd16(img, x + 46) != (0x4600 | dst << 3) ||
		rd16(img, x + 48) != 0x2220 || rd16(img, x + 50) != 0x2320 ||
		!is_bl(img, x + 52) || (rd16(img, x + 56) & 0xf800) != 0xe000)
		return -1;
	size_t append = bl_target(img, x + 30);
	if(append == SIZE_MAX || append != bl_target(img, x + 52) ||
		bl_target(img, x + 12) == SIZE_MAX || append == bl_target(img, x + 12) ||
		bl_target(img, x + 16) == SIZE_MAX || bl_target(img, x + 34) == SIZE_MAX)
		return -1;

	int32_t disp = rd16(img, x + 56) & 0x7ff;
	if(disp & 0x400)
		disp -= 0x800;
	int64_t join_signed = (int64_t)x + 60 + disp * 2;
	if(join_signed < (int64_t)x + 60 || join_signed + 4 > (int64_t)img->len ||
		join_signed > (int64_t)x + 512)
		return -1;
	size_t join = (size_t)join_signed;
	if((int64_t)x + 2 + (int8_t)(rd16(img, x - 2) & 0xff) * 2 != (int64_t)join - 2 ||
		(int64_t)x + 46 + (int8_t)(rd16(img, x + 42) & 0xff) * 2 != (int64_t)join)
		return -1;
	size_t suffix = literal(img, x + 24, &reg);
	if(suffix == SIZE_MAX || reg != 1 || progress == SIZE_MAX ||
		rd32(img, suffix) != img->base + progress)
		return -1;
	suffix = literal(img, x + 44, &reg);
	if(suffix == SIZE_MAX || reg != 1 || restore == SIZE_MAX ||
		rd32(img, suffix) != img->base + restore)
		return -1;
	size_t fallback = literal(img, join - 2, &reg);
	if(fallback == SIZE_MAX || reg != dst ||
		(rd16(img, join - 2) & 0xf800) != 0x4800)
		return -1;
	uint32_t empty = rd32(img, fallback);
	if(empty < img->base || empty - img->base >= img->len ||
		((const uint8_t *)img->buf)[empty - img->base] || fallback == lit ||
		(lit >= x && lit < x + 58) || (fallback >= x && fallback < x + 58))
		return -1;
	size_t entry = x, dest = x + 4, capacity = 53, n = strlen(args);
	uint16_t global_load = 0, global_store = 0;
	uint16_t args_load = (rd16(img, x) & 0xf8ff) | dst << 8;
	if(n > capacity && x >= 26) {
		// Reuse the stack-string setup too, leaving 75 bytes plus NUL.
		size_t start = x - 26;
		unsigned stack_string = (rd16(img, x + 6) & 255);
		int valid = stack_string <= 248 && rd16(img, x - 6) == 0x6800;
		for(unsigned i = 0; valid && i < 8; i++)
			valid = rd16(img, start + i * 2) ==
				(0x9000 | dst << 8 | (stack_string + 7 - i));
		unsigned global_reg;
		size_t global = literal(img, x - 10, &global_reg);
		size_t global_pc = (start + 4) & ~(size_t)3;
		size_t args_pc = (start + 8) & ~(size_t)3;
		uint32_t global_address = global == SIZE_MAX ? 0 : rd32(img, global);
		if(valid && global != SIZE_MAX && global_reg == 0 &&
			(rd16(img, x - 10) & 0xff00) == 0x4800 &&
			rd16(img, x - 8) == 0x900e && img->len >= 0x340 &&
			!(global_address & 3) && global_address >= img->base + img->len &&
			(uint64_t)global_address + 4 <= rd32(img, 0x33c) &&
			global >= global_pc && global - global_pc <= 1020 &&
			lit >= args_pc && lit - args_pc <= 1020 &&
			!(global >= start && global < x + 58) &&
			!(lit >= start && lit < x + 58) &&
			!(fallback >= start && fallback < x + 58)) {
			global_load = 0x4800 | ((global - global_pc) / 4);
			global_store = rd16(img, x - 8);
			args_load = 0x4800 | dst << 8 | ((lit - args_pc) / 4);
			entry = start;
			dest = start + 8;
			capacity = 75;
		}
	}
	if(n > capacity) {
		WARN("This Thumb image has room for at most %zu boot-argument bytes\n", capacity);
		return -1;
	}
	if(entry != x) {
		wr16(img, entry, global_load);
		wr16(img, entry + 2, global_store);
		wr16(img, entry + 4, args_load);
		wr16(img, entry + 6, 0xe000 | ((join - entry - 10) / 2));
	} else {
		// LDR selected, [original literal]; B join.
		wr16(img, entry, args_load);
		wr16(img, entry + 2, 0xe000 | ((join - entry - 6) / 2));
	}
	memset((uint8_t *)img->buf + dest, 0, capacity + 1);
	memcpy((uint8_t *)img->buf + dest, args, n);
	wr32(img, lit, (uint32_t)(img->base + dest));
	wr32(img, fallback, (uint32_t)(img->base + dest));
	LOG("Set split Thumb boot arguments at 0x%zx (join 0x%zx, literals 0x%zx/0x%zx)\n",
		dest, join, lit, fallback);
	return 0;
}

// Patch kernel handoff arguments because bootx skips the upgrade command's builder.
static int kernel_bootargs_patch(struct iboot64_img* img, const char* args,
	size_t dest, size_t capacity) {
	size_t format = find_string(img, "%s force-usb-power=1 ");
	size_t plain = find_string(img, "%s "), bootargs = find_string(img, "boot-args");
	if(format == SIZE_MAX || plain == SIZE_MAX || bootargs == SIZE_MAX || dest == SIZE_MAX)
		return -1;
	size_t selected = SIZE_MAX, selected_pool = SIZE_MAX, selected_format = SIZE_MAX;
	for(size_t q = 0x344; q + 28 <= img->len; q += 2) {
		unsigned reg, first_reg;
		size_t pool = literal(img, q, &reg), first = literal(img, q - 2, &first_reg);
		if(pool == SIZE_MAX || first == SIZE_MAX || reg != first_reg ||
			rd32(img, pool) != img->base + format || rd32(img, first) != img->base + plain ||
			(rd16(img, q - 4) != 0xbf0c && rd16(img, q - 4) != 0xbf14))
			continue;
		for(size_t x = q > 0x3a0 ? q - 96 : 0x340; x + 8 <= q; x += 2) {
			uint16_t load = rd16(img, x), cmp = rd16(img, x + 2), mov = rd16(img, x + 6);
			unsigned dst = (load >> 8) & 7, src = (cmp >> 8) & 7, unused;
			size_t empty = literal(img, x, &unused);
			if((load & 0xf800) != 0x4800 || (cmp & 0xf8ff) != 0x2800 ||
				rd16(img, x + 4) != 0xbf18 || mov != (0x4600 | src << 3 | dst) ||
				empty == SIZE_MAX || rd32(img, empty) < img->base ||
				rd32(img, empty) - img->base >= img->len ||
				((const uint8_t *)img->buf)[rd32(img, empty) - img->base])
				continue;
			int compact = reg == 2 && rd32(img, q + 2) == 0x0048f106 &&
				rd32(img, q + 6) == 0x7180f44f && rd16(img, q + 10) == (0x4603 | dst << 3) &&
				(is_bl(img, q + 12) || (rd16(img, q + 12) == 0x4635 && is_bl(img, q + 14)));
			int stacked = reg == 0 && rd32(img, q + 2) == 0x7180f44f &&
				rd16(img, q + 6) == 0x2200 && rd16(img, q + 8) == 0xe88d &&
				rd16(img, q + 10) == (1u | 1u << dst) && rd32(img, q + 12) == 0x0038f106 &&
				rd32(img, q + 16) == 0x7382f44f && is_bl(img, q + 20);
			int paired = reg == 0 && rd16(img, q + 2) == 0x2200 &&
				rd32(img, q + 4) == 0x7380f44f && rd16(img, q + 8) == 0xe9cd &&
				rd16(img, q + 10) == dst << 8 && (rd16(img, q + 12) & 0xff00) == 0x9900 &&
				rd32(img, q + 14) == 0x0038f101 && rd16(img, q + 18) == 0x460d &&
				rd32(img, q + 20) == 0x7180f44f && is_bl(img, q + 24);
			if(!compact && !stacked && !paired)
				continue;
			if(x < 0x380)
				continue;
			size_t call = src == 0 ? x - 4 : x - 16;
			if(!is_bl(img, call) || (src != 0 && rd16(img, x - 12) != (0x4600 | src)))
				continue;
			int lookup = 0;
			for(size_t p = x - 64; p < call; p += 2) {
				size_t l = literal(img, p, &unused);
				if(l != SIZE_MAX && unused == 0 && rd32(img, l) == img->base + bootargs)
					lookup = 1;
			}
			if(!lookup)
				continue;
			if(selected != SIZE_MAX)
				return -1;
			selected = x;
			selected_pool = empty;
			selected_format = q;
		}
	}
	if(selected == SIZE_MAX || strlen(args) > capacity)
		return -1;
	memcpy((uint8_t *)img->buf + dest, args, strlen(args) + 1);
	wr32(img, selected_pool, (uint32_t)(img->base + dest));
	wr16(img, selected + 4, 0xbf00);
	wr16(img, selected + 6, 0xbf00);
	LOG("Set kernel Thumb boot arguments at 0x%zx (selector 0x%zx, literal 0x%zx, formatter 0x%zx)\n",
		dest, selected, selected_pool, selected_format);
	return 0;
}

int watch_bootargs_patch(struct iboot64_img* img, const char* args) {
	// Unified loaders without certificate text can reuse a fatal diagnostic string.
	static const char diagnostic[] = "%s:%d assert failed:seems like nand might not have enough space to accomodate exported capacity \n";
	static const char storage[] = "Reliance on this certificate by any party assumes acceptance of "
		"the then applicable standard terms and conditions of use, "
		"certificate policy and certification practice statements.";
	size_t dest = SIZE_MAX, n = strlen(args);
	size_t capacity = sizeof(storage) - 2;
	if(n >= sizeof(storage) - 1) {
		WARN("Thumb boot arguments must be at most %zu bytes\n", sizeof(storage) - 2);
		return -1;
	}
	const uint8_t* b = img->buf;
	for(size_t p = 0; p + sizeof(storage) - 1 <= img->len; p++)
		if(!memcmp(b + p, storage, sizeof(storage) - 1)) {
			dest = p;
			break;
		}
	if(dest == SIZE_MAX && n < sizeof(diagnostic)) {
		dest = find_string(img, diagnostic);
		if(dest != SIZE_MAX)
			capacity = sizeof(diagnostic) - 1;
	}
	if(find_string(img, " rd=md0") != SIZE_MAX ||
		find_string(img, " rd=md0 nand-enable-reformat=1 -progress") != SIZE_MAX)
		return kernel_bootargs_patch(img, args, dest, capacity);
	size_t argstr = find_string(img, DEFAULT_BOOTARGS_STRING);
	if(argstr == SIZE_MAX)
		argstr = find_string(img, "rd=md0 nand-enable-reformat=1 -progress -restore");
	if(argstr == SIZE_MAX)
		argstr = find_string(img, OTHER_DEFAULT_BOOTARGS_STRING);
	if(argstr == SIZE_MAX)
		return split_bootargs_patch(img, args);

	if(dest == SIZE_MAX) {
		size_t capacity = strlen((const char *)b + argstr);
		if(n > capacity) {
			WARN("This Thumb image has room for at most %zu boot-argument bytes\n", capacity);
			return -1;
		}
		dest = argstr;
	}
	if(dest == SIZE_MAX)
		return -1;
	size_t lit, x;
	unsigned argreg;
	x = ref(img, argstr, 0, &argreg, &lit);
	if(x == SIZE_MAX)
		return -1;
	size_t it = SIZE_MAX;
	unsigned dst = 0, src = 0;
	for(size_t p = x + 2; p + 4 <= img->len && p < x + 40; p += width(rd16(img, p))) {
		uint16_t h = rd16(img, p), mov = rd16(img, p + 2);
		if((h == 0xbf08 || h == 0xbf18) && (mov & 0xff00) == 0x4600) {
			dst = (mov & 7) | ((mov >> 4) & 8);
			src = (mov >> 3) & 15;
			if(src == argreg || dst == argreg) {
				it = p;
				break;
			}
		}
	}
	if(it == SIZE_MAX || dst > 7)
		return -1;
	// Find the empty default used without a ramdisk.
	size_t fallback = SIZE_MAX;
	for(size_t p = it + 4; p + 4 <= img->len && p < it + 128; p += 2) {
		unsigned r;
		size_t l = literal(img, p, &r);
		if(l == SIZE_MAX || r != dst)
			continue;
		uint32_t ptr = rd32(img, l);
		if(ptr < img->base || ptr - img->base >= img->len)
			continue;
		if(b[ptr - img->base] == 0) {
			fallback = l;
			break;
		}
	}
	if(fallback == SIZE_MAX && dst == argreg)
		return -1;
	memcpy((uint8_t *)img->buf + dest, args, n + 1);
	wr32(img, lit, (uint32_t)(img->base + dest));
	wr16(img, it, 0xbf00); // nop
	if(dst == argreg)
		wr16(img, it + 2, 0xbf00);
	if(fallback != SIZE_MAX)
		wr32(img, fallback, (uint32_t)(img->base + dest));
	LOG("Set Thumb boot arguments at 0x%zx (xref 0x%zx, selector 0x%zx, literal 0x%zx, fallback 0x%zx)\n",
		dest, x, it, lit, fallback);
	return 0;
}

int watch_command_patch(struct iboot64_img* img, const char* command, uint64_t target) {
	if(target > UINT32_MAX || !target || !*command)
		return -1;

	target |= 1;
	size_t n = strlen(command) + 1, handler = SIZE_MAX;
	const uint8_t* b = img->buf;
	for(size_t s = 1; n <= img->len && s <= img->len - n; s++) {
		if(b[s - 1] || memcmp(b + s, command, n))
			continue;
		for(size_t p = 0; p + 12 <= img->len; p += 4) {
			if(rd32(img, p) != img->base + s)
				continue;
			uint32_t old = rd32(img, p + 4), desc = rd32(img, p + 8);
			if(!(old & 1) || (old & ~1U) < img->base || (old & ~1U) - img->base >= img->len ||
				desc < img->base || desc - img->base >= img->len)
				continue;
			if(handler != SIZE_MAX)
				return -1;
			handler = p + 4;
		}
	}
	if(handler == SIZE_MAX)
		return -1;
	wr32(img, handler, (uint32_t)target);
	LOG("Set Thumb command %s handler to 0x%08x\n", command, (unsigned)target);
	return 0;
}

int watch_nvram_patch(struct iboot64_img* img) {
	size_t str = find_string(img, "debug-uarts");
	if(str == SIZE_MAX)
		return -1;
	size_t funcs[3], count = 0;
	int legacy_shared_list = 0;

	for(size_t p = 4; p + 4 <= img->len; p += 4) {
		if(rd32(img, p) != img->base + str)
			continue;
		size_t start = p, entries = 0;
		while(start >= 4 && rd32(img, start - 4) && entries++ < 64) {
			uint32_t ptr = rd32(img, start - 4);
			if(ptr < img->base || ptr - img->base >= img->len)
				break;
			start -= 4;
		}
		if(start < 4 || rd32(img, start - 4) || count >= 2)
			continue;
		unsigned reg;
		size_t l, x = ref(img, start, 0, &reg, &l);
		if(x == SIZE_MAX)
			continue;
		size_t f = function_start(img, x);
		if(f == SIZE_MAX)
			return -1;
		if(count && funcs[0] == f)
			continue;
		funcs[count++] = f;
		// watchOS 1 shares one list for setenv and persistence.
		static const char* const legacy[] = {"auto-boot", "boot-args", "debug-uarts", "filesize"};
		int matches = start + 20 <= img->len && rd32(img, start + 16) == 0;
		for(size_t j = 0; matches && j < 4; j++) {
			size_t text = find_string(img, legacy[j]);
			if(text == SIZE_MAX || rd32(img, start + j * 4) != img->base + text)
				matches = 0;
		}
		legacy_shared_list |= matches;
	}
	if(count != 2 && !(count == 1 && legacy_shared_list))
		return -1;
	size_t system = find_string(img, "com.apple.System."), l;
	unsigned reg;
	size_t x = ref(img, system, 0, &reg, &l);
	if(x == SIZE_MAX || reg != 1 || x + 4 > img->len || rd16(img, x + 2) != 0x2211)
		return -1;
	size_t namespace_check = function_start(img, x);
	if(namespace_check == SIZE_MAX)
		return -1;
	funcs[count++] = namespace_check;
	for(size_t i = 0; i < count; i++) {
		wr16(img, funcs[i], 0x2000); // movs r0, #0; bx lr
		wr16(img, funcs[i] + 2, 0x4770);
		LOG("Unlocked Thumb NVRAM check at 0x%zx\n", funcs[i]);
	}
	return 0;
}
