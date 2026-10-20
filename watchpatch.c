#include "watchpatch.h"

static uint16_t read16(const uint8_t* b, size_t p) {
	return (uint16_t)b[p] | (uint16_t)b[p + 1] << 8;
}

static uint32_t read32(const uint8_t* b, size_t p) {
	return (uint32_t)read16(b, p) | (uint32_t)read16(b, p + 2) << 16;
}

static int prologue(const uint8_t* b, size_t n, size_t p) {
	return p <= n && n - p >= 4 && read16(b, p) == 0xb5f0 && read16(b, p + 2) == 0xaf03;
}

static size_t function_start(const uint8_t* b, size_t n, size_t p) {
	for(p &= ~(size_t)1; p >= 0x340; p -= 2)
		if(prologue(b, n, p))
			return p;
	return 0;
}

static size_t function_end(const uint8_t* b, size_t n, size_t start) {
	for(size_t p = start + 4; p + 4 <= n; p += 2)
		if(prologue(b, n, p))
			return p;
	return n;
}

static int literal(const uint8_t* b, size_t n, size_t p, unsigned reg, uint32_t* value) {
	if(p > n || n - p < 2)
		return 0;
	uint16_t h = read16(b, p);
	if((h & 0xff00) != (0x4800 | reg << 8))
		return 0;
	size_t pool = ((p + 4) & ~(size_t)3) + (h & 255) * 4;
	if(pool > n || n - pool < 4)
		return 0;
	*value = read32(b, pool);
	return 1;
}

static int branch_target(const uint8_t* b, size_t n, size_t p, size_t* target) {
	if(p > n || n - p < 4)
		return 0;
	uint16_t a = read16(b, p), z = read16(b, p + 2);
	if((a & 0xf800) != 0xf000 || (z & 0xd000) != 0xd000)
		return 0;
	uint32_t s = (a >> 10) & 1;
	uint32_t i1 = !(((z >> 13) & 1) ^ s), i2 = !(((z >> 11) & 1) ^ s);
	uint32_t raw = s << 24 | i1 << 23 | i2 << 22 | (a & 1023) << 12 | (z & 2047) << 1;
	int32_t displacement = (int32_t)(raw << 7) >> 7;
	int64_t destination = (int64_t)p + 4 + displacement;
	if(destination < 0 || (uint64_t)destination >= n)
		return 0;
	*target = (size_t)destination;
	return 1;
}

static int address_offset(uint32_t address, uint64_t base, size_t n, size_t* offset) {
	if(address < base || (uint64_t)address - base >= n)
		return 0;
	*offset = (size_t)((uint64_t)address - base);
	return 1;
}

// Older callbacks are direct; newer ones use a table.
static size_t callback(const uint8_t* b, size_t n, uint64_t base, uint32_t value) {
	size_t p;
	if((value & 1) && address_offset(value & ~1u, base, n, &p) && prologue(b, n, p))
		return p;
	if(!(value & 3) && address_offset(value, base, n, &p) && n - p >= 8) {
		uint32_t first = read32(b, p), second = read32(b, p + 4);
		size_t q, r;
		if((first & 1) && (second & 1) && address_offset(first & ~1u, base, n, &q) &&
			address_offset(second & ~1u, base, n, &r) && prologue(b, n, q))
			return q;
	}
	return 0;
}

static int crypto_call(const uint8_t* b, size_t n, uint64_t base, uint32_t table,
	size_t verifier) {
	size_t data;
	if((table & 3) || !address_offset(table, base, n, &data) || n - data < 20 ||
		!prologue(b, n, verifier))
		return 0;
	for(size_t i = 0; i < 4; i++) {
		uint32_t pointer = read32(b, data + i * 4);
		size_t member;
		if(!(pointer & 1) || !address_offset(pointer & ~1u, base, n, &member) ||
			n - member < 4)
			return 0;
	}
	unsigned table_reg = 16;
	size_t end = function_end(b, n, verifier);
	if(end - verifier > 0x500)
		end = verifier + 0x500;
	for(size_t p = verifier + 4; p + 4 <= end; p += 2) {
		uint16_t h = read16(b, p), second = read16(b, p + 2);
		if((h & 0xfff8) == 0x4618)
			table_reg = h & 7; // MOV rN,r3
		unsigned reg = 16;
		if(table_reg < 8 && h == (0xf8d0 | table_reg) && (second & 0x0fff) == 8)
			reg = second >> 12;
		if(table_reg < 8 && (h & 0xfff8) == (0x6880 | table_reg << 3))
			reg = h & 7;
		if(reg < 15)
			for(size_t q = p + 2; q + 2 <= end && q <= p + 64; q += 2)
				if(read16(b, q) == (0x4780 | reg << 3))
					return 1;
	}
	return 0;
}

// watchOS 7 wraps the six-argument evaluator.
static size_t evaluator(const uint8_t* b, size_t n, size_t entry) {
	if(prologue(b, n, entry))
		return entry;
	if(entry > n || n - entry < 26 || read32(b, entry) != 0x466fb580 ||
		read16(b, entry + 4) != 0xb082 || read16(b, entry + 6) != 0xf8d7)
		return 0;
	unsigned context_reg = read16(b, entry + 8) >> 12;
	size_t internal;
	if((read16(b, entry + 8) & 0xfff) != 8 || context_reg < 8 || context_reg > 12 ||
		read32(b, entry + 10) != 0x0c00f04f || read16(b, entry + 14) != 0xe9cd ||
		read16(b, entry + 16) != (0xc000 | context_reg << 8) ||
		!branch_target(b, n, entry + 18, &internal) ||
		read32(b, entry + 22) != 0xbd80b002 || !prologue(b, n, internal))
		return 0;
	return internal;
}

static int legacy_adapter(const uint8_t* b, size_t n, size_t entry) {
	size_t internal;
	return entry <= n && n - entry >= 64 && read32(b, entry) == 0x466fb580 &&
		read16(b, entry + 4) == 0xb083 && read32(b, entry + 48) == 0x5000e88d &&
		read32(b, entry + 52) == 0x464b9302 &&
		branch_target(b, n, entry + 56, &internal) && prologue(b, n, internal) &&
		read32(b, entry + 60) == 0xbd80b003;
}

enum value_kind { UNKNOWN, ADDRESS, STACK };
struct value {
	enum value_kind kind;
	uint32_t value;
};
struct call_state {
	struct value reg[16];
	struct value stack[1024];
};

static size_t instruction_width(uint16_t h) {
	return (h & 0xf800) >= 0xe800 ? 4 : 2;
}

static void invalidate_writes(struct call_state* state, uint16_t h, uint16_t second,
	size_t width) {
	if(width == 2) {
		if((h & 0xe000) == 0x0000 || (h & 0xfc00) == 0x4000 ||
			(h & 0xff00) == 0xb200 || (h & 0xff00) == 0xba00) {
			unsigned op = (h >> 6) & 15;
			if((h & 0xfc00) != 0x4000 || (op != 8 && op != 10 && op != 11))
				state->reg[h & 7].kind = UNKNOWN;
		} else if((h & 0xe000) == 0x2000) {
			if((h & 0xf800) != 0x2800) // CMP does not write.
				state->reg[(h >> 8) & 7].kind = UNKNOWN;
		} else if((h & 0xff00) == 0x4400) {
			state->reg[(h & 7) | ((h >> 4) & 8)].kind = UNKNOWN;
		} else if(((h & 0xf000) == 0x5000 && ((h >> 9) & 7) >= 3) ||
				((h & 0xe000) == 0x6000 && (h & 0x0800)) ||
				((h & 0xf000) == 0x8000 && (h & 0x0800))) {
			state->reg[h & 7].kind = UNKNOWN;
		} else if((h & 0xf800) == 0x9800) {
			state->reg[(h >> 8) & 7].kind = UNKNOWN;
		} else if((h & 0xf800) == 0xa000) {
			state->reg[(h >> 8) & 7].kind = UNKNOWN;
		} else if((h & 0xfe00) == 0xbc00 || (h & 0xf800) == 0xc800) {
			for(unsigned i = 0; i < 8; i++)
				if(h & (1u << i))
					state->reg[i].kind = UNKNOWN;
		}
		if((h & 0xf000) == 0xc000)
			state->reg[(h >> 8) & 7].kind = UNKNOWN;
		if((h & 0xff80) == 0x4780) {
			for(unsigned i = 0; i < 4; i++)
				state->reg[i].kind = UNKNOWN;
			state->reg[12].kind = UNKNOWN;
		}
	} else {
		// LDR/LDRB/LDRH and LDRD, including frame-relative forms.
		if((h & 0xfe10) == 0xf810)
			state->reg[second >> 12].kind = UNKNOWN;
		else if((h & 0xfff0) == 0xf840 && (second & 0x0100))
			state->reg[h & 15].kind = UNKNOWN; // STR with writeback.
		else if((h & 0xfe50) == 0xe850) {
			state->reg[second >> 12].kind = UNKNOWN;
			state->reg[(second >> 8) & 15].kind = UNKNOWN;
		} else if(h == 0xe8bd) {
			for(unsigned i = 0; i < 16; i++)
				if(second & (1u << i))
					state->reg[i].kind = UNKNOWN;
		} else if((h & 0xfe00) == 0xea00 ||
				((h & 0xfc00) == 0xf000 && !(second & 0x8000))) {
			state->reg[(second >> 8) & 15].kind = UNKNOWN;
		}
	}
}

static void arguments(const uint8_t* b, size_t n, size_t start, size_t call,
	struct call_state* state) {
	memset(state, 0, sizeof(*state));
	for(size_t p = start; p + 2 <= call;) {
		uint16_t h = read16(b, p);
		size_t width = instruction_width(h);
		if(p + width > call)
			break;
		uint16_t second = width == 4 ? read16(b, p + 2) : 0;
		if((h & 0xf800) == 0x4800) {
			uint32_t value;
			unsigned reg = (h >> 8) & 7;
			state->reg[reg].kind = UNKNOWN;
			if(literal(b, n, p, reg, &value))
				state->reg[reg] = (struct value){ ADDRESS, value };
		} else if((h & 0xf800) == 0xa800) {
			state->reg[(h >> 8) & 7] = (struct value){ STACK, (h & 255) * 4 };
		} else if(h == 0xf10d && !(second & 0x8000) && !(second & 0x7000)) {
			state->reg[(second >> 8) & 15] = (struct value){ STACK, second & 255 };
		} else if((h & 0xff00) == 0x4600) {
			unsigned dest = (h & 7) | ((h >> 4) & 8), src = (h >> 3) & 15;
			state->reg[dest] = state->reg[src];
		} else if((h & 0xf800) == 0x9000) {
			state->stack[h & 255] = state->reg[(h >> 8) & 7];
		} else if(h == 0xf8cd) {
			state->stack[(second & 0xfff) / 4] = state->reg[second >> 12];
		} else if(h == 0xe9cd) {
			size_t index = second & 255;
			state->stack[index] = state->reg[second >> 12];
			state->stack[index + 1] = state->reg[(second >> 8) & 15];
		} else {
			invalidate_writes(state, h, second, width);
		}

		if(width == 4 && (h & 0xf800) == 0xf000 && (second & 0xc000) == 0xc000) {
			for(size_t i = 0; i < 4; i++)
				state->reg[i] = (struct value){ UNKNOWN, 0 };
			state->reg[12].kind = UNKNOWN;
		}
		p += width;
	}
}

static int property_offsets(const uint8_t* b, size_t n, size_t loader, size_t end,
	uint32_t properties, unsigned* key_offset) {
	unsigned counts[256] = {0};
	unsigned direct_calls[256] = {0}, conditional_calls[256] = {0};
	for(size_t p = loader; p + 4 <= end && p + 4 <= n; p += 2) {
		if(read16(b, p) != 0xf89d)
			continue; // LDRB.W r0,[sp,#imm12]
		uint16_t h = read16(b, p + 2);
		unsigned offset = h & 0xfff;
		if((h & 0xf000) || offset < properties || offset - properties >= 256)
			continue;
		unsigned field = offset - properties;
		counts[field]++;
		size_t target;
		if(branch_target(b, n, p + 4, &target))
			direct_calls[field]++;
		// security_set_untrusted is conditional on !enable_keys.
		uint16_t branch = p + 6 <= end ? read16(b, p + 4) : 0;
		if((branch & 0xf507) == 0xb100 && p + 10 <= end &&
			branch_target(b, n, p + 6, &target))
			conditional_calls[field]++;
		if(branch == 0x2800 && p + 12 <= end && read16(b, p + 6) == 0xbf08 &&
			branch_target(b, n, p + 8, &target))
			conditional_calls[field]++;
	}
	unsigned matches = 0;
	for(unsigned i = 1; i + 1 < 256; i++)
		if(counts[i] >= 2 && counts[i + 1] >= 1 && direct_calls[i - 1] &&
			conditional_calls[i]) {
			*key_offset = i;
			matches++;
		}
	return matches == 1;
}

int watch_sigcheck_patch(struct iboot64_img* image) {
	const uint8_t* b = image->buf;
	size_t n = image->len, parser = 0, selected = 0;
	unsigned selected_key = 0;
	int selected_legacy = 0;
	uint32_t base;
	if(!watch_image_info(b, n, &base) || image->base != base)
		return -1;

	for(size_t p = 0x340; p + 2 <= n; p += 2) {
		uint32_t value;
		size_t string;
		if(literal(b, n, p, 1, &value) && address_offset(value, image->base, n, &string) &&
			n - string >= 5 && !memcmp(b + string, "IMG4\0", 5)) {
			size_t f = function_start(b, n, p);
			if(!f || (parser && parser != f))
				return -1;
			parser = f;
		}
	}
	if(!parser)
		return -1;
	for(size_t p = 0x340; p + 4 <= n; p += 2) {
		size_t target;
		if(!branch_target(b, n, p, &target) || target != parser)
			continue;
		size_t loader = function_start(b, n, p);
		if(!loader)
			continue;
		size_t end = function_end(b, n, loader);
		// Legacy callers pass the context in r3, newer callers on the stack.
		for(size_t call = p + 4; call + 4 <= end; call += 2) {
			size_t verifier;
			if(!branch_target(b, n, call, &verifier))
				continue;
			struct call_state state;
			arguments(b, n, loader, call, &state);
			if(state.reg[2].kind != ADDRESS ||
				!callback(b, n, image->base, state.reg[2].value))
				continue;
			int legacy = state.reg[3].kind == STACK && legacy_adapter(b, n, verifier);
			size_t internal = legacy ? 0 : evaluator(b, n, verifier);
			if(!legacy && (!internal || state.reg[3].kind != ADDRESS ||
				!crypto_call(b, n, image->base, state.reg[3].value, internal)))
				continue;
			struct value context = legacy ? state.reg[3] : state.stack[0];
			if(context.kind != STACK || (context.value & 3) || context.value > 4084)
				continue;
			struct value properties = state.stack[context.value / 4 + 2];
			unsigned key;
			if(properties.kind != STACK ||
				!property_offsets(b, n, loader, end, properties.value, &key))
				continue;
			if(selected && (selected != verifier || selected_key != key ||
				selected_legacy != legacy))
				return -1;
			selected = verifier;
			selected_key = key;
			selected_legacy = legacy;
		}
	}
	if(!selected) {
		WARN("Could not identify Watch IMG4 trust evaluator\n");
		return -1;
	}

	uint8_t trust_patch[] = {
		0x00, 0x98,       // LDR r0,[sp], or MOV r0,r3 for the legacy ABI
		0x80, 0x68,       // LDR r0,[r0,#8] -- img_properties
		0x01, 0x21,       // MOVS r1,#1
		0x80, 0xf8, 0, 0, // STRB.W r1,[r0,#EKEY]
		0x80, 0xf8, 0, 0, // STRB.W r1,[r0,#AMNM]
		0x00, 0x20,       // MOVS r0,#0 -- DR_Success
		0x70, 0x47,       // BX lr
	};
	if(selected_legacy) {
		trust_patch[0] = 0x18;
		trust_patch[1] = 0x46;
	}
	unsigned offsets[] = { selected_key, selected_key + 1 };
	for(size_t i = 0; i < 2; i++) {
		trust_patch[8 + 4 * i] = offsets[i] & 255;
		trust_patch[9 + 4 * i] = 0x10 | (offsets[i] >> 8);
	}
	if(n - selected < sizeof(trust_patch))
		return -1;
	memcpy((uint8_t *)image->buf + selected, trust_patch, sizeof(trust_patch));
	LOG("Patched Thumb IMG4 trust evaluation at 0x%zx (EKEY +0x%x, AMNM +0x%x%s)\n",
		selected, selected_key, selected_key + 1, selected_legacy ? ", legacy ABI" : "");
	return 0;
}
