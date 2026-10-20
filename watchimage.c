#include "watchpatch.h"

static uint32_t image_word(const uint8_t* b, size_t p) {
	return (uint32_t)b[p] | (uint32_t)b[p + 1] << 8 |
		(uint32_t)b[p + 2] << 16 | (uint32_t)b[p + 3] << 24;
}

static int watch_board(const uint8_t* b) {
	static const char* const names[] = {
		"n27a", "n28a", "n27d", "n28d", "n64", "n65",
		"n74", "n75",
		"n111s", "n111b", "n121s", "n121b"
	};
	static const char* const stages[] = {
		"iBSS for ", "iBEC for ", "LLB for ", "iBoot for ",
		"iBootStage1 for ", "iBootStage2 for "
	};
	for(size_t s = 0; s < sizeof(stages) / sizeof(stages[0]); s++) {
		size_t prefix = strlen(stages[s]);
		if(memcmp(b + 0x200, stages[s], prefix))
			continue;
		for(size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
			size_t length = strlen(names[i]);
			if(!memcmp(b + 0x200 + prefix, names[i], length) &&
				!memcmp(b + 0x200 + prefix + length, ", Copyright ", 12))
				return 1;
		}
	}
	return 0;
}

static int version_string(const uint8_t* b) {
	if(memcmp(b + 0x280, "iBoot-", 6) || b[0x286] < '0' || b[0x286] > '9')
		return 0;
	for(size_t p = 0x287; p < 0x2c0; p++) {
		if(!b[p])
			return 1;
		if((b[p] < '0' || b[p] > '9') && b[p] != '.')
			return 0;
	}
	return 0;
}

static int string_pointers(const uint8_t* b, size_t table, uint32_t base) {
	return base <= UINT32_MAX - 0x280 &&
		image_word(b, table) == base + 0x200 &&
		image_word(b, table + 4) == base + 0x240 &&
		image_word(b, table + 8) == base + 0x280 &&
		image_word(b, 0x20) == base + 0x40;
}

int watch_image_info(const uint8_t* b, size_t n, uint32_t* base) {
	uint32_t address;
	if(!b || n < 0x340 || image_word(b, 0) != 0xea00000e ||
		!watch_board(b) || !version_string(b))
		return 0;

	// Headers before the UUID command.
	address = image_word(b, 0x310);
	if(string_pointers(b, 0x300, address))
		goto found;
	address = image_word(b, 0x330);
	if(string_pointers(b, 0x320, address))
		goto found;

	// Newer headers use entry points and image bounds.
	address = image_word(b, 0x324);
	if(address > UINT32_MAX - 0x340 || (address & 0xfff) ||
		image_word(b, 0x20) != address + 0x40 ||
		image_word(b, 0x300) != 0x64697575 || image_word(b, 0x304) != 1)
		return 0;
	uint32_t entry = image_word(b, 0x320);
	uint32_t end = image_word(b, 0x328);
	uint32_t code_end = image_word(b, 0x32c);
	uint32_t data_start = image_word(b, 0x330);
	if(!(entry & 1) || (entry & ~1u) < address + 0x340 ||
		(uint64_t)(entry & ~1u) - address >= n || end <= address ||
		(uint64_t)end - address > n || code_end <= (entry & ~1u) ||
		code_end > data_start || data_start > end)
		return 0;

found:
	if(base)
		*base = address;
	return 1;
}
