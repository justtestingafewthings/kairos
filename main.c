/*
 * main.c - main file for using kairos, used to patch unpacked IM4P iOS bootloader images
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

#include "newpatch.h"
#include "watchoptions.h"
#include "watchpatch.h"
#include <errno.h>

int main(int argc, char* argv[]) {
	if(argc < 3) {
		printf("Incorrect usage\nusage: %s [deciBoot] [patchediBoot] [OPTIONS]\n",argv[0]);
		printf("Options:\n\t-b [args]\t\tset boot-args\n");
		printf("\t-c [cmd] [location]\trelocate command handler\n");
		printf("\t-n\t\t\tunlock nvram\n");
		printf("\nExample usage:\n%s iBEC.dec iBEC.patched -n -b \"-v debug=0x09\" -c \"go\" 0x830000300\n",argv[0]);
		return -1;
	}
	
	char* inFile = argv[1];
	char* outFile = argv[2];
	char* bootArgs = NULL;
	char* command_str = NULL;
	uint64_t command_ptr = 0;
	struct iboot64_img iboot_in;
	int ret = 0;
	memset(&iboot_in, 0, sizeof(iboot_in));
	bool doNvramUnlock = false;

	for(int i = 3; i < argc; i++) {
		if(!strcmp(argv[i], "-b") && i + 1 < argc) {
			bootArgs = argv[++i];
		} else if(!strcmp(argv[i], "-c") && i + 2 < argc) {
			command_str = argv[++i];
			char* end;
			const char* address = argv[++i];
			errno = 0;
			command_ptr = strtoull(address, &end, 0);
			if(errno || end == address || *end || address[0] == '-' || !command_ptr) {
				WARN("Invalid command handler address: %s\n", address);
				return 1;
			}
		} else if(!strcmp(argv[i], "-n")) {
			doNvramUnlock = true;
		} else {
			WARN("Unknown option or missing argument: %s\n", argv[i]);
			return 1;
		}
	}
	// read in image
	FILE* fp = fopen(inFile,"rb");
	if(!fp) {
		printf("Error opening %s for reading\n",inFile);
		return -1;
	}
	if(fseek(fp, 0, SEEK_END)) {
		fclose(fp);
		return 1;
	}
	long file_size = ftell(fp);
	if(file_size < 0x340 || fseek(fp, 0, SEEK_SET)) {
		WARN("Input is too short to be an unpacked iBoot image\n");
		fclose(fp);
		return 1;
	}
	iboot_in.len = (size_t)file_size;
	iboot_in.buf = malloc(iboot_in.len);
	if(!iboot_in.buf) {
		fclose(fp);
		return 1;
	}
	if(fread(iboot_in.buf, 1, iboot_in.len, fp) != iboot_in.len) {
		WARN("Could not read the complete input image\n");
		free(iboot_in.buf);
		fclose(fp);
		return 1;
	}
	fclose(fp);
	LOG("Patching %s\n",inFile);
	if(has_magic(iboot_in.buf)) {
		WARN("%s does not appear to be stripped\n",inFile);
		free(iboot_in.buf);
		return -1;
	}
	uint32_t reset;
	memcpy(&reset, iboot_in.buf, sizeof(reset));
	uint32_t base;
	if(watch_image_info(iboot_in.buf, iboot_in.len, &base)) {
		iboot_in.base = base;
		get_iboot64_version(&iboot_in);
		LOG("ARMv7 Thumb Watch bootloader, base 0x%08x, iBoot-%u.%u\n", base, iboot_in.VERS,
			iboot_in.minor_vers);
		ret = watch_sigcheck_patch(&iboot_in);
		if(ret < 0)
			goto patch_failed;
		if(has_kernel_load_k(&iboot_in)) {
			if(bootArgs && watch_bootargs_patch(&iboot_in, bootArgs) < 0) {
				WARN("Failed to patch Thumb boot arguments\n");
				goto patch_failed;
			}
			if(watch_debug_patch(&iboot_in) < 0)
				WARN("Could not enable Thumb kernel debug\n");
		}
		if(has_recovery_console_k(&iboot_in)) {
			if(command_str && watch_command_patch(&iboot_in, command_str, command_ptr) < 0) {
				WARN("Failed to patch Thumb command handler\n");
				goto patch_failed;
			}
			if(doNvramUnlock && watch_nvram_patch(&iboot_in) < 0) {
				WARN("Failed to unlock Thumb NVRAM\n");
				goto patch_failed;
			}
		}
		goto write_output;
	}
	if((reset & 0xff000000) == 0xea000000 ||
		!memcmp((uint8_t *)iboot_in.buf + 4, "\x18\xf0\x9f\xe5", 4) ||
		!get_iboot64_version(&iboot_in)) {
		WARN("Unsupported or invalid unpacked bootloader\n");
		goto patch_failed;
	}
	LOG("Base address: 0x%llx\n",get_iboot64_base_address(&iboot_in));
	bool pac = iboot64_pac_check(&iboot_in);
	if(has_kernel_load_k(&iboot_in)) {
		LOG("Does have kernel load\n");
		if(bootArgs) {
			LOG("Patching boot-args...\n");
			ret = patch_boot_args64(&iboot_in,bootArgs);
			if(ret < 0) {
				WARN("Failed to patch boot-args\n");
				goto patch_failed;
			}
		}
		LOG("Enabling kernel debug...\n");
		ret = enable_kernel_debug(&iboot_in);
		if(ret < 0)
			WARN("Could not enable kernel debug\n");
	}
	if(has_recovery_console_k(&iboot_in)) {
		if(command_str && (command_ptr != 0)) { // need to reassign command handler
			LOG("Changing command handler %s to 0x%llx...\n",command_str,command_ptr);
			ret = do_command_handler_patch(&iboot_in,command_str,command_ptr);
			if(ret < 0) {
				WARN("Failed to patch command handler for %s\n",command_str);
				goto patch_failed;
			}
		}
		if(doNvramUnlock) {
			LOG("Unlocking nvram...\n");
			ret = unlock_nvram(&iboot_in);
			if(ret < 0) {
				WARN("Failed to unlock nvram\n");
				goto patch_failed;
			}
		}
	}
	LOG("Patching out RSA signature check...\n");
	ret = rsa_sigcheck_patch(&iboot_in, pac);
	if(ret < 0)
		goto patch_failed;

write_output:
	// now write file
	fp = fopen(outFile,"wb+");
	if(!fp) {
		printf("Error opening %s for writing\n",outFile);
		free(iboot_in.buf);
		return -1;
	}
	if(fwrite(iboot_in.buf, 1, iboot_in.len, fp) != iboot_in.len || fflush(fp)) {
		WARN("Error writing %s\n", outFile);
		fclose(fp);
		free(iboot_in.buf);
		return 1;
	}
	if(fclose(fp)) {
		WARN("Error closing %s\n", outFile);
		free(iboot_in.buf);
		return 1;
	}
	free(iboot_in.buf);
	LOG("Wrote patched image to %s\n",outFile);
	return 0;

patch_failed:
	WARN("Patching failed; output was not written\n");
	free(iboot_in.buf);
	return 1;
}
