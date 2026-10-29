#define _POSIX_C_SOURCE 200809L
#include "imageio.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int kairos_check_paths(const char *input, const char *output) {
	struct stat source, destination;
	if(stat(input, &source)) {
		perror(input);
		return 1;
	}
	if(!S_ISREG(source.st_mode)) {
		fprintf(stderr, "Input must be a regular file: %s\n", input);
		return 1;
	}
	if(stat(output, &destination)) {
		if(errno == ENOENT)
			return 0;
		perror(output);
		return 1;
	}
	if(source.st_dev == destination.st_dev && source.st_ino == destination.st_ino) {
		fputs("Input and output must be different files\n", stderr);
		return 1;
	}
	if(!S_ISREG(destination.st_mode)) {
		fprintf(stderr, "Output must be a regular file: %s\n", output);
		return 1;
	}
	return 0;
}

int kairos_write_image(const char *input, const char *output,
	const void *data, size_t size) {
	if(kairos_check_paths(input, output))
		return 1;

	static const char suffix[] = ".tmp.XXXXXX";
	size_t length = strlen(output);
	if(length > SIZE_MAX - sizeof(suffix)) {
		errno = ENAMETOOLONG;
		perror(output);
		return 1;
	}
	char *temporary = malloc(length + sizeof(suffix));
	if(!temporary) {
		perror(output);
		return 1;
	}
	memcpy(temporary, output, length);
	memcpy(temporary + length, suffix, sizeof(suffix));
	int fd = mkstemp(temporary);
	if(fd < 0) {
		perror(output);
		free(temporary);
		return 1;
	}

	int error = 0;
	FILE *stream = fdopen(fd, "wb");
	if(!stream) {
		error = errno;
		close(fd);
	} else {
		errno = 0;
		if(fwrite(data, 1, size, stream) != size)
			error = errno ? errno : EIO;
		if(fclose(stream) && !error)
			error = errno ? errno : EIO;
	}
	if(!error && rename(temporary, output))
		error = errno;
	if(error) {
		unlink(temporary);
		errno = error;
		perror(output);
	}
	free(temporary);
	return error != 0;
}
