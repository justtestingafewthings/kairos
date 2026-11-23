ifeq ($(OS),Windows_NT)
	detected_OS := Windows
	TARGET := kairos.exe
else
	detected_OS := $(shell uname 2>/dev/null || echo unknown)
	TARGET := kairos
endif

CPPFLAGS += -Iinclude -Iarm32
ifneq ($(detected_OS),Darwin)
CPPFLAGS += -DNOT_DARWIN
endif
CFLAGS += -Wno-multichar

SOURCES := main.c imageio.c arm32_dispatch.c \
	arm32/driver.c arm32/finders.c arm32/functions.c arm32/patchers.c \
	dfuuart.c kaslr64.c watchkaslr.c watchimage.c watchpatch.c watchoptions.c \
	patchfinder64.c newpatch.c decoders.c instructions.c
HEADERS := $(wildcard include/*.h arm32/include/*.h)

.PHONY: all clean
all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS) storage_keys64.c Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES) $(LDLIBS)

clean:
	$(RM) kairos kairos.exe
