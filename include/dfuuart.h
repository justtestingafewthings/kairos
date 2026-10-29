#ifndef KAIROS_DFU_UART_H
#define KAIROS_DFU_UART_H
#include <stddef.h>
/* Force early Thumb/ARM64 UART mode 3, before NVRAM. Returns 0 or -1 without edits. */
int dfu_uart_patch(void *buffer, size_t length);
#endif
