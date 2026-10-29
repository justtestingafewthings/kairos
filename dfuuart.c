/* Early debug_enable_uarts patch, GPL-3.0-or-later.
 * Based on Nyan Satan's https://nyansatan.github.io/dfu-uart/ analysis. */
#include "dfuuart.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint16_t du_half(const uint8_t *b, size_t p) {
    return (uint16_t)b[p] | (uint16_t)b[p + 1] << 8;
}
static uint32_t du_word(const uint8_t *b, size_t p) {
    return (uint32_t)b[p] | (uint32_t)b[p + 1] << 8 |
           (uint32_t)b[p + 2] << 16 | (uint32_t)b[p + 3] << 24;
}
static size_t du_call(const uint8_t *b, size_t n, size_t p) {
    if (p > n || n - p < 4) return SIZE_MAX;
    unsigned a = du_half(b, p), v = du_half(b, p + 2);
    if ((a & 0xf800) != 0xf000 || (v & 0xd000) != 0xd000) return SIZE_MAX;
    unsigned s = (a >> 10) & 1;
    uint32_t imm = s << 24 | (1 ^ ((v >> 13 & 1) ^ s)) << 23 |
                   (1 ^ ((v >> 11 & 1) ^ s)) << 22 |
                   (a & 1023) << 12 | (v & 2047) << 1;
    int64_t target = (int64_t)p + 4 + (int64_t)imm - (s ? 0x2000000 : 0);
    return target >= 0x340 && (uint64_t)target < n ? (size_t)target : SIZE_MAX;
}
static int du_setter(const uint8_t *b, size_t n, size_t p, uint32_t base) {
    if (p > n || n - p < 10) return 0;
    unsigned literal = du_half(b,p), load = du_half(b,p+2),
             combine = du_half(b,p+4), store = du_half(b,p+6);
    if ((literal & 0xf800) != 0x4800 || (load & 0xffc0) != 0x6800 ||
        (combine & 0xffc7) != 0x4300 || (store & 0xffc7) != 0x6000 ||
        du_half(b,p+8) != 0x4770) return 0;
    unsigned address = (literal >> 8) & 7, temp = load & 7;
    if (!address || !temp || temp == address || ((load >> 3) & 7) != address ||
        ((combine >> 3) & 7) != temp || ((store >> 3) & 7) != address) return 0;
    size_t slot = ((p + 4) & ~(size_t)3) + (literal & 255) * 4;
    if (slot > n || n - slot < 4) return 0;
    uint32_t pointer = du_word(b,slot);
    /* UART state may lie in BSS beyond the file. Exclude MMIO addresses. */
    return !(pointer & 3) && pointer >= base && pointer - base < 16*1024*1024;
}
static int du_argument(const uint8_t *b, size_t n, size_t p) {
    if (p < 0x34a || p > n || n - p < 8 || du_call(b,n,p-6) == SIZE_MAX ||
        du_call(b,n,p+4) == SIZE_MAX) return 0;
    unsigned value = du_half(b,p-2), a = du_half(b,p-10), c = du_half(b,p-8);
    if (a == 0x2001) { a = c; }
    else if (c != 0x2001) return 0;
    unsigned reg, displacement;
    if ((a & 0xff87) == 0x4601) { reg = (a >> 3) & 15; displacement = 0; }
    else if ((a & 0xfe07) == 0x1c01) { reg = (a >> 3) & 7; displacement = (a >> 6) & 7; }
    else return 0;
    if (reg > 7) return 0;
    if (value == 0x2003) return 1; /* Already forced, same verified call chain. */
    return (value & 0xf807) == 0x7800 && ((value >> 3) & 7) == reg &&
           ((value >> 6) & 31) == displacement;
}
static size_t du_a64_call(const uint8_t *b, size_t n, size_t p) {
    if (p > n || n - p < 4) return SIZE_MAX;
    uint32_t op = du_word(b,p);
    if ((op & 0xfc000000) != 0x94000000) return SIZE_MAX;
    int64_t offset = (int64_t)(op & 0x3ffffff) - ((op & 0x2000000) ? 0x4000000 : 0);
    int64_t target = (int64_t)p + offset * 4;
    return target >= 0x340 && (uint64_t)target < n ? (size_t)target : SIZE_MAX;
}
static int du_a64_setter(const uint8_t *b, size_t n, size_t p) {
    if (p > n || n - p < 20) return 0;
    uint32_t page=du_word(b,p),load=du_word(b,p+4),combine=du_word(b,p+8),store=du_word(b,p+12);
    unsigned address=page&31,temp=load&31;
    if ((page&0x9f000000)!=0x90000000 || (load&0xffc00000)!=0xb9400000 ||
        ((load>>5)&31)!=address || temp==31 || temp==0 || address==31 ||
        combine!=(0x2a000000|(temp<<5)|temp) ||
        store!=(0xb9000000|(load&0x3fffff)) || du_word(b,p+16)!=0xd65f03c0) return 0;
    unsigned raw=((page>>5)&0x7ffff)<<2|((page>>29)&3);
    int64_t delta=(int64_t)raw-((raw&0x100000)?0x200000:0);
    int64_t global=(int64_t)(p&~(size_t)4095)+delta*4096+((load>>10)&0xfff)*4;
    return global>=0x340 && (uint64_t)global<n+16*1024*1024;
}
static int du_a64_argument(const uint8_t *b, size_t n, size_t p) {
    if (p<0x350 || p>n || n-p<8 || du_a64_call(b,n,p-8)==SIZE_MAX ||
        du_a64_call(b,n,p+4)==SIZE_MAX) return 0;
    uint32_t value=du_word(b,p-4),a=du_word(b,p-16),c=du_word(b,p-12);
    if (a==0x52800020 || a==0x320003e0) a=c;
    else if (c!=0x52800020 && c!=0x320003e0) return 0;
    unsigned reg,offset;
    if ((a&0xffe0ffff)==0xaa0003e1) {reg=(a>>16)&31;offset=0;}
    else if ((a&0xffc0001f)==0x91000001) {reg=(a>>5)&31;offset=(a>>10)&0xfff;}
    else return 0;
    if (reg==31) return 0;
    if (value==0x52800060) return 1;
    return (value&0xffc0001f)==0x39400000 && ((value>>5)&31)==reg &&
           ((value>>10)&0xfff)==offset;
}
static int du_a64_patch(uint8_t *b,size_t n) {
    /* Raw ARM64 entry points start with ADRP or B. */
    uint32_t first=du_word(b,0);
    if ((first&0x9f000000)!=0x90000000 && (first&0xfc000000)!=0x14000000) return -1;
    if (!memchr(b+0x280,0,0x40) || memcmp(b+0x280,"iBoot-",6)) return -1;
    size_t selected=SIZE_MAX,setter=SIZE_MAX;
    for(size_t p=0x350;p+8<=n;p+=4) {
        size_t target=du_a64_call(b,n,p);
        if(target==SIZE_MAX || !du_a64_setter(b,n,target) || !du_a64_argument(b,n,p)) continue;
        if(selected!=SIZE_MAX && selected!=p-4) {
            fputs("[!] Ambiguous early ARM64 UART initialization; no changes made\n",stderr);
            return -1;
        }
        selected=p-4;setter=target;
    }
    if(selected==SIZE_MAX) {
        fputs("[!] Could not validate early ARM64 UART initialization; no changes made\n",stderr);
        return -1;
    }
    uint32_t old=du_word(b,selected),op=0x52800060;
    for(unsigned i=0;i<4;i++) b[selected+i]=(uint8_t)(op>>(i*8));
    printf("[+] Early ARM64 UART mode 3 at 0x%zx (setter 0x%zx, %08x -> 52800060)%s\n",
           selected,setter,old,old==op?" already enabled":"");
    return 0;
}
int dfu_uart_patch(void *buffer, size_t length) {
    uint8_t *b = buffer;
    if (!b || length < 0x340 || length > 16*1024*1024) return -1;
    if (du_word(b,0) != 0xea00000e) return du_a64_patch(b,length);
    if (du_word(b,4) != 0xe59ff018) {
        fputs("[!] Early UART patch requires an unpacked Thumb bootloader\n",stderr);
        return -1;
    }
    uint32_t entry = du_word(b,0x20);
    if (entry < 0x40 || ((entry - 0x40) & 0xfff)) return -1;
    uint32_t base = entry - 0x40;
    size_t selected = SIZE_MAX, setter = SIZE_MAX;
    for (size_t p = 0x34a; p + 8 <= length; p += 2) {
        size_t target = du_call(b,length,p);
        if (target == SIZE_MAX || !du_setter(b,length,target,base) || !du_argument(b,length,p)) continue;
        if (selected != SIZE_MAX && selected != p - 2) {
            fputs("[!] Ambiguous early UART initialization; no changes made\n",stderr);
            return -1;
        }
        selected = p - 2; setter = target;
    }
    if (selected == SIZE_MAX) {
        fputs("[!] Could not validate early UART initialization; no changes made\n",stderr);
        return -1;
    }
    unsigned old = du_half(b,selected);
    b[selected] = 3; b[selected+1] = 0x20;
    printf("[+] Early Thumb UART mode 3 at 0x%zx (setter 0x%zx, %04x -> 2003)%s\n",
           selected,setter,old,old == 0x2003 ? " already enabled" : "");
    return 0;
}
