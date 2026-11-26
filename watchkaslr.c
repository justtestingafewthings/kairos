/* Thumb kernel-slide discovery, GPL-3.0-or-later. Preserve load alignment. */
#include "watchkaslr.h"
#include "compat.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct wk_plan { size_t sites[2]; unsigned count, reg; };
static uint16_t wk_h(const struct iboot64_img *i, size_t p) {
    const unsigned char *b = i->buf;
    return (uint16_t)b[p] | (uint16_t)b[p + 1] << 8;
}
static uint32_t wk_w(const struct iboot64_img *i, size_t p) {
    return (uint32_t)wk_h(i,p) | (uint32_t)wk_h(i,p+2)<<16;
}
static int wk_call(const struct iboot64_img *i, size_t p) {
    if (p > i->len || i->len-p < 4) return 0;
    unsigned h=wk_h(i,p),l=wk_h(i,p+2),s=(h>>10)&1;
    if ((h&0xf800)!=0xf000 || (l&0xd000)!=0xd000) return 0;
    uint32_t imm=s<<24 | (1^((l>>13&1)^s))<<23 |
        (1^((l>>11&1)^s))<<22 | (h&1023)<<12 | (l&2047)<<1;
    int64_t target=(int64_t)p+4+imm-(s?0x2000000:0);
    return target>=0x340 && (uint64_t)target+2<=i->len;
}
static uint32_t wk_expand(unsigned imm) {
    unsigned byte=imm&255;
    if (!(imm&0xc00)) {
        switch ((imm>>8)&3) {
            case 0:return byte;
            case 1:return byte<<16|byte;
            case 2:return byte<<24|byte<<8;
            default:return byte*0x01010101u;
        }
    }
    unsigned value=0x80|(imm&127),rotate=(imm>>7)&31;
    return value>>rotate | value<<(32-rotate);
}
static int wk_mov(const struct iboot64_img *i,size_t p,unsigned *reg,uint32_t *value) {
    if (p>i->len || i->len-p<4) return 0;
    unsigned h=wk_h(i,p),l=wk_h(i,p+2);
    if ((h&0xfbff)!=0xf04f || (l&0x8000)) return 0;
    *reg=(l>>8)&15;
    *value=wk_expand(((h>>10)&1)<<11|((l>>12)&7)<<8|(l&255));
    return *reg<13;
}
static int wk_zero(const struct iboot64_img *i,size_t p,unsigned reg) {
    unsigned r;uint32_t v;
    return wk_mov(i,p,&r,&v) && r==reg && v==0;
}
static int wk_literal(const struct iboot64_img *i,size_t p,unsigned reg,uint32_t wanted) {
    if (p>i->len || i->len-p<2) return 0;
    unsigned h=wk_h(i,p);
    if ((h&0xf800)!=0x4800 || ((h>>8)&7)!=reg) return 0;
    size_t slot=((p+4)&~(size_t)3)+(h&255)*4;
    return slot<=i->len && i->len-slot>=4 && wk_w(i,slot)==wanted;
}
static int wk_store(const struct iboot64_img *i,size_t start,unsigned reg) {
    if(start>i->len)return 0;
    size_t end=i->len-start<192?i->len:start+192;
    for(size_t p=start;p+4<=end;p+=2) {
        unsigned h=wk_h(i,p),l=wk_h(i,p+2);
        if ((h&0xf800)==0x9000 && ((h>>8)&7)==reg) return 1;
        if (h==0xf8cd && l>>12==reg) return 1;
        if (h==0xe9cd && ((l>>12)==reg || ((l>>8)&15)==reg)) return 1;
    }
    return 0;
}
static int wk_entropy(const struct iboot64_img *i,size_t load,unsigned offset) {
    if (load<0x354 || !wk_call(i,load-4)) return 0;
    int address=0,length=0;
    for(size_t q=load-14;q<load-4;q+=2) {
        unsigned h=wk_h(i,q);
        address|=(h&0xff00)==0xa800 && (h&255)*4==offset;
        length|=h==0x2104;
    }
    return address && length;
}
static int wk_classic(const struct iboot64_img *i,size_t p,struct wk_plan *out) {
    if (wk_h(i,p)!=0xf89d) return 0;
    unsigned load=wk_h(i,p+2),byte=load>>12,offset=load&4095;
    if (byte>7 || !wk_entropy(i,p,offset)) return 0;
    for(size_t q=p+8;q+12<=i->len && q<=p+28;q+=2) {
        if (wk_h(i,q)!=(0x2800|byte<<8)) continue;
        size_t add=q+2;
        unsigned h=wk_h(i,add),l=wk_h(i,add+2),reg=(l>>8)&15,base=h&15;
        int original=(h&0xfff0)==0xeb00 && !(l&0x8030) &&
            (((l>>12)&7)*4+((l>>6)&3))==21 && (l&15)==byte && reg<13;
        if (!original) {
            uint32_t value;
            if (!wk_mov(i,add,&reg,&value) || value) continue;
        }
        int constant=0;
        for(size_t a=p+4;a+4<=q;a+=2) {
            unsigned r;uint32_t v;
            if(wk_mov(i,a,&r,&v) && v==0x1000000 && (!original || r==base)) constant=1;
        }
        if(!constant || wk_h(i,add+4)!=0xbf08) continue;
        unsigned fallback_reg;uint32_t fallback;
        if(!wk_mov(i,add+6,&fallback_reg,&fallback) || fallback_reg!=reg ||
           (original ? (fallback!=0x1000000 && fallback!=0x21000000) : fallback!=0)) continue;
        if(!wk_store(i,add+10,reg)) continue;
        *out=(struct wk_plan){{add,add+6},2,reg};return 1;
    }
    return 0;
}
static int wk_entropy_register(const struct iboot64_img *i,size_t p,unsigned reg) {
    /* Track the saved entropy word before its low byte enters the slide. */
    size_t begin=p>160?p-160:0x340;
    for(size_t load=begin;load+4<=p;load+=2) {
        if(wk_h(i,load)!=0xf8dd || wk_h(i,load+2)>>12!=reg) continue;
        unsigned offset=wk_h(i,load+2)&4095;
        for(size_t call=load>=20?load-20:0x340;call+4<=load;call+=2) {
            if(!wk_call(i,call))continue;
            int size=0,address=0;
            for(size_t q=call>=16?call-16:0x340;q<call;q+=2) {
                unsigned h=wk_h(i,q);
                size|=h==0x2104;
                if((h&0xff00)==0xa800 && (h&255)*4==offset) address=1;
                if((h&0xff00)==0x4600 && (h&0x87)==0) {
                    unsigned from=((h>>3)&15);
                    for(size_t a=call>=24?call-24:0x340;a<q;a+=2)
                        if(wk_h(i,a)==(0xa800|from<<8|offset/4) && !(offset&3))address=1;
                }
            }
            if(size&&address)return 1;
        }
    }
    return 0;
}
static int wk_early(const struct iboot64_img *i,size_t p,struct wk_plan *out) {
    if(p>i->len || i->len-p<20 || wk_h(i,p)!=0xf89d || p<0x360 || !wk_call(i,p-6))return 0;
    unsigned load=wk_h(i,p+2),byte=load>>12,offset=load&4095;
    if(byte>7 || (wk_h(i,p-2)&0xfd07)!=0xb900 || wk_h(i,p+4)!=(0x2800|byte<<8) ||
       (wk_h(i,p+6)&0xff00)!=0xd000)return 0;
    int address=0,length=0;
    for(size_t q=p-18;q<p-6;q+=2) {
        unsigned h=wk_h(i,q);
        address|=(h&0xff00)==0xa800 && (h&255)*4==offset;
        length|=h==0x2101;
    }
    if(!address || !length)return 0;
    unsigned base;uint32_t constant;
    if(!wk_mov(i,p+8,&base,&constant) || constant!=0x1000000)return 0;
    size_t add=p+12;unsigned h=wk_h(i,add),l=wk_h(i,add+2),reg=(l>>8)&15;
    int original=(h&0xfff0)==0xeb00 && !(l&0x8030) &&
        (((l>>12)&7)*4+((l>>6)&3))==21 && (l&15)==byte && (h&15)==base && reg<13;
    if(!original) {
        if(!wk_mov(i,add,&reg,&constant) || constant)return 0;
    }
    unsigned branch=wk_h(i,p+6);
    size_t fallback=p+10+(branch&255)*2;
    unsigned fallback_reg;uint32_t value;
    if(fallback<=add+4 || fallback+10>i->len || fallback>p+48 ||
       !wk_mov(i,fallback,&fallback_reg,&value) || fallback_reg!=reg ||
       value!=(original?0x21000000:0))return 0;
    size_t join=fallback+4;
    unsigned literal=wk_h(i,join),store=wk_h(i,join+2),target=(literal>>8)&7;
    if((literal&0xf800)!=0x4800 || (store&0xffc0)!=0x6000 ||
       (store&7)!=reg || ((store>>3)&7)!=target)return 0;
    size_t slot=((join+4)&~(size_t)3)+(literal&255)*4;
    if(slot>i->len || i->len-slot<4 || wk_w(i,slot)<i->base ||
       wk_w(i,slot)-i->base>i->len+16*1024*1024)return 0;
    *out=(struct wk_plan){{add,fallback},2,reg};return 1;
}
static int wk_insert(const struct iboot64_img *i,size_t p,struct wk_plan *out) {
    unsigned h=wk_h(i,p),l=wk_h(i,p+2),source=h&15,reg=(l>>8)&15;
    if((h&0xfff0)!=0xf360 || (l&0x8020) ||
       (((l>>12)&7)*4+((l>>6)&3))!=21 || (l&31)!=28 || source<4 || source>11 || reg>7)
        return 0;
    int base=0;
    for(size_t q=p>16?p-16:0x340;q+2<=p;q+=2)base|=wk_literal(i,q,reg,0x1fffff);
    if(!base || !wk_entropy_register(i,p,source))return 0;
    for(size_t add=p+4;add+4<=i->len && add<=p+16;add+=2) {
        unsigned a=wk_h(i,add),b=wk_h(i,add+2);
        if((a&0xfbff)!=(0xf100|reg) || ((b>>8)&15)!=reg || (b&0x8000) ||
           wk_expand(((a>>10)&1)<<11|((b>>12)&7)<<8|(b&255))!=0x1000000)continue;
        for(size_t end=add+4;end+4<=i->len && end<=add+16;end+=2) {
            unsigned x=wk_h(i,end),y=wk_h(i,end+2),mask=y&15,outreg=(y>>8)&15;
            int original=x==(0xea00|reg) && !(y&0xf0f0) && outreg>=4 && outreg<=11;
            if(!original) {
                uint32_t value;
                if(!wk_mov(i,end,&outreg,&value) || value || outreg<4 || outreg>11)continue;
            }
            int matched_mask=0;
            for(size_t q=p+4;q+2<=add;q+=2)
                for(unsigned r=0;r<8;r++)
                    if((!original || r==mask) && wk_literal(i,q,r,0x3fe00000))matched_mask=1;
            if(!matched_mask || !wk_store(i,end+4,outreg))continue;
            *out=(struct wk_plan){{end,0},1,outreg};return 1;
        }
    }
    return 0;
}
static int wk_debug(const struct iboot64_img *i,size_t p,struct wk_plan *out) {
    unsigned base;uint32_t value;
    if(!wk_mov(i,p,&base,&value) || value!=0x1000000 || p+8>i->len)return 0;
    const unsigned char *bytes=i->buf;
    const unsigned char *off=memmem(bytes,i->len,"kaslr-off",10);
    const unsigned char *slide=memmem(bytes,i->len,"kaslr-slide",12);
    if(!off || !slide)return 0;
    int off_ref=0,slide_ref=0;
    for(size_t q=p>256?p-256:0x340;q+2<=p;q+=2) {
        int is_off=wk_literal(i,q,0,(uint32_t)(i->base+(off-bytes)));
        int is_slide=wk_literal(i,q,0,(uint32_t)(i->base+(slide-bytes)));
        if(!is_off && !is_slide)continue;
        for(size_t c=q+2;c+4<=p && c<=q+12;c+=2)
            if(wk_call(i,c)) { off_ref|=is_off;slide_ref|=is_slide;break; }
    }
    if(!off_ref || !slide_ref)return 0;
    size_t add=p+4;unsigned h=wk_h(i,add),l=wk_h(i,add+2),reg=(l>>8)&15,byte=l&15;
    int original=(h&0xfff0)==0xeb00 && !(l&0x8030) &&
        (((l>>12)&7)*4+((l>>6)&3))==21 && (h&15)==base && byte<8 && reg<13;
    if(!original) {
        if(!wk_mov(i,add,&reg,&value) || value)return 0;
        byte=0; /* The preserved test below identifies the byte register. */
    }
    for(size_t fallback=add+4;fallback+8<=i->len && fallback<=add+16;fallback+=2) {
        unsigned r;uint32_t v;
        if(!wk_mov(i,fallback,&r,&v) || r!=reg || v!=(original?0x21000000:0))continue;
        int control=0;
        if(fallback==add+8 && wk_h(i,add+6)==0xbf08) {
            unsigned cmp=wk_h(i,add+4);
            if((cmp&0xf8ff)==0x2800 && (!original || ((cmp>>8)&7)==byte))control=1;
        }
        for(size_t branch=p>=12?p-12:0x340;branch+2<=p;branch+=2) {
            unsigned cond=wk_h(i,branch);
            if((cond&0xff00)==0xd000 && branch+4+(cond&255)*2==fallback &&
               (wk_h(i,add+4)&0xf800)==0xe000)control=1;
        }
        if(!control)continue;
        int consumed=wk_store(i,fallback+4,reg);
        unsigned literal=wk_h(i,fallback+4),store=wk_h(i,fallback+6);
        if((literal&0xf800)==0x4800 && (store&0xffc0)==0x6000 &&
           (store&7)==reg && ((store>>3)&7)==((literal>>8)&7))consumed=1;
        if(!consumed)continue;
        *out=(struct wk_plan){{add,fallback},2,reg};return 1;
    }
    return 0;
}
int watch_disable_kaslr(struct iboot64_img *i) {
    if(!i || !i->buf || i->len<0x400 || i->len>16*1024*1024 ||
       wk_w(i,0)!=0xea00000e || i->base>UINT32_MAX ||
       !memmem(i->buf,i->len,"__PAGEZERO",10) || !memmem(i->buf,i->len,"__TEXT",6))return -1;
    struct wk_plan selected={{0,0},0,0};
    for(size_t p=0x354;p+4<=i->len;p+=2) {
        struct wk_plan found;
        if(!wk_classic(i,p,&found) && !wk_insert(i,p,&found) && !wk_early(i,p,&found) && !wk_debug(i,p,&found))continue;
        if(selected.count && (selected.count!=found.count || selected.reg!=found.reg ||
           selected.sites[0]!=found.sites[0] || selected.sites[1]!=found.sites[1])) {
            fputs("[!] Ambiguous Thumb kernel-slide calculation; no changes made\n",stderr);return -1;
        }
        selected=found;
    }
    if(!selected.count) {
        fputs("[!] Could not validate Thumb kernel-slide calculation; no changes made\n",stderr);return -1;
    }
    unsigned changed=0;
    for(unsigned n=0;n<selected.count;n++) {
        size_t p=selected.sites[n];
        if(wk_zero(i,p,selected.reg))continue;
        unsigned char *b=i->buf;b[p]=0x4f;b[p+1]=0xf0;b[p+2]=0;b[p+3]=selected.reg;
        changed++;
    }
    printf("[+] Thumb KASLR virtual slide forced to zero (%u site%s)%s\n",
           selected.count,selected.count==1?"":"s",changed?"":"; already disabled");
    return 0;
}
