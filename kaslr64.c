/* ARM64 kernel-slide discovery, GPL-3.0-or-later. Preserve load geometry. */
#include "kaslr64.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define K64_NONE SIZE_MAX
static uint32_t k64_word(const struct iboot64_img *image, size_t p) {
    if (p > image->len || image->len - p < 4) return 0;
    const uint8_t *b = image->buf;
    return (uint32_t)b[p] | (uint32_t)b[p+1]<<8 | (uint32_t)b[p+2]<<16 | (uint32_t)b[p+3]<<24;
}
static int k64_string(const struct iboot64_img *image, const char *text) {
    size_t length = strlen(text)+1;
    if (length > image->len) return 0;
    for (size_t p=0; p<=image->len-length; ++p)
        if (!memcmp((uint8_t *)image->buf+p,text,length)) return 1;
    return 0;
}
static int k64_and(uint32_t op, unsigned *rd,unsigned *rn,uint64_t *value);
static int k64_mov(uint32_t op, unsigned *reg, uint64_t *value) {
    if ((op&0x7f8003e0)==0x320003e0) {
        unsigned ignored;
        return k64_and(op&~0x600003e0u,reg,&ignored,value);
    }
    if ((op&0x7f800000) != 0x52800000) return 0;
    unsigned shift=((op>>21)&3)*16;
    if (!(op>>31) && shift>=32) return 0;
    *reg=op&31; *value=(uint64_t)((op>>5)&0xffff)<<shift;
    return *reg!=31;
}
static int k64_add(uint32_t op, unsigned *rd,unsigned *rn,unsigned *rm,unsigned *shift) {
    if ((op&0x7f200000)!=0x0b000000 || ((op>>22)&3)) return 0;
    *rd=op&31; *rn=(op>>5)&31; *rm=(op>>16)&31; *shift=(op>>10)&63;
    return *rd!=31 && *rn!=31 && *rm!=31;
}
static int k64_and(uint32_t op, unsigned *rd,unsigned *rn,uint64_t *value) {
    if ((op&0x7f800000)!=0x12000000) return 0;
    unsigned bits=op>>31?64:32, n=(op>>22)&1, s=(op>>10)&63,r=(op>>16)&63;
    unsigned selector=(n<<6)|((~s)&63),len=0;
    while (selector>>1) { selector>>=1; ++len; }
    if (!selector || len<1 || len>6 || (bits==32 && (n || len>5))) return 0;
    unsigned levels=(1u<<len)-1; s&=levels; r&=levels;
    if (s==levels) return 0;
    unsigned width=1u<<len;
    uint64_t mask=width==64?UINT64_MAX:((UINT64_C(1)<<width)-1);
    uint64_t element=s==63?UINT64_MAX:((UINT64_C(1)<<(s+1))-1);
    if (r) element=((element>>r)|(element<<(width-r)))&mask;
    uint64_t result=0;
    for (unsigned p=0;p<bits;p+=width) result|=element<<p;
    *rd=op&31;*rn=(op>>5)&31;*value=result;
    return *rd!=31 && *rn!=31;
}
static int k64_load_stack(uint32_t op,unsigned reg,int byte) {
    unsigned base=(op>>5)&31;
    if ((op&31)!=reg || (base!=31 && base!=29)) return 0;
    if (byte) return (op&0xffc00000)==0x39400000 || (op&0xffe00c00)==0x38400000;
    return (op&0xffc00000)==0xf9400000 || (op&0xffe00c00)==0xf8400000;
}
static int k64_output_use(const struct iboot64_img *image,size_t p,unsigned reg) {
    uint32_t tracked=1u<<reg;
    for (size_t q=p+4;q+4<=image->len && q-p<=96;q+=4) {
        uint32_t op=k64_word(image,q);
        /* Accept the loader's X7 argument or persistent slide, not stack scratch. */
        if ((op&0xffe0ffe0)==0xaa0003e0 && (tracked&(1u<<((op>>16)&31)))) {
            if((op&31)==7) return 1;
            tracked|=1u<<(op&31);
        }
        unsigned rd,rn,rm,shift;
        if(k64_add(op,&rd,&rn,&rm,&shift) && !shift &&
           ((tracked&(1u<<rn)) || (tracked&(1u<<rm)))) tracked|=1u<<rd;
        if ((op&0xbfc00000)==0xb9000000 && (tracked&(1u<<(op&31))) &&
            ((((op>>5)&31)!=31 && ((op>>5)&31)!=29) || q==p+4)) return 1;
        if ((op&0x7c000000)==0x14000000) break;
    }
    return 0;
}
struct k64_expr { unsigned type, byte; uint64_t value; };
static int k64_classic(const struct iboot64_img *image,size_t p,unsigned *reg) {
    uint32_t terminal=k64_word(image,p); unsigned dst=terminal&31;
    int csel=(terminal&0x7fe00c00)==0x1a800000 && ((terminal>>12)&15)==0;
    unsigned already_reg;uint64_t already_value;
    int already=k64_mov(terminal,&already_reg,&already_value) && (!already_value || already_value==0x1000000);
    if ((!csel && !already) || dst==31 || p<0x360) return 0;
    struct k64_expr state[32]={{0}};
    unsigned comparison=32;
    size_t start=p>48?p-48:0x340;
    if(start<0x340) start=0x340;
    for(size_t q=start;q<p;q+=4) {
        uint32_t op=k64_word(image,q);unsigned rd,rn,rm,shift;uint64_t value;
        if(k64_mov(op,&rd,&value)) state[rd]=(struct k64_expr){1,0,value};
        else if(k64_load_stack(op,op&31,1))
            state[op&31]=(struct k64_expr){2,op&31,0};
        else if(k64_add(op,&rd,&rn,&rm,&shift) && shift==21 &&
                state[rn].type==1 && state[rn].value==0x1000000 && state[rm].type==2)
            state[rd]=(struct k64_expr){3,state[rm].byte,0};
        else if((op&0x7ffffc1f)==0x7100001f) {
            unsigned compared=(op>>5)&31;
            comparison=state[compared].type==2?state[compared].byte:32;
        }
        else if(op!=0xd503201f) {
            /* Discard register values outside the matched expression. */
            if((op&0x7c000000)==0x14000000) memset(state,0,sizeof(state));
            else state[op&31]=(struct k64_expr){0};
            comparison=32;
        }
    }
    if(comparison==32) return 0;
    int expression=0;
    if(csel) {
        unsigned a=(terminal>>5)&31,b=(terminal>>16)&31;
        expression=(state[a].type==1 && (state[a].value==0x21000000 || state[a].value==0x1000000) &&
                    state[b].type==3 && state[b].byte==comparison);
    } else {
        int fallback=0,biased=0;
        for(unsigned n=0;n<31;++n) {
            fallback|=state[n].type==1 && (state[n].value==0x21000000 || state[n].value==0x1000000);
            biased|=state[n].type==3 && state[n].byte==comparison;
        }
        expression=fallback && biased;
    }
    if(!expression || !k64_output_use(image,p,dst)) return 0;
    *reg=dst;
    for(unsigned n=0;n<31;++n)
        if(state[n].type==1 && state[n].value==0x21000000) return 1;
    return 3; /* Keep the later loader's required 16 MiB minimum bias. */
}
static int k64_masked_classic(const struct iboot64_img *image,size_t p,unsigned *reg) {
    if(p<0x370 || image->len-p<12) return 0;
    uint32_t terminal=k64_word(image,p);unsigned dst=terminal&31;
    int csel=(terminal&0x7fe00c00)==0x1a800000 && ((terminal>>12)&15)==0;
    unsigned already_reg;uint64_t already_value;
    int already=k64_mov(terminal,&already_reg,&already_value) && !already_value;
    if((!csel && !already) || dst==31) return 0;
    unsigned masked,entropy;uint64_t mask;
    if(!k64_and(k64_word(image,p-12),&masked,&entropy,&mask) || mask!=0x1fe00000 ||
       !k64_load_stack(k64_word(image,p-16),entropy,0)) return 0;
    uint32_t tst=k64_word(image,p-8);unsigned ignored,used;uint64_t testmask;
    if((tst&0x7f80001f)!=0x7200001f ||
       !k64_and(tst&~0x6000001fu,&ignored,&used,&testmask) || used!=entropy || testmask!=mask) return 0;
    unsigned fallback;uint64_t bias;
    if(!k64_mov(k64_word(image,p-4),&fallback,&bias) || bias!=0x20000000 ||
       (csel && (((terminal>>5)&31)!=fallback || ((terminal>>16)&31)!=masked))) return 0;
    unsigned physical,virtual_;uint64_t congruence;
    if(!(k64_and(k64_word(image,p+4),&physical,&virtual_,&congruence) &&
          virtual_==dst && congruence==0x1e00000) && !k64_output_use(image,p,dst)) return 0;
    if((k64_word(image,p-20)&0xfc000000)!=0x94000000) return 0;
    unsigned size_reg;uint64_t size;
    if(!k64_mov(k64_word(image,p-24),&size_reg,&size) || size_reg!=1 || size!=8) return 0;
    *reg=dst;return 1;
}
static int k64_shifted_minimum(const struct iboot64_img *image,size_t p,unsigned *reg) {
    if(p<0x3c0 || image->len-p<96) return 0;
    unsigned rd,rn;uint64_t mask;uint32_t op=k64_word(image,p);
    int masked=k64_and(op,&rd,&rn,&mask) && (op>>31) && mask==0x1fe00000;
    if(!masked) {
        uint64_t zero;
        if(!k64_mov(op,&rd,&zero) || zero) return 0;
        rn=rd;
    }
    uint32_t shift=k64_word(image,p-4);
    if((shift&0xfffffc1f)!=(0x530b2800u|rn)) return 0;
    unsigned entropy=(shift>>5)&31;
    if(entropy<19 || entropy>28) return 0;
    unsigned sum,a,b,distance;
    if(!k64_add(k64_word(image,p+4),&sum,&a,&b,&distance) || distance ||
       !((a==rd && b!=rd) || (b==rd && a!=rd))) return 0;
    unsigned biasreg;uint64_t bias;
    if(!k64_mov(k64_word(image,p+8),&biasreg,&bias) || bias!=0x1000000) return 0;
    unsigned dest,left,right,amount;
    if(!k64_add(k64_word(image,p+12),&dest,&left,&right,&amount) || amount || dest!=sum ||
       !((left==sum && right==biasreg) || (right==sum && left==biasreg))) return 0;
    size_t load=K64_NONE;
    for(size_t q=p-8;q>=0x340 && p-q<=112;q-=4) {
        uint32_t w=k64_word(image,q);
        unsigned base=(w>>5)&31;
        if((w&31)==entropy && (base==31 || base==29) &&
           ((w&0xffc00000)==0xb9400000 || (w&0xffe00c00)==0xb8400000)) {load=q;break;}
        if((w&0x7c000000)==0x14000000 || (w&0xff000010)==0x54000000 ||
           (w&0x7e000000)==0x34000000 || (w&0x7e000000)==0x36000000) continue;
        if((w&31)==entropy) return 0;
    }
    if(load==K64_NONE || (k64_word(image,load-4)&0xfc000000)!=0x94000000) return 0;
    unsigned sizearg;uint64_t size;
    if(!k64_mov(k64_word(image,load-8),&sizearg,&size) || sizearg!=1 || size!=8) return 0;
    int low=0,sub=0,edge=0;
    for(size_t q=p+16;q<=p+64;q+=4) {
        uint32_t w=k64_word(image,q);unsigned x,y;uint64_t v;
        if(k64_and(w,&x,&y,&v) && v==0x1fffff) low=1;
        if((w&0xffe0fc00)==0xeb000000) sub=1;
        if((w&0xff00001f)==0x54000009) edge=1;
    }
    if(!low || !sub || !edge) return 0;
    *reg=rd;return 2;
}
static int k64_modern(const struct iboot64_img *image,size_t p,unsigned *reg) {
    if(p<0x370 || image->len-p<64) return 0;
    uint32_t op=k64_word(image,p);unsigned rd,rn;uint64_t mask;
    int masked=k64_and(op,&rd,&rn,&mask) && (op>>31) && mask==0x1fffc000 && rd==rn;
    uint64_t value;unsigned already;
    if(!masked) {
        if(!k64_mov(op,&already,&value) || value) return 0;
        rd=rn=already;
    }
    size_t entropy_load=K64_NONE;
    for(size_t q=p-4;q>=0x340 && p-q<=96;q-=4) {
        uint32_t w=k64_word(image,q);
        if(k64_load_stack(w,rn,0)) {entropy_load=q;break;}
        if((w&0xfc000000)==0x94000000) break;
        if((w&0x7c000000)==0x14000000 || (w&0xff000010)==0x54000000 ||
           (w&0x7e000000)==0x34000000 || (w&0x7e000000)==0x36000000) continue;
        if((w&31)==rn) break;
    }
    if(entropy_load==K64_NONE) return 0;
    size_t call=K64_NONE;
    for(size_t q=entropy_load-4;q>=entropy_load-24;q-=4) {
        if((k64_word(image,q)&0xfc000000)==0x94000000) {call=q;break;}
    }
    if(call==K64_NONE) return 0;
    int eight=0;
    for(size_t q=call-4;q>=call-24;q-=4) {
        unsigned arg;uint64_t size;
        if(k64_mov(k64_word(image,q),&arg,&size) && size==8 && (arg==1 || arg==4)) eight=1;
    }
    if(!eight) return 0;
    unsigned virt,a,b,shift;
    if(!k64_add(k64_word(image,p+4),&virt,&a,&b,&shift) || shift ||
       !((a==rd && b!=rd) || (b==rd && a!=rd))) return 0;
    size_t low=K64_NONE;unsigned lowreg=0;
    for(size_t q=p+8;q<=p+40;q+=4) {
        unsigned x,y;uint64_t limit;
        if(k64_and(k64_word(image,q),&x,&y,&limit) && y==virt &&
           (limit==0x1ffffff || limit==0x1ffc000 || limit==0x1fffffe)) {low=q;lowreg=x;break;}
    }
    if(low==K64_NONE) return 0;
    int subtraction=0,lower_edge=0,virt_correction=0;
    for(size_t q=low+4;q<=low+48 && q+4<=image->len;q+=4) {
        uint32_t x=k64_word(image,q);
        if((x&0xffe0fc00)==0xeb000000 && ((x>>16)&31)==lowreg) subtraction=1;
        if((x&0xff00001f)==0x54000009) lower_edge=1; /* B.LS */
        if((x&0xffe0fc00)==0xab000000 && (x&31)==virt &&
           (((x>>5)&31)==virt || ((x>>16)&31)==virt)) virt_correction=1;
        /* Older compilers use ADD/CMP/B.LS/MOV for the overflow correction. */
        unsigned sum,left,right,distance;
        if(k64_add(x,&sum,&left,&right,&distance) && !distance &&
           (left==virt || right==virt) && q+16<=image->len &&
           k64_word(image,q+4)==(0xeb00001fu|(virt<<16)|(sum<<5)) &&
           (k64_word(image,q+8)&0xff00001f)==0x54000009 &&
           k64_word(image,q+12)==(0xaa0003e0u|(sum<<16)|virt)) virt_correction=1;
    }
    if(!virt_correction) {
        for(size_t q=low+4;q<=low+36 && q+24<=image->len;q+=4) {
            unsigned sum,left,right,distance;
            if(!k64_add(k64_word(image,q),&sum,&left,&right,&distance) || distance ||
               (left!=virt && right!=virt)) continue;
            int compare=0,move=0,edge=0;
            for(size_t r=q+4;r<=q+24;r+=4) {
                uint32_t w=k64_word(image,r);
                if(w==(0xeb00001fu|(virt<<16)|(sum<<5))) compare=1;
                else if(w==(0xaa0003e0u|(sum<<16)|virt)) move=1;
                else if((w&0xff000010)==0x54000000 && ((w&15)==8 || (w&15)==9)) edge=1;
                else if((w&0xffe0ffe0)==0xaa0003e0 && (w&31)!=sum && (w&31)!=virt) {}
                else break;
                if(compare && edge && (move || sum!=virt)) {virt_correction=1;break;}
            }
        }
    }
    if(!subtraction || !lower_edge || !virt_correction) return 0;
    *reg=rd;return 2;
}
int arm64_disable_kaslr(struct iboot64_img *image) {
    if(!image || !image->buf || image->len<0x380 || image->len>16*1024*1024 ||
       !k64_string(image,"__PAGEZERO")) {
        fputs("[!] KASLR requires a supported ARM64 kernel-loading image\n",stderr);return -1;
    }
    size_t selected=K64_NONE;unsigned selected_reg=0;int family=0;
    for(size_t p=0x340;p+64<=image->len;p+=4) {
        unsigned reg;int kind=k64_classic(image,p,&reg);
        if(!kind) kind=k64_masked_classic(image,p,&reg)?1:k64_modern(image,p,&reg);
        if(!kind) kind=k64_shifted_minimum(image,p,&reg);
        if(!kind) continue;
        if(selected!=K64_NONE && selected!=p) {
            fputs("[!] Ambiguous ARM64 kernel-slide selection; no changes made\n",stderr);return -1;
        }
        selected=p;selected_reg=reg;family=kind;
    }
    if(selected==K64_NONE) {
        fputs("[!] Could not validate ARM64 kernel-slide selection; no changes made\n",stderr);return -1;
    }
    uint32_t before=k64_word(image,selected),replacement=(family==3?0xd2a02000u:0xd2800000u)|selected_reg;
    /* MOV Xn,#0 also clears the corresponding Wn result of old loaders. */
    uint8_t *b=image->buf;
    for(unsigned n=0;n<4;++n)b[selected+n]=(uint8_t)(replacement>>(n*8));
    printf("[+] ARM64 KASLR %s at 0x%zx (%08x -> %08x)%s\n",
           family==1?"virtual slide disabled":"entropy disabled; required bias/alignment retained",
           selected,before,replacement,before==replacement?" already disabled":"");
    return 0;
}
