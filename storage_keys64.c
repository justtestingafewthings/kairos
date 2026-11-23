/* UID/AES locators adapted from QwQramdisk, under LICENSE.QwQramdisk. */
struct storage_edit { size_t off; uint32_t value; const char *name; };
static size_t storage_find(struct iboot64_img *i,const char *s,size_t length) {
    size_t found=SIZE_MAX;
    for(size_t p=0;length<=i->len && p<=i->len-length;p++) if(!memcmp((char *)i->buf+p,s,length)) {
        if(found!=SIZE_MAX) return SIZE_MAX;
        found=p;
    }
    return found;
}
static int storage_call(struct iboot64_img *i,size_t p) {
    return p<=i->len && i->len-p>=4 && (a64_word(i,p)&0xfc000000)==0x94000000;
}
static size_t storage_target(struct iboot64_img *i,size_t p) {
    if(!storage_call(i,p)) return SIZE_MAX;
    int64_t target=(int64_t)p+(int64_t)(int32_t)(a64_word(i,p)<<6)/16;
    return target>=0x340 && (uint64_t)target<i->len?(size_t)target:SIZE_MAX;
}
static size_t storage_capability(struct iboot64_img *i,const char *name) {
    size_t str=storage_find(i,name,strlen(name)+1),ref=SIZE_MAX;
    if(str==SIZE_MAX) return SIZE_MAX;
    for(size_t p=0x340;p+8<=i->len;p+=4) {
        unsigned reg;size_t addr,width;
        if(a64_address(i,p,&reg,&addr,&width) && addr==str) {
            if(ref!=SIZE_MAX) return SIZE_MAX;
            ref=p+width-4;
        }
    }
    if(ref==SIZE_MAX || ref>i->len || i->len-ref<0x40) return SIZE_MAX;
    size_t call=SIZE_MAX,count=0;
    for(size_t p=ref+4;p<ref+0x40;p+=4) if(storage_call(i,p)) { call=p;count++; }
    return count==2 && storage_target(i,call)!=SIZE_MAX?call:SIZE_MAX;
}
int storage_keys_patch64(struct iboot64_img *i) {
    static const char mask7[]="\x09\x00\x80\x12\x7f\x02\x00\x31\xc8\x12\x89\x1a\x1f\x00\x00\x31\x81\x12\x89\x1a\xe0\x03\x08\xaa";
    static const char mask8[]="\x7f\x02\x00\x71\x09\x00\x80\x12\x88\x12\x89\x1a\x1f\x00\x00\x71\xa1\x12\x89\x1a\xe0\x03\x08\xaa";
    static const char early8[]="\x68\x06\x40\xb9\xa8\x00\x98\x37\x01\x00\x80\x12\x00\x00\x80\x52";
    static const char early9[]="\xa8\x00\x90\x37\x00\x00\x80\x12\x01\x00\x80\x52";
    static const char gid9[]="\xe8\x03\x20\x2a\x13\x01\x00\x13\xe0\x03\x0d\x32";
    static const char uid9[]="\xe8\x03\x20\x2a\x01\x01\x00\x13\xe0\x03\x13\xaa";
    static const char bec9[]="\x7f\x02\x00\x71\x09\x00\x80\x12\xa8\x12\x89\x1a\x1f\x00\x00\x71\x81\x12\x89\x1a\xe0\x03\x08\xaa";
    struct storage_edit edits[12];size_t count=0,mask,writer=SIZE_MAX,disable=SIZE_MAX,gid_disable=SIZE_MAX;
    int ios7=i->VERS==1940,ios8=i->VERS==2261,ios9=i->VERS==2817;
    int bec=has_kernel_load_k(i);
#define EDIT(p,v,n) do { size_t at=(p);if(at==SIZE_MAX || at>i->len || i->len-at<4 || (at&3) || count>=12) return -1;edits[count++]=(struct storage_edit){at,v,n}; } while(0)
    if(!ios7 && !ios8 && !ios9) {
        if(i->VERS>=3406) { LOG("Legacy UID/AES adjustments do not apply to iBoot-%u\n",i->VERS);return 0; }
        WARN("Unrecognized iBoot generation for storage keys\n");return -1;
    }
    mask=storage_find(i,ios7?mask7:mask8,24);
    if(ios7 || ios8 || mask!=SIZE_MAX) {
        if(mask==SIZE_MAX) return -1;
        writer=mask+24;
        EDIT(mask+16,ios7?0x2a1403e1:0x2a1503e1,"Preserve bootx UID AES mask");
    } else if(!bec) {
        size_t gid=storage_find(i,gid9,12),uid=storage_find(i,uid9,12);
        if(gid==SIZE_MAX || uid!=gid+16) return -1;
        writer=uid+12;
        EDIT(gid+4,0x52800013,"Preserve bootx GID AES mask");
        EDIT(uid+4,0x52800001,"Preserve bootx UID AES mask");
    } else {
        mask=storage_find(i,bec9,24);if(mask==SIZE_MAX)return -1;writer=mask+24;
        EDIT(mask+8,0x52800008,"Preserve bootx GID AES mask");
        EDIT(mask+16,0x2a1403e1,"Preserve bootx UID AES mask");
    }
    if(!storage_call(i,writer) || storage_target(i,writer)==SIZE_MAX) return -1;
    if(ios9) {
        size_t early=storage_find(i,early9,12);if(early==SIZE_MAX) return -1;
        gid_disable=early+12;disable=early+32;
        if(!storage_call(i,gid_disable) || !storage_call(i,disable) ||
           storage_target(i,gid_disable)!=storage_target(i,disable)) return -1;
        if(mask==SIZE_MAX || !memcmp((char *)i->buf+mask,bec9,24)) {
            if(storage_target(i,writer)!=storage_target(i,gid_disable)) return -1;
            EDIT(gid_disable,0xd503201f,"Skip early GID AES disable");
        }
    } else {
        size_t early=storage_find(i,early8,16);if(early==SIZE_MAX)return -1;disable=early+16;
    }
    if(!storage_call(i,disable) || storage_target(i,disable)==SIZE_MAX) return -1;
    EDIT(disable,0xd503201f,"Skip early UID AES disable");
    if(bec) {
        size_t debug=storage_capability(i,"debug-enabled"),uid=storage_capability(i,"uid-aes-key");
        if(debug==SIZE_MAX || uid==SIZE_MAX || (a64_word(i,uid+4)&0x7e000000)!=0x34000000) return -1;
        EDIT(debug,0x52800020,"Accept debug capability");
        EDIT(uid+4,0xd503201f,"Publish uid-aes-key capability");
        if(ios7) {
            size_t trust=storage_capability(i,"system-trusted");
            if(trust==SIZE_MAX || (a64_word(i,trust+4)&0x7e000000)!=0x34000000) return -1;
            EDIT(trust+4,0xd503201f,"Publish system-trusted capability");
        }
    }
    for(size_t n=0;n<count;n++) {
        LOG("%s at 0x%zx\n",edits[n].name,edits[n].off);
        memcpy((char *)i->buf+edits[n].off,&edits[n].value,4);
    }
#undef EDIT
    return 0;
}
