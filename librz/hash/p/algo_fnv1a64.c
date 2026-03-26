#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#define OFF 0xcbf29ce484222325ULL
#define PRM 0x00000100000001b3ULL

typedef struct { ut64 h; } C;

static void *ctx_new(){ return RZ_NEW0(C); }
static void ctx_free(void *c){ free(c); }

static bool init(void *c){
 rz_return_val_if_fail(c,false);
 ((C*)c)->h = OFF;
 return true;
}

static bool update(void *c,const ut8*d,ut64 l){
 rz_return_val_if_fail(c&&d,false);
 C*x=c;
 for(ut64 i=0;i<l;i++){
  x->h ^= d[i];
  x->h *= PRM;
 }
 return true;
}

static bool final(void *c,ut8*out){
 rz_return_val_if_fail(c&&out,false);
 rz_write_le64(out,((C*)c)->h);
 return true;
}

RzHashPlugin rz_hash_plugin_fnv1a64 = {
 .name="fnv1a64",
 .license="LGPL3",
 .author="Ahmed Sami",
 .description="FNV1a 64bit",
 .support_hmac=false,
 .context_new=ctx_new,
 .context_free=ctx_free,
 .digest_size=NULL,
 .block_size=NULL,
 .init=init,
 .update=update,
 .final=final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
 .type = RZ_LIB_TYPE_HASH,
 .data = &rz_hash_plugin_fnv1a64,
 .version = RZ_VERSION
};
#endif
