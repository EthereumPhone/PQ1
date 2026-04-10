#ifndef __AES_CMAC_H__
#define __AES_CMAC_H__

#include <sm_types.h>

#include <string.h>
#include <stdlib.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_USER

void aes_cmac(uint8_t *input, unsigned long length, uint8_t *key, uint8_t *mac_value);
void gen_subkey(aes_ctx_t *aes_ctx, uint8_t *key, uint8_t *subkey_1, uint8_t *subkey_2);
void block_xor_triple(uint8_t *a, uint8_t *b, uint8_t *c);

#endif //#if SSS_HAVE_HOSTCRYPTO_USER
#endif
