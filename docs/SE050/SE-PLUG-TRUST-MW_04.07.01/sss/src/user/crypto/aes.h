#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>
#include <stdlib.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_USER

#include <fsl_sss_types.h>

#define AES_BLOCKSIZE 16

typedef struct
{
    uint8_t state[4][4];
    int rounds;
    int keylen;
    uint8_t roundkey[(10 + 1) * AES_BLOCKSIZE]; //allocate memory at runtime according to keysize
} aes_ctx_t;

void AES_user_encrypt(aes_ctx_t *ctx, uint8_t *in, uint8_t *out);

void AES_user_decrypt(aes_ctx_t *ctx, uint8_t *in, uint8_t *out);

aes_ctx_t *AES_ctx_alloc(uint8_t *key, size_t keylen);
#endif // SSS_HAVE_HOSTCRYPTO_USER
#endif // __AES_H__