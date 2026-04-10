/**
 * @file ax_sssEngine_rand.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2018,2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Engine for NXP Embedded Secure Element over SSS API's
 *
 * The following operations are supported by this engine:
 * - Random number generation
 * - ECC sign
 * - ECC verify
 * - ECDH compute_key
 *
 * When dealing with an EC key argument whose a public key is used:
 * - In case the key is a 'reference key' -> use the referenced public key
 * - In case the above does not apply; at compile time one can choose between two
 *   strategies:
 *   (1) return a fail
 *   (2) delegate the operation to the OpenSSL SW implementation
 *
 * When dealing with an EC key argument whose private key is used:
 * - In case the key is a 'reference key' -> use the referenced private key
 * - In case the above does not apply; at compile time one can choose between two
 *   strategies:
 *   (1) return a fail
 *   (2) delegate the operation to the OpenSSL SW implementation
 *
 * @note
 *   Compatible with:
 *   - OpenSSL 1.0.2
 *   - OpenSSL 1.1.0
 *
 */

/*
 * This file contains source code form OpenSSL distribution that is covered
 * by the LICENSE-OpenSSL file to be found in the root of this source code
 * distribution tree.
 */

#include <ex_sss.h>
#include <stdlib.h>
//#include <malloc.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "ax_api.h"
#include "ax_embSeEngine.h"
#include "ax_embSeEngine_Internal.h"
#include "sm_printf.h"

#ifdef AX_ENGINE_SUPPORTS_RAND

#if SSS_HAVE_APPLET_SE05X_IOT
#define MAX_RND_CHUNK SE05X_MAX_BUF_SIZE_RSP
#elif (SSS_HAVE_HOSTCRYPTO_MBEDTLS || SSS_HAVE_HOSTCRYPTO_OPENSSL)
#define MAX_RND_CHUNK 256
#else
#error "Invalid Platform for openssl engine random generator"
#endif

/* Random Num Status, used when Get Rand Status is invoked */
unsigned short gRandStatus = 1;

/**
 * Implementation of Engine API for Random Number Generation. Invokes Host API RND_GetRandom
 * @param[in,out] buf   buffer to store the generated Random Number
 * @param[in]     num   number of random bytes requested
 * @retval  0 upon failure
 * @retval  1 upon success
 */
static int EmbSe_Rand(unsigned char *buf, int num)
{
    int ret = 0;
    int requested = 0;
    int offset = 0;
    int chunk = 0;
    sss_status_t status = kStatus_SSS_Fail;
    sss_rng_context_t rng;

    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Rand invoked requesting %d random bytes\n", num);
    EMBSE_ENSURE_OR_GO_EXIT(num > 0);
    memset(buf, 0, num);

    status = sss_rng_context_init(&rng, &gpCtx->session /* Session */);
    EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    requested = num;
    while (requested > 0) {
        if (requested > MAX_RND_CHUNK) {
            chunk = MAX_RND_CHUNK;
        }
        else {
            chunk = requested;
        }

        status = sss_rng_get_random(&rng, buf + offset, chunk);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        offset += chunk;
        requested -= chunk;
    }

    ret = 1;
exit:
    gRandStatus = ret;
    if (ret == 0) {
        EmbSe_Print(LOG_ERR_ON, "Call to sss_rng_get_random failed \n");
    }
    return ret;
}

/**
* @function EmbSe_Rand_Status
* @description Engine API to return the status from invocation of RND_GetRandom()
* @param void
* @return value U16 of previous RND_GetRandom() API.
*/
static int EmbSe_Rand_Status(void)
{
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Rand_Status invoked\n");
    return (int)gRandStatus;
}

/* Fill in implemented Engine methods in respective data structures */
RAND_METHOD EmbSe_RAND = {
    NULL,             /* RAND_seed() */
    EmbSe_Rand,       /* RAND_bytes() */
    NULL,             /* RAND_cleanup() */
    NULL,             /* RAND_add() */
    EmbSe_Rand,       /* RAND_pseudo_rand() */
    EmbSe_Rand_Status /* RAND_status() */
};

#endif //AX_ENGINE_SUPPORTS_RAND
