/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sss_psa_alt.h"

#include <nxLog_App.h>

#include "ex_sss_ports.h"
#include "ex_sss_boot.h"
#include "nxEnsure.h"

ex_sss_boot_ctx_t gPsaAltBootCtx;

/* Session Open from driver->p_init API */
sss_status_t sss_psa_alt_session_open()
{
    sss_status_t status = kStatus_SSS_Fail;
    char *portName;

    status = ex_sss_boot_connectstring(0, NULL, &portName);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    ex_sss_session_close(&gPsaAltBootCtx);

    status = ex_sss_boot_open(&gPsaAltBootCtx, portName);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

#if EX_SSS_BOOT_DO_ERASE
    status = ex_sss_boot_factory_reset(&gPsaAltBootCtx);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
#endif

    status = ex_sss_key_store_and_object_init(&gPsaAltBootCtx);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

exit:
#if defined(_MSC_VER)
    if (portName) {
        char *dummy_portName = NULL;
        size_t dummy_sz      = 0;
        _dupenv_s(&dummy_portName, &dummy_sz, EX_SSS_BOOT_SSS_PORT);
        if (NULL != dummy_portName) {
            free(dummy_portName);
            free(portName);
        }
    }
#endif // _MSC_VER
    return status;
}

sss_status_t sss_psa_alt_allocate_key()
{
    sss_status_t status = kStatus_SSS_Success;
    LOG_I("Allocating Key");
    return status;
}

sss_status_t sss_psa_alt_generate_key(
    uint32_t keyId, size_t keyBitLen, sss_key_part_t keyPart, sss_cipher_type_t cipherType)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(&sss_object, keyId, keyPart, cipherType, 0, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_store_generate_key(&gPsaAltBootCtx.ks, &sss_object, keyBitLen, NULL);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

sss_status_t sss_psa_alt_export_key(uint32_t keyId, uint8_t *data, size_t bufferLen, size_t *dataLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    *dataLen                = bufferLen;

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&sss_object, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_store_get_key(&gPsaAltBootCtx.ks, &sss_object, data, dataLen, dataLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

sss_status_t sss_psa_alt_destroy_key(uint32_t keyId)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&sss_object, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_store_erase_key(&gPsaAltBootCtx.ks, &sss_object);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

sss_status_t sss_psa_alt_import_key(uint32_t keyId,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(&sss_object, keyId, keyPart, cipherType, 0, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_store_set_key(&gPsaAltBootCtx.ks, &sss_object, data, dataLen, keyBitLen, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

sss_status_t sss_psa_alt_asymmetric_sign_digest(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    uint8_t *digest,
    size_t digestLen,
    uint8_t *signature,
    size_t *signatureLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_asymmetric_t asymm_ctx;

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&sss_object, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status =
        sss_asymmetric_context_init(&asymm_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, kMode_SSS_Sign);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_asymmetric_sign_digest(&asymm_ctx, digest, digestLen, signature, signatureLen);
    sss_asymmetric_context_free(&asymm_ctx);

exit:
    return status;
}

sss_status_t sss_psa_alt_asymmetric_verify_digest(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    uint8_t *digest,
    size_t digestLen,
    uint8_t *signature,
    size_t signatureLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_asymmetric_t asymm_ctx;

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&sss_object, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status =
        sss_asymmetric_context_init(&asymm_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, kMode_SSS_Sign);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_asymmetric_verify_digest(&asymm_ctx, digest, digestLen, signature, signatureLen);
    sss_asymmetric_context_free(&asymm_ctx);

exit:
    return status;
}

sss_status_t sss_psa_alt_asymmetric_encrypt(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    const uint8_t *input,
    size_t inputLen,
    uint8_t *output,
    size_t *outputLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_asymmetric_t asymm_ctx;

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&sss_object, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status =
        sss_asymmetric_context_init(&asymm_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, kMode_SSS_Sign);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_asymmetric_encrypt(&asymm_ctx, input, inputLen, output, outputLen);
    sss_asymmetric_context_free(&asymm_ctx);

exit:
    return status;
}

sss_status_t sss_psa_alt_asymmetric_decrypt(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    const uint8_t *input,
    size_t inputLen,
    uint8_t *output,
    size_t *outputLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_asymmetric_t asymm_ctx;

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&sss_object, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status =
        sss_asymmetric_context_init(&asymm_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, kMode_SSS_Sign);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_asymmetric_decrypt(&asymm_ctx, input, inputLen, output, outputLen);
    sss_asymmetric_context_free(&asymm_ctx);

exit:
    return status;
}
