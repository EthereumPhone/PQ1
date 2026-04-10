/* Copyright 2019,2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <se05x_const.h>
#include <string.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define I2C_SENSOR_BUS_ADDRESS 0x1D /* I2C bus address of sensor */
#define MAX_SIGNATURE_LEN 256
#define I2C_MAX_DATA 32
#define FXOS8700CQ_STATUS 0x00
#define FXOS8700CQ_WHOAMI 0x0D
#define FXOS8700CQ_XYZ_DATA_CFG 0x0E
#define FXOS8700CQ_CTRL_REG1 0x2A
#define FXOS8700CQ_WHOAMI_VAL 0xC7
#define ACCEL_READ_TIMES 100

/* ************************************************************************** */
/* Static Defines                                                              */
/* ************************************************************************** */
static ex_sss_boot_ctx_t gex_sss_boot_ctx;

/* Usage of pre-provisioned attestation key as per Variants */
#if SSS_HAVE_APPLET_SE05X_B && SSS_HAVE_SE05X_VER_03_XX
#define KEY_BIT_LEN 2048
#define ATTESTATION_KEY_ID 0xF0000010
#else
#define KEY_BIT_LEN 256
#define ATTESTATION_KEY_ID 0xF0000012
#endif

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

SE05x_I2CM_cmd_t TLV[5];
sss_object_t verification_object;

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>
/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

#if SSS_HAVE_SE05X_VER_GTE_07_02
extern int add_taglength_to_data(uint8_t **buf,
    size_t *bufLen,
    const size_t actualBufLen,
    SE05x_TAG_t tag,
    const uint8_t *cmd,
    size_t cmdLen,
    bool extendedLength);
#endif

#if SSS_HAVE_HOSTCRYPTO_ANY
static sss_status_t i2cm_ConfigureAttestation(ex_sss_boot_ctx_t *pCtx, sss_object_t *key)
{
    sss_status_t sss_status = kStatus_SSS_Success;
    // size_t keylen                    = KEY_BIT_LEN;
    uint32_t keyId = ATTESTATION_KEY_ID;

    uint8_t public_key[1024] = {0};
    size_t public_key_len    = sizeof(public_key);
    size_t keyBitLen         = KEY_BIT_LEN;

    sss_status = sss_key_object_init(key, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

    sss_status = sss_key_object_get_handle(key, keyId);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

    sss_status = sss_key_store_get_key(&pCtx->ks, key, public_key, &public_key_len, &keyBitLen);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    sss_status = sss_key_object_init(&verification_object, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    sss_status = sss_key_object_allocate_handle(&verification_object,
        __LINE__,
        kSSS_KeyPart_Public,
        (sss_cipher_type_t)key->cipherType,
        public_key_len,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    sss_status =
        sss_key_store_set_key(&pCtx->host_ks, &verification_object, public_key, public_key_len, keyBitLen, NULL, 0);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    return kStatus_SSS_Success;
cleanup:
    return kStatus_SSS_Fail;
}
#endif

#if SSS_HAVE_HOSTCRYPTO_ANY
static sss_status_t i2cm_VerifyAttestation(
    ex_sss_boot_ctx_t *pCtx, sss_se05x_attst_comp_data_t *attest_data, uint8_t *rspbuffer, size_t rspbufferLen)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
#if SSS_HAVE_APPLET_SE05X_B && SSS_HAVE_SE05X_VER_03_XX
    sss_algorithm_t algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
#else
    sss_algorithm_t algorithm = kAlgorithm_SSS_ECDSA_SHA512;
#endif
    sss_algorithm_t digest_algorithm = kAlgorithm_SSS_SHA512;
    sss_asymmetric_t asymm_ctx       = {0};
    sss_digest_t digest_ctx          = {0};
    uint8_t cmdHashed[64]            = {0};
    size_t cmdHashedLen              = sizeof(cmdHashed);
    uint8_t inputData[2500]          = {0};
    size_t inputDataLen              = 0;
    uint8_t *pInputData              = &inputData[0];
#if SSS_HAVE_SE05X_VER_GTE_07_02
    int tlvRet     = 0;
    size_t buffLen = sizeof(inputData);
#endif // SSS_HAVE_SE05X_VER_GTE_07_02

    sss_status = sss_digest_context_init(&digest_ctx, &pCtx->host_session, digest_algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

#if SSS_HAVE_SE05X_VER_GTE_07_02
    sss_status = sss_digest_one_go(&digest_ctx, attest_data->cmd, (attest_data->cmdLen), cmdHashed, &cmdHashedLen);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    memcpy(pInputData, cmdHashed, cmdHashedLen);
    pInputData += cmdHashedLen;
    inputDataLen += cmdHashedLen;

    tlvRet = add_taglength_to_data(&pInputData, &inputDataLen, buffLen, kSE05x_TAG_1, rspbuffer, rspbufferLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    tlvRet = add_taglength_to_data(
        &pInputData, &inputDataLen, buffLen, kSE05x_TAG_2, attest_data->chipId, attest_data->chipIdLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    tlvRet = add_taglength_to_data(
        &pInputData, &inputDataLen, buffLen, kSE05x_TAG_4, attest_data->objSize, attest_data->objSizeLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    tlvRet = add_taglength_to_data(&pInputData,
        &inputDataLen,
        buffLen,
        kSE05x_TAG_TIMESTAMP,
        attest_data->timeStamp.ts,
        attest_data->timeStampLen,
        true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
#else
    memcpy(pInputData, rspbuffer, rspbufferLen);
    pInputData += rspbufferLen;
    memcpy(pInputData, attest_data->timeStamp.ts, attest_data->timeStampLen);
    pInputData += attest_data->timeStampLen;
    memcpy(pInputData, attest_data->outrandom, attest_data->outrandomLen);
    pInputData += attest_data->outrandomLen;
    memcpy(pInputData, attest_data->chipId, attest_data->chipIdLen);
    pInputData += attest_data->chipIdLen;
    inputDataLen = rspbufferLen + attest_data->timeStampLen + attest_data->outrandomLen + attest_data->chipIdLen;
#endif

    sss_status = sss_digest_one_go(&digest_ctx, inputData, inputDataLen, cmdHashed, &cmdHashedLen);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    LOG_MAU8_D("Cmd Hashed ", cmdHashed, cmdHashedLen);
    sss_digest_context_free(&digest_ctx);

    sss_status =
        sss_asymmetric_context_init(&asymm_ctx, &pCtx->host_session, &verification_object, algorithm, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    sss_status = sss_asymmetric_verify_digest(
        &asymm_ctx, cmdHashed, cmdHashedLen, attest_data->signature, attest_data->signatureLen);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    return kStatus_SSS_Success;
cleanup:
    return kStatus_SSS_Fail;
}
#endif

static smStatus_t i2cm_AttestedWrite(ex_sss_boot_ctx_t *pCtx,
    uint8_t *random,
    size_t randomLen,
    sss_object_t *key,
    SE05x_AttestationAlgo_t attest_algo,
    uint8_t *writebuf,
    uint32_t writeLength)
{
#if SSS_HAVE_HOSTCRYPTO_ANY
    sss_status_t sss_status;
#endif
    smStatus_t status                              = SM_NOT_OK;
    sss_se05x_attst_comp_data_t attest_data        = {0};
    uint8_t rspbuffer[SE05X_I2CM_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufferLen                            = sizeof(rspbuffer);
    /* doc:start: i2cm-read-with-attestation */
    TLV[0].type                 = kSE05x_I2CM_Configure;
    TLV[0].cmd.cfg.I2C_addr     = I2C_SENSOR_BUS_ADDRESS;
    TLV[0].cmd.cfg.I2C_baudRate = kSE05x_I2CM_Baud_Rate_400Khz;

    TLV[1].type = kSE05x_I2CM_Write;
    if (writeLength > UINT8_MAX) {
        return status;
    }
    TLV[1].cmd.w.writeLength = writeLength;
    TLV[1].cmd.w.writebuf    = writebuf;

    attest_data.timeStampLen = sizeof(attest_data.timeStamp.ts);
    attest_data.chipIdLen    = sizeof(attest_data.chipId);
#if SSS_HAVE_SE05X_VER_GTE_07_02
    attest_data.objSizeLen = sizeof(attest_data.objSize);
#endif // SSS_HAVE_SE05X_VER_GTE_07_02
    attest_data.signatureLen = sizeof(attest_data.signature);
    status                   = Se05x_i2c_master_attst_txn(
        &pCtx->session, key, &TLV[0], random, randomLen, attest_algo, &attest_data, rspbuffer, &rspbufferLen, 2);
    /* doc:end: i2cm-read-with-attestation */
    ENSURE_OR_GO_EXIT(SE05X_I2CM_MAX_TIMESTAMP_SIZE == attest_data.timeStampLen);
    ENSURE_OR_GO_EXIT(SE05X_I2CM_MAX_CHIP_ID_SIZE == attest_data.chipIdLen);
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    ENSURE_OR_GO_EXIT(SE05X_I2CM_MAX_FRESHNESS_SIZE == attest_data.outrandomLen);
    for (size_t iCnt = 0; iCnt < attest_data.outrandomLen; iCnt++) {
        if (random[iCnt] == attest_data.outrandom[iCnt]) {
            continue;
        }
        else {
            LOG_E("failed to verify freshness data");
            return status;
        }
    }
#endif // SSS_HAVE_SE05X_VER_GTE_07_02

#if SSS_HAVE_HOSTCRYPTO_ANY
    sss_status = i2cm_VerifyAttestation(pCtx, &attest_data, rspbuffer, rspbufferLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
#else
    LOG_W("i2cm_VerifyAttestation is Not Performed !");
#endif

    return status;
exit:
    return SM_NOT_OK;
}

static smStatus_t i2cm_AttestedRead(ex_sss_boot_ctx_t *pCtx,
    uint8_t *random,
    size_t randomLen,
    sss_object_t *key,
    SE05x_AttestationAlgo_t attest_algo,
    uint8_t *readbuf,
    uint32_t readLength)
{
#if SSS_HAVE_HOSTCRYPTO_ANY
    sss_status_t sss_status;
#endif
    smStatus_t status                              = SM_NOT_OK;
    sss_se05x_attst_comp_data_t attest_data        = {0};
    uint8_t rspbuffer[SE05X_I2CM_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufferLen                            = sizeof(rspbuffer);
    TLV[0].type                                    = kSE05x_I2CM_Configure;
    TLV[0].cmd.cfg.I2C_addr                        = I2C_SENSOR_BUS_ADDRESS;
    TLV[0].cmd.cfg.I2C_baudRate                    = kSE05x_I2CM_Baud_Rate_400Khz;

    TLV[1].type = kSE05x_I2CM_Read;
    if (readLength > UINT16_MAX) {
        return status;
    }
    TLV[1].cmd.rd.readLength = readLength;
    TLV[1].cmd.rd.rdBuf      = readbuf;

    attest_data.timeStampLen = sizeof(attest_data.timeStamp.ts);
    attest_data.chipIdLen    = sizeof(attest_data.chipId);
#if SSS_HAVE_SE05X_VER_GTE_07_02
    attest_data.objSizeLen = sizeof(attest_data.objSize);
#endif // SSS_HAVE_SE05X_VER_GTE_07_02
    attest_data.signatureLen = sizeof(attest_data.signature);
    status                   = Se05x_i2c_master_attst_txn(
        &pCtx->session, key, &TLV[0], random, randomLen, attest_algo, &attest_data, rspbuffer, &rspbufferLen, 2);
    ENSURE_OR_GO_EXIT(SE05X_I2CM_MAX_TIMESTAMP_SIZE == attest_data.timeStampLen);
    ENSURE_OR_GO_EXIT(SE05X_I2CM_MAX_CHIP_ID_SIZE == attest_data.chipIdLen);
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    ENSURE_OR_GO_EXIT(SE05X_I2CM_MAX_FRESHNESS_SIZE == attest_data.outrandomLen);
    for (size_t iCnt = 0; iCnt < attest_data.outrandomLen; iCnt++) {
        if (random[iCnt] == attest_data.outrandom[iCnt]) {
            continue;
        }
        else {
            LOG_E("failed to verify freshness data");
            return status;
        }
    }
#endif // SSS_HAVE_SE05X_VER_GTE_07_02

#if SSS_HAVE_HOSTCRYPTO_ANY
    sss_status = i2cm_VerifyAttestation(pCtx, &attest_data, rspbuffer, rspbufferLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
#else
    LOG_W("i2cm_VerifyAttestation is Not Performed !");
#endif

    return status;
exit:
    return SM_NOT_OK;
}

static smStatus_t i2cm_AttestedWriteRead(ex_sss_boot_ctx_t *pCtx,
    uint8_t *random,
    size_t randomLen,
    sss_object_t *key,
    SE05x_AttestationAlgo_t attest_algo,
    uint8_t *writebuf,
    uint32_t writeLength,
    uint8_t *readbuf,
    uint32_t readLength)
{
#if SSS_HAVE_HOSTCRYPTO_ANY
    sss_status_t sss_status;
#endif
    smStatus_t status                              = SM_NOT_OK;
    sss_se05x_attst_comp_data_t attest_data        = {0};
    uint8_t rspbuffer[SE05X_I2CM_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufferLen                            = sizeof(rspbuffer);
    TLV[0].type                                    = kSE05x_I2CM_Configure;
    TLV[0].cmd.cfg.I2C_addr                        = I2C_SENSOR_BUS_ADDRESS;
    TLV[0].cmd.cfg.I2C_baudRate                    = kSE05x_I2CM_Baud_Rate_400Khz;

    TLV[1].type = kSE05x_I2CM_Write;
    if (writeLength > UINT8_MAX) {
        return status;
    }
    TLV[1].cmd.w.writeLength = writeLength;
    TLV[1].cmd.w.writebuf    = writebuf;

    TLV[2].type = kSE05x_I2CM_Read;
    if (readLength > UINT16_MAX) {
        return status;
    }
    TLV[2].cmd.rd.readLength = readLength;
    TLV[2].cmd.rd.rdBuf      = readbuf;

    attest_data.timeStampLen = sizeof(attest_data.timeStamp.ts);
    attest_data.chipIdLen    = sizeof(attest_data.chipId);
#if SSS_HAVE_SE05X_VER_GTE_07_02
    attest_data.objSizeLen = sizeof(attest_data.objSize);
#endif // SSS_HAVE_SE05X_VER_GTE_07_02
    attest_data.signatureLen = sizeof(attest_data.signature);
    status                   = Se05x_i2c_master_attst_txn(
        &pCtx->session, key, &TLV[0], random, randomLen, attest_algo, &attest_data, rspbuffer, &rspbufferLen, 3);
    ENSURE_OR_GO_EXIT(SE05X_I2CM_MAX_TIMESTAMP_SIZE == attest_data.timeStampLen);
    ENSURE_OR_GO_EXIT(SE05X_I2CM_MAX_CHIP_ID_SIZE == attest_data.chipIdLen);
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    ENSURE_OR_GO_EXIT(SE05X_I2CM_MAX_FRESHNESS_SIZE == attest_data.outrandomLen);
    for (size_t iCnt = 0; iCnt < attest_data.outrandomLen; iCnt++) {
        if (random[iCnt] == attest_data.outrandom[iCnt]) {
            continue;
        }
        else {
            LOG_E("failed to verify freshness data");
            return status;
        }
    }
#endif // SSS_HAVE_SE05X_VER_GTE_07_02

#if SSS_HAVE_HOSTCRYPTO_ANY
    sss_status = i2cm_VerifyAttestation(pCtx, &attest_data, rspbuffer, rspbufferLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
#else
    LOG_W("i2cm_VerifyAttestation is Not Performed !");
#endif

    return status;
exit:
    return SM_NOT_OK;
}

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    smStatus_t status;
#if SSS_HAVE_HOSTCRYPTO_ANY
    sss_status_t ret;
#endif
    sss_object_t key;
    uint8_t pAcclwhoAmIreg[]  = {0x0D};
    uint8_t pAcclCtrlReg1[]   = {0x2A, 0x00};
    uint8_t pAcclCtrlReg2[]   = {0x2A, 0x0D, 0x00};
    uint8_t pAcclxyzDataCfg[] = {0x0E, 0x01};
    uint8_t pacclRead[I2C_MAX_DATA];
    uint8_t status_value = 0;
    uint32_t i           = 0;
#if LOG_INFO_ENABLED
    int16_t x, y, z;
#endif
    SE05x_AttestationAlgo_t attest_algo = kSE05x_AttestationAlgo_EC_SHA_512;
    uint8_t random[16]                  = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    size_t randomLen                    = sizeof(random);

    LOG_I("I2CM example to read attested Accelerometer value");
    /* ------------------------------------------------------------------------------------------------------------------- */
#if SSS_HAVE_HOSTCRYPTO_ANY
    ret = i2cm_ConfigureAttestation(pCtx, &key);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == ret);
#else
    LOG_W("i2cm_ConfigureAttestation Not Performed !");
#endif

    status = i2cm_AttestedWriteRead(
        pCtx, random, randomLen, &key, attest_algo, pAcclwhoAmIreg, sizeof(pAcclwhoAmIreg), pacclRead, 1);
    ENSURE_OR_GO_EXIT(SM_OK == status);
    ENSURE_OR_GO_EXIT(kSE05x_I2CM_Success == TLV[1].cmd.w.wrStatus);

    status = i2cm_AttestedWrite(pCtx, random, randomLen, &key, attest_algo, pAcclCtrlReg1, sizeof(pAcclCtrlReg1));
    ENSURE_OR_GO_EXIT(SM_OK == status);
    ENSURE_OR_GO_EXIT(kSE05x_I2CM_Success == TLV[1].cmd.w.wrStatus);

    status = i2cm_AttestedWrite(pCtx, random, randomLen, &key, attest_algo, pAcclxyzDataCfg, sizeof(pAcclxyzDataCfg));
    ENSURE_OR_GO_EXIT(SM_OK == status);
    ENSURE_OR_GO_EXIT(kSE05x_I2CM_Success == TLV[1].cmd.w.wrStatus);

    status = i2cm_AttestedWrite(pCtx, random, randomLen, &key, attest_algo, pAcclCtrlReg2, sizeof(pAcclCtrlReg2));
    ENSURE_OR_GO_EXIT(SM_OK == status);
    ENSURE_OR_GO_EXIT(kSE05x_I2CM_Success == TLV[1].cmd.w.wrStatus);

    for (i = 0; i < ACCEL_READ_TIMES; i++) {
        /*  wait for new data are ready. */
        while (status_value != 0xff) {
            status = i2cm_AttestedRead(pCtx, random, randomLen, &key, attest_algo, pacclRead, 1);
            ENSURE_OR_GO_EXIT(SM_OK == status);
            status_value = TLV[1].cmd.rd.rdBuf[0];
        }
        status = i2cm_AttestedRead(pCtx, random, randomLen, &key, attest_algo, pacclRead, 7);
        ENSURE_OR_GO_EXIT(SM_OK == status);

#if LOG_INFO_ENABLED
        x = ((int16_t)(((TLV[1].cmd.rd.rdBuf[1] * 256U) | TLV[1].cmd.rd.rdBuf[2]))) / 4U;
        y = ((int16_t)(((TLV[1].cmd.rd.rdBuf[3] * 256U) | TLV[1].cmd.rd.rdBuf[4]))) / 4U;
        z = ((int16_t)(((TLV[1].cmd.rd.rdBuf[5] * 256U) | TLV[1].cmd.rd.rdBuf[6]))) / 4U;

        LOG_I("x = %5d , y = %5d , z = %5d", x, y, z);
#endif
    }

    LOG_I("I2CM test completed !!!...");

    return kStatus_SSS_Success;

exit:
    return kStatus_SSS_Fail;
}
