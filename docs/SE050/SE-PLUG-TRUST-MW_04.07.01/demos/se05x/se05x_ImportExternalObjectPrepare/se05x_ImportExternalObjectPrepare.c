/*
* Copyright 2020 NXP
*
* SPDX-License-Identifier: Apache-2.0
*/

#include "se05x_ImportExternalObjectPrepare.h"

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_policy.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <nxScp03_Apis.h>
#include <nxScp03_Const.h>
#include <se05x_APDU.h>
#include <se05x_tlv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <smCom.h>

#include "fsl_sss_util_asn1_der.h"
#include "smCom.h"

static ex_sss_boot_ctx_t gex_sss_import_external_prepare;
uint8_t gTxBuffer[SE05X_MAX_BUF_SIZE_CMD];
size_t gTxBufferLen;
Se05xSession_t *pgSe05xSessionCtx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_import_external_prepare)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1
#define EX_SSS_BOOT_SKIP_SELECT_APPLET 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

static void usage()
{
    LOG_W(
        "\n\
    Usage:\n\
    se05x_ImportExternalObjectPrepare.exe \n\
        -keyid <ECDSA auth object id>\n\
        -file  <Input ECDSA keypair file>");
    return;
}

static sss_status_t parse_command_line_args(int argc, const char **argv);
static sss_status_t calculate_shared_secret(ex_sss_boot_ctx_t *pCtx);
static sss_status_t calculate_master_secret(ex_sss_boot_ctx_t *pCtx);
static sss_status_t nxECKey_HostLocal_CalculateSessionKeys(ex_sss_boot_ctx_t *pCtx);
static sss_status_t nxECKey_Calculate_Initial_Mac_Chaining_Value(ex_sss_boot_ctx_t *pCtx);

static sss_status_t read_se_ecka_and_store(ex_sss_boot_ctx_t *pCtx);
static sss_status_t generate_tee_ecka_and_export(ex_sss_boot_ctx_t *pCtx,
    uint8_t *pk_tee_ecka,
    size_t *pk_tee_ecka_len,
    size_t *publicKeyLen,
    uint16_t *outKeyIndex);
static sss_status_t store_ecdsa_key(ex_sss_boot_ctx_t *pCtx);
static sss_status_t create_internal_auth_data(ex_sss_boot_ctx_t *pCtx,
    uint8_t *p_to_be_signed_buf,
    size_t *to_be_signed_len,
    uint8_t *pk_tee_ecka,
    size_t publicKeyLen);

smStatus_t se05x_ImportExtObjTransformBuffer(Se05xSession_t *pwrite_apdubufferctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle);

smStatus_t se05x_ImportExtObjCreateAPDU(Se05xSession_t *pwrite_apdubufferctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle);

static smStatus_t se05x_ImportExtObjTransmitBuffer(void *conn_ctx,
    struct _sss_se05x_tunnel_context *pChannelCtx,
    SE_AuthType_t currAuth,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle);

smStatus_t se05x_ImportExtObjDecryptResponse(
    struct Se05xSession *pSessionCtx, size_t cmd_cmacLen, uint8_t *rsp, size_t *rspLength, uint8_t hasle);

extern void add_ecc_header(uint8_t *key, size_t *keylen, uint8_t **key_buf, size_t *key_buflen, uint32_t curve_id);
extern sss_status_t nxECKey_ReadEckaPublicKey(pSe05xSession_t se05xSession,
    sss_key_store_t *pHostKeyStore,
    uint8_t *pSePubEcka,
    size_t *pSePubEckaLen,
    uint32_t eckaObjId);

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status;
    smStatus_t sm_status     = SM_NOT_OK;
    int argc                 = gex_sss_argc;
    const char **argv        = gex_sss_argv;
    uint8_t pk_tee_ecka[256] = {0};
    size_t pk_tee_ecka_len   = sizeof(pk_tee_ecka);
    size_t publicKeyLen;
    uint16_t outKeyIndex;
    uint8_t to_be_signed[200] = {0};
    size_t to_be_signed_len   = 0;
    sss_digest_t digest_ctx;
    uint8_t digest[32] = {0};
    size_t digestLen   = sizeof(digest);
    sss_asymmetric_t asymm_ctx;
    uint8_t signature[80]                       = {0};
    size_t signatureLen                         = sizeof(signature);
    uint8_t internal_auth_pk_tee_ecka_sig_tag[] = INTERNAL_AUTH_PK_TEE_ECKA_SIG_TAG;
    uint8_t auth_data[256]                      = {0};
    size_t auth_data_len                        = 0;
    uint8_t auth_id[4]                          = {0};
    NXSCP03_DynCtx_t dyn_ctx;
    uint8_t EncryptedAPDU[100]           = {0};
    uint8_t EncryptedAPDUWithHeader[300] = {0};
    size_t EncryptedAPDUWithHeaderLen    = 0;
    uint8_t mac[16]                      = {0};
    size_t macLen;

    sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)&pCtx->session;
    pgSe05xSessionCtx                  = &se05x_session->s_ctx;

    /* Parse commandline arguments */
    status = parse_command_line_args(argc, argv);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    for (int i = 0; i < 4; ++i)
        auth_id[i] = ((uint8_t *)&ecdsa_auth_id)[3 - i];

    sss_se05x_session_t se05xWriteBufferSession;
    Se05xSession_t *pse05xWriteBufferSessionCtx = &se05xWriteBufferSession.s_ctx;

    /* Read PK.SE.ECKA */
    status = read_se_ecka_and_store(pCtx);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Generate SK.TEE.ECKA and read PK.TEE.ECKA */
    status = generate_tee_ecka_and_export(pCtx, pk_tee_ecka, &pk_tee_ecka_len, &publicKeyLen, &outKeyIndex);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Store ECDSA key in host */
    status = store_ecdsa_key(pCtx);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Create InternalAuth TLV to be signed by ECDSA key */
    status = create_internal_auth_data(pCtx, to_be_signed, &to_be_signed_len, &pk_tee_ecka[outKeyIndex], publicKeyLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Sign InternalAuth data
     * Data should be hashed and signed
     * Signature algorithm should be kAlgorithm_SSS_ECDSA_SHA256
     */
    status = sss_digest_context_init(&digest_ctx, &pCtx->host_session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_digest_one_go(&digest_ctx, to_be_signed, to_be_signed_len, digest, &digestLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    sss_digest_context_free(&digest_ctx);

    status = sss_asymmetric_context_init(
        &asymm_ctx, &pCtx->host_session, &hostECDSAkey_object, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_asymmetric_sign_digest(&asymm_ctx, digest, digestLen, signature, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    sss_asymmetric_context_free(&asymm_ctx);

    /* Add signature to 0x5F37 tag */

    memcpy(&auth_data[auth_data_len], to_be_signed, to_be_signed_len);
    auth_data_len += to_be_signed_len;
    memcpy(&auth_data[auth_data_len], internal_auth_pk_tee_ecka_sig_tag, sizeof(internal_auth_pk_tee_ecka_sig_tag));
    auth_data_len += sizeof(internal_auth_pk_tee_ecka_sig_tag);
    auth_data[auth_data_len++] = (uint8_t)signatureLen;
    memcpy(&auth_data[auth_data_len], signature, signatureLen);
    auth_data_len += signatureLen;

    status = calculate_shared_secret(pCtx);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = calculate_master_secret(pCtx);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = nxECKey_HostLocal_CalculateSessionKeys(pCtx);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = nxECKey_Calculate_Initial_Mac_Chaining_Value(pCtx);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    pse05xWriteBufferSessionCtx->authType     = kSSS_AuthType_ECKey;
    pse05xWriteBufferSessionCtx->pdynScp03Ctx = &dyn_ctx;
    memcpy(&pse05xWriteBufferSessionCtx->pdynScp03Ctx->Enc, &enc_obj, sizeof(sss_object_t));
    memcpy(&pse05xWriteBufferSessionCtx->pdynScp03Ctx->Mac, &mac_obj, sizeof(sss_object_t));
    memcpy(&pse05xWriteBufferSessionCtx->pdynScp03Ctx->Rmac, &rmac_obj, sizeof(sss_object_t));
    memcpy(pse05xWriteBufferSessionCtx->pdynScp03Ctx->MCV, iniMacChaining, 16);
    memcpy(pse05xWriteBufferSessionCtx->pdynScp03Ctx->cCounter, commandCounter, 16);
    pse05xWriteBufferSessionCtx->pdynScp03Ctx->authType      = kSSS_AuthType_ECKey;
    pse05xWriteBufferSessionCtx->pdynScp03Ctx->SecurityLevel = SECURITY_LEVEL;

    /* doc:start:writesecureobjbuf */
    /* Symmetric Key */
    /* clang-format off */
    uint8_t keyValue[] = {0x48, 0x45, 0x4C, 0x4C, 0x4F, 0x48, 0x45, 0x4C, 0x4C, 0x4F, 0x48, 0x45, 0x4C, 0x4C, 0x4F, 0x31};
    /* clang-format on */
    /* API to create buffer */
    pse05xWriteBufferSessionCtx->fp_TXn = &se05x_ImportExtObjCreateAPDU;
    int index                           = 0;

    sm_status = Se05x_API_WriteSymmKey(pse05xWriteBufferSessionCtx,
        NULL,
        SE05x_MaxAttemps_NA,
        __LINE__,
        SE05x_KeyID_KEK_NONE,
        keyValue,
        sizeof(keyValue),
        kSE05x_INS_NA,
        kSE05x_SymmKeyType_AES);
    if (sm_status != SM_OK) {
        LOG_E("Failed to create buffer");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    /* WriteSecureObject API will prepare complete APDU.
     * We need to skip initial CLA INS P1 P2 and use just the TLVs
     *
     * The length is determined by the first length byte. If it
     * is 0x00, the next two bytes are the length, otherwise that
     * byte is the length.
     *
     * Determine the length here and accordingly determine the TLV.
     */
    if (gTxBuffer[4] == 0x00) {
        WriteSymmKeyAPDU_len = ((gTxBuffer[5] << 8) && 0xFF00) | ((gTxBuffer[6]) && 0xFF);
        index                = 7;
    }
    else {
        WriteSymmKeyAPDU_len = gTxBuffer[4];
        index                = 5;
    }
    if (WriteSymmKeyAPDU_len > sizeof(WriteSymmKeyAPDU)) {
        LOG_E("Insufficient buffer");
        status = kStatus_SSS_Fail;
        goto exit;
    }
    memcpy(WriteSymmKeyAPDU, &gTxBuffer[index], WriteSymmKeyAPDU_len);
    /* doc:end:writesecureobjbuf */

    /* Wrap WriteSecureObject APDU with FastSCP context */
    memcpy(EncryptedAPDU, WriteSymmKeyAPDU, WriteSymmKeyAPDU_len);
    status =
        nxSCP03_Encrypt_CommandAPDU(pse05xWriteBufferSessionCtx->pdynScp03Ctx, EncryptedAPDU, &WriteSymmKeyAPDU_len);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Add header containing CLA INS P1 P2 */
    EncryptedAPDUWithHeader[0] = 0x84; /* CLA */
    EncryptedAPDUWithHeader[1] = 0x01; /* INS */
    EncryptedAPDUWithHeader[2] = 0x03; /* P1 */
    EncryptedAPDUWithHeader[3] = 0x00; /* P2 */
    EncryptedAPDUWithHeader[4] = (uint8_t)WriteSymmKeyAPDU_len + 8 /* Length of mac added */;

    memcpy(&EncryptedAPDUWithHeader[5], EncryptedAPDU, WriteSymmKeyAPDU_len);
    EncryptedAPDUWithHeaderLen = WriteSymmKeyAPDU_len + 5;
    /* Add MAC to the wrapped command */
    status = nxpSCP03_CalculateMac_CommandAPDU(
        pse05xWriteBufferSessionCtx->pdynScp03Ctx, EncryptedAPDUWithHeader, EncryptedAPDUWithHeaderLen, mac, &macLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if SSS_HAVE_SE05X_VER_GTE_07_02
    /* Save MAC for RMAC calculation */
    memcpy(ObjectMAC, mac, 16);
#endif

    memcpy(&EncryptedAPDUWithHeader[EncryptedAPDUWithHeaderLen], mac, 8);
    EncryptedAPDUWithHeaderLen += 8;
    LOG_D("Restore MCV ");
#if SSS_HAVE_SE05X_VER_GTE_07_02
    /* For 5.10 applet onwards Current MAC is MCV*/
    memcpy(pse05xWriteBufferSessionCtx->pdynScp03Ctx->MCV, ObjectMAC, 16);
#else
    /* Before 5.10 applet initial MAC is MCV*/
    memcpy(pse05xWriteBufferSessionCtx->pdynScp03Ctx->MCV, iniMacChaining, 16);
#endif

    pse05xWriteBufferSessionCtx->fp_TXn     = &se05x_ImportExtObjTransformBuffer;
    pse05xWriteBufferSessionCtx->fp_RawTXn  = &se05x_ImportExtObjTransmitBuffer;
    pse05xWriteBufferSessionCtx->fp_DeCrypt = &se05x_ImportExtObjDecryptResponse;
    /* Create raw APDU for ImportExternalObject */
    sm_status = Se05x_API_ImportExternalObject(pse05xWriteBufferSessionCtx,
        auth_data,
        auth_data_len,
        auth_id,
        sizeof(auth_id),
        EncryptedAPDUWithHeader,
        EncryptedAPDUWithHeaderLen);

    status = (sm_status == SM_OK) ? kStatus_SSS_Success : kStatus_SSS_Fail;

exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_ImportExternalObjectPrepare Example Success !!!...");
    }
    else {
        LOG_E("se05x_ImportExternalObjectPrepare Example Failed !!!...");
    }
    return status;
}

static sss_status_t parse_command_line_args(int argc, const char **argv)
{
    bool ecdsa_file_parameter_passed = false;
    bool ecdsa_auth_id_passed        = false;

    for (int j = 1; j < argc; j++) {
        if (strcmp(argv[j], "-file") == 0) {
            ecdsa_file_parameter_passed = true;
            j++;
            if (j >= argc) {
                usage();
                return kStatus_SSS_Fail;
            }
            const char *filename = argv[j];
            FILE *fp             = fopen(filename, "rb");
            if (fp == NULL) {
                LOG_E("Cannot open file");
                return kStatus_SSS_Fail;
            }
            fread(hostEcdsakey, sizeof(hostEcdsakey), 1, fp);
            fclose(fp);
        }
        else if (strcmp(argv[j], "-keyid") == 0) {
            ecdsa_auth_id_passed = true;
            j++;
            if (j >= argc) {
                usage();
                return kStatus_SSS_Fail;
            }
            ecdsa_auth_id = (uint32_t)strtoul(argv[j], NULL, 16);
        }
    }
    if (!ecdsa_file_parameter_passed) {
        LOG_E("ECDSA file parameter not passed");
        usage();
        return kStatus_SSS_Fail;
    }
    if (!ecdsa_auth_id_passed) {
        LOG_E("ECDSA KeyID not passed");
        usage();
        return kStatus_SSS_Fail;
    }

    return kStatus_SSS_Success;
}

static sss_status_t calculate_shared_secret(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_derive_key_t dervCtx;
    size_t sharedSecBitLen = 0;
    /* Derive shared secret using PK.SE.ECKA and SK.TEE.ECKA
     * This will be stored in shsSecret object
     */
    status = sss_key_object_init(&shsSecret, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(
        &shsSecret, __LINE__, kSSS_KeyPart_Default, kSSS_CipherType_AES, 32, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_derive_key_context_init(
        &dervCtx, &pCtx->host_session, &sk_tee_ecka_obj, kAlgorithm_SSS_ECDH, kMode_SSS_ComputeSharedSecret);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_derive_key_dh(&dervCtx, &se_ecka_pub_host_obj, &shsSecret);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_get_key(shsSecret.keyStore, &shsSecret, sharedSecret, &sharedSecretLen, &sharedSecBitLen);
    LOG_D("sharedSecret");
    LOG_AU8_D(sharedSecret, sharedSecretLen);

cleanup:
    sss_derive_key_context_free(&dervCtx);
    sss_key_object_free(&shsSecret);
    return status;
}

static sss_status_t calculate_master_secret(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_digest_t md;
    /* Fixed DR.SE */
    uint8_t dr_se[16] = {0};
    size_t dr_se_len  = sizeof(dr_se);

    uint8_t derivationInput[100] = {0};
    size_t derivationInputLen    = 0;

#if SSS_HAVE_SE05X_VER_GTE_07_02 || SSS_HAVE_FIPS
    const uint8_t kdf_counter[] = {0x00, 0x00, 0x00, 0x01};
    memcpy(&derivationInput[derivationInputLen], kdf_counter, sizeof(kdf_counter));
    derivationInputLen += sizeof(kdf_counter);
#endif
    /* Calculate master secret using previously derived shared secret and dr.se (fixed) */
    memcpy(&derivationInput[derivationInputLen], sharedSecret, sharedSecretLen);
    derivationInputLen += sharedSecretLen;
    memcpy(&derivationInput[derivationInputLen], dr_se, dr_se_len);
    derivationInputLen += dr_se_len;

    derivationInput[derivationInputLen++] = SCP_CONFIG;
    derivationInput[derivationInputLen++] = SECURITY_LEVEL;
    derivationInput[derivationInputLen++] = GPCS_KEY_TYPE_AES;
    derivationInput[derivationInputLen++] = GPCS_KEY_LEN_AES;

    status = sss_digest_context_init(&md, &pCtx->host_session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_digest_one_go(&md, derivationInput, derivationInputLen, masterSk, &masterSkLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    sss_digest_context_free(&md);
    masterSkLen = 16;
    LOG_MAU8_D("Master Secret", masterSk, masterSkLen);
    /*Set the Master secret as AES Key*/
    status = sss_key_object_init(&masterSec, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(
        &masterSec, __LINE__, kSSS_KeyPart_Default, kSSS_CipherType_AES, 32, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_host_key_store_set_key(&pCtx->host_ks, &masterSec, masterSk, masterSkLen, masterSkLen * 8, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("master shared Secret !!!!");
    LOG_AU8_I(masterSk, masterSkLen);
cleanup:
    return status;
}

static sss_status_t nxECKey_HostLocal_CalculateSessionKeys(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    uint8_t ddA[128];
    uint16_t ddALen = sizeof(ddA);
    uint8_t sessionEncKey[16];
    uint8_t sessionMacKey[16];
    uint8_t sessionRmacKey[16];
    uint32_t signatureLen = 16;

    /* Generation and Creation of Session ENC SSS Key Object */

    // Set the Derviation data
    nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SENC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, NULL, 0);
    // Calculate the Session-ENC key
    status = nxScp03_Generate_SessionKey(&masterSec, ddA, ddALen, sessionEncKey, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_I("sessionEncKey", sessionEncKey, 16);
    // Set the Session-ENC key
    status = sss_key_object_init(&enc_obj, &pCtx->host_ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(
        &enc_obj, __LINE__, kSSS_KeyPart_Default, kSSS_CipherType_AES, 32, kKeyObject_Mode_Persistent);
    status = sss_key_store_set_key(&pCtx->host_ks, &enc_obj, sessionEncKey, 16, (16) * 8, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Generation and Creation of Session MAC SSS Key Object */

    // Set the Derviation data
    nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, NULL, 0);
    // Calculate the Session-MAC key
    status = nxScp03_Generate_SessionKey(&masterSec, ddA, ddALen, sessionMacKey, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_I("sessionMacKey", sessionMacKey, 16);
    // Set the Session-MAC key
    status = sss_key_object_init(&mac_obj, &pCtx->host_ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(
        &mac_obj, __LINE__, kSSS_KeyPart_Default, kSSS_CipherType_AES, 32, kKeyObject_Mode_Persistent);
    status = sss_host_key_store_set_key(&pCtx->host_ks, &mac_obj, sessionMacKey, 16, (16) * 8, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Generation and Creation of Session RMAC SSS Key Object */

    // Set the Derviation data
    nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SRMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, NULL, 0);
    // Calculate the Session-RMAC key
    status = nxScp03_Generate_SessionKey(&masterSec, ddA, ddALen, sessionRmacKey, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_I("sessionRmacKey", sessionRmacKey, 16);
    // Set the Session-RMAC key
    status = sss_key_object_init(&rmac_obj, &pCtx->host_ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(
        &rmac_obj, __LINE__, kSSS_KeyPart_Default, kSSS_CipherType_AES, 32, kKeyObject_Mode_Persistent);
    status = sss_host_key_store_set_key(&pCtx->host_ks, &rmac_obj, sessionRmacKey, 16, (16) * 8, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
exit:
    return status;
}

static sss_status_t nxECKey_Calculate_Initial_Mac_Chaining_Value(ex_sss_boot_ctx_t *pCtx)
{
    AX_UNUSED_ARG(pCtx);
    sss_status_t status = kStatus_SSS_Fail;
    uint8_t ddA[128];
    uint16_t ddALen       = sizeof(ddA);
    uint32_t signatureLen = 16;

    // Set the Derviation data
    nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_INITIAL_MCV, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, NULL, 0);
    // Calculate the Initial MCV value
    status = nxScp03_Generate_SessionKey(&masterSec, ddA, ddALen, iniMacChaining, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_I("Initial MCV", iniMacChaining, 16);
    // Set the Initial MCV value
exit:
    return status;
}
/* doc:start:transformsapdubuf */
/* This API transforms buffer to APDU and internally calls transmit and Decrypt */
smStatus_t se05x_ImportExtObjTransformBuffer(Se05xSession_t *pSe05xSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle)
{
    memset(gTxBuffer, 0, sizeof(gTxBuffer));
    size_t i = 0;
    memcpy(&gTxBuffer[i], hdr, sizeof(*hdr));
    smStatus_t ret = SM_NOT_OK;
    i += sizeof(*hdr);
    if (cmdBufLen > 0) {
        // The Lc field must be extended in case the length does not fit
        // into a single byte (Note, while the standard would allow to
        // encode 0x100 as 0x00 in the Lc field, nobody who is sane in his mind
        // would actually do that).
        if ((cmdBufLen < 0xFF) && !hasle) {
            gTxBuffer[i++] = (uint8_t)cmdBufLen;
        }
        else {
            gTxBuffer[i++] = 0x00;
            gTxBuffer[i++] = 0xFFu & (cmdBufLen >> 8);
            gTxBuffer[i++] = 0xFFu & (cmdBufLen);
        }
        ENSURE_OR_GO_EXIT(cmdBufLen <= sizeof(gTxBuffer) - i);
        memcpy(&gTxBuffer[i], cmdBuf, cmdBufLen);
        i += cmdBufLen;
    }
    if (hasle) {
        gTxBuffer[i++] = 0x00;
        gTxBuffer[i++] = 0x00;
    }
    gTxBufferLen = i;

    LOG_D("Here is the buffer of Object needs to be Import");
    LOG_AU8_D(gTxBuffer, gTxBufferLen);

    if (pSe05xSession->fp_RawTXn) {
        ret = pSe05xSession->fp_RawTXn(
            pgSe05xSessionCtx->conn_ctx, NULL, kSSS_AuthType_None, hdr, cmdBuf, cmdBufLen, rsp, rspLen, hasle);
        ENSURE_OR_GO_EXIT(ret == SM_OK);
    }
    if (pSe05xSession->fp_DeCrypt) {
        ret = pSe05xSession->fp_DeCrypt(pSe05xSession, cmdBufLen, rsp, rspLen, hasle);
    }
exit:
    return ret;
}
/* doc:end:transformsapdubuf */

/* doc:start:decryptsresponsebuf */
/* This API decrypts the response buffer  */
smStatus_t se05x_ImportExtObjDecryptResponse(
    struct Se05xSession *pSessionCtx, size_t cmd_cmacLen, uint8_t *rsp, size_t *rspLength, uint8_t hasle)
{
    U16 rv = SM_NOT_OK;

    if (*rspLength >= 2) {
        rv = rsp[(*rspLength) - 2] << 8 | rsp[(*rspLength) - 1];
        if ((rv == SM_OK) && (pSessionCtx->pdynScp03Ctx != NULL)) {
#if SSS_HAVE_SCP_SCP03_SSS
            rv = nxpSCP03_Decrypt_ResponseAPDU(pSessionCtx->pdynScp03Ctx, cmd_cmacLen, rsp, rspLength, hasle);
#else
            LOG_W("Decrypting without SSS_HAVE_SCP_SCP03_SSS");
            rv = SM_NOT_OK;
#endif
        }
#if SSS_HAVE_SCP_SCP03_SSS
        else { /*Counter to be increament only in case of authentication is all kind of SCP
               and response is not 9000 */
            if ((rv != SM_OK) && (pSessionCtx->pdynScp03Ctx != NULL)) {
                if (((pSessionCtx->pdynScp03Ctx->authType == kSSS_AuthType_AESKey) ||
                        (pSessionCtx->pdynScp03Ctx->authType == kSSS_AuthType_ECKey)) ||
                    ((pSessionCtx->pdynScp03Ctx->authType == kSSS_AuthType_SCP03) && (cmd_cmacLen - 8) > 0)) {
                    nxpSCP03_Inc_CommandCounter(pSessionCtx->pdynScp03Ctx);
                }
            }
        }
#endif
    }
    else {
        rv = SM_NOT_OK;
    }

    return rv;
}
/* doc:end:decryptsresponsebuf */

/* doc:start:transmitapdubuf */
/* This API transmit the buffer in default session */
static smStatus_t se05x_ImportExtObjTransmitBuffer(void *conn_ctx,
    struct _sss_se05x_tunnel_context *pChannelCtx,
    SE_AuthType_t currAuth,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle)
{
    AX_UNUSED_ARG(pChannelCtx);
    AX_UNUSED_ARG(currAuth);
    uint8_t txBuf[SE05X_MAX_BUF_SIZE_CMD] = {0};
    size_t i                              = 0;
    memcpy(&txBuf[i], hdr, sizeof(*hdr));
    smStatus_t ret = SM_NOT_OK;
    i += sizeof(*hdr);
    if (cmdBufLen > 0) {
        // The Lc field must be extended in case the length does not fit
        // into a single byte (Note, while the standard would allow to
        // encode 0x100 as 0x00 in the Lc field, nobody who is sane in his mind
        // would actually do that).
        if ((cmdBufLen < 0xFF) && !hasle) {
            txBuf[i++] = (uint8_t)cmdBufLen;
        }
        else {
            txBuf[i++] = 0x00;
            txBuf[i++] = 0xFFu & (cmdBufLen >> 8);
            txBuf[i++] = 0xFFu & (cmdBufLen);
        }
        memcpy(&txBuf[i], cmdBuf, cmdBufLen);
        i += cmdBufLen;
    }
    else {
        if (cmdBufLen == 0) {
            txBuf[i++] = 0x00;
        }
    }

    if (hasle) {
        txBuf[i++] = 0x00;
        txBuf[i++] = 0x00;
    }

    uint32_t U32rspLen = (uint32_t)*rspLen;
    ret                = (smStatus_t)smCom_TransceiveRaw(conn_ctx, txBuf, (U16)i, rsp, &U32rspLen);
    *rspLen            = U32rspLen;
    return ret;
}
/* doc:end:transmitapdubuf */

/* doc:start:createapdubuf */
/* This API creates an APDU buffer of the object stores it to the global buffer */
smStatus_t se05x_ImportExtObjCreateAPDU(Se05xSession_t *pwrite_apdubufferctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle)
{
    AX_UNUSED_ARG(pwrite_apdubufferctx);
    AX_UNUSED_ARG(rsp);
    AX_UNUSED_ARG(rspLen);
    memset(gTxBuffer, 0, sizeof(gTxBuffer));
    size_t i = 0;
    memcpy(&gTxBuffer[i], hdr, sizeof(*hdr));
    smStatus_t ret = SM_OK;
    i += sizeof(*hdr);
    if (cmdBufLen > 0) {
        // The Lc field must be extended in case the length does not fit
        // into a single byte (Note, while the standard would allow to
        // encode 0x100 as 0x00 in the Lc field, nobody who is sane in his mind
        // would actually do that).
        if ((cmdBufLen < 0xFF) && !hasle) {
            gTxBuffer[i++] = (uint8_t)cmdBufLen;
        }
        else {
            gTxBuffer[i++] = 0x00;
            gTxBuffer[i++] = 0xFFu & (cmdBufLen >> 8);
            gTxBuffer[i++] = 0xFFu & (cmdBufLen);
        }
        memcpy(&gTxBuffer[i], cmdBuf, cmdBufLen);
        i += cmdBufLen;
    }
    if (hasle) {
        gTxBuffer[i++] = 0x00;
        gTxBuffer[i++] = 0x00;
    }
    ret          = SM_OK;
    gTxBufferLen = i;

    LOG_AU8_I(gTxBuffer, gTxBufferLen);

    return ret;
}
/* doc:end:createapdubuf */

static sss_status_t read_se_ecka_and_store(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t keyBitLen    = 256;

    sss_se05x_session_t se05xRawTxRxSession;
    Se05xSession_t *pse05xRawTxRxSessionCtx = &se05xRawTxRxSession.s_ctx;
    pse05xRawTxRxSessionCtx->fp_TXn         = &se05x_ImportExtObjTransformBuffer;
    pse05xRawTxRxSessionCtx->fp_RawTXn      = &se05x_ImportExtObjTransmitBuffer;
    pse05xRawTxRxSessionCtx->fp_DeCrypt     = NULL;

    uint8_t *p_se_ecka_pub = NULL;
    size_t key_buflen      = 0;

    add_ecc_header(se_ecka_pub, &se_ecka_pub_len, &p_se_ecka_pub, &key_buflen, kSE05x_ECCurve_NIST_P256);
    se_ecka_pub_len = se_ecka_pub_len - key_buflen;

    status = nxECKey_ReadEckaPublicKey(
        pse05xRawTxRxSessionCtx, &pCtx->host_ks, p_se_ecka_pub, &se_ecka_pub_len, SE_ECKA_PUB_OBJID);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    se_ecka_pub_len = se_ecka_pub_len + key_buflen;

    /* Set PK.SE.ECKA in host */
    status = sss_key_object_init(&se_ecka_pub_host_obj, &pCtx->host_ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(&se_ecka_pub_host_obj,
        __LINE__,
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        256,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status =
        sss_key_store_set_key(&pCtx->host_ks, &se_ecka_pub_host_obj, se_ecka_pub, se_ecka_pub_len, keyBitLen, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
exit:
    return status;
}

static sss_status_t generate_tee_ecka_and_export(
    ex_sss_boot_ctx_t *pCtx, uint8_t *pk_tee_ecka, size_t *pk_tee_ecka_len, size_t *publicKeyLen, uint16_t *outKeyIndex)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t keyBitLen    = 256;
    status              = sss_key_object_init(&sk_tee_ecka_obj, &pCtx->host_ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(&sk_tee_ecka_obj,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        sizeof(hostEcdsakey),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_store_generate_key(&pCtx->host_ks, &sk_tee_ecka_obj, 256, NULL);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_get_key(&pCtx->host_ks, &sk_tee_ecka_obj, pk_tee_ecka, pk_tee_ecka_len, &keyBitLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_D("HOST ECKA Keypair");
    LOG_AU8_D(pk_tee_ecka, *pk_tee_ecka_len);
    status = sss_util_pkcs8_asn1_get_ec_public_key_index(pk_tee_ecka, *pk_tee_ecka_len, outKeyIndex, publicKeyLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
exit:
    return status;
}

static sss_status_t store_ecdsa_key(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    status              = sss_key_object_init(&hostECDSAkey_object, &pCtx->host_ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(&hostECDSAkey_object,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        sizeof(hostEcdsakey),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status =
        sss_key_store_set_key(&pCtx->host_ks, &hostECDSAkey_object, hostEcdsakey, sizeof(hostEcdsakey), 256, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

static sss_status_t create_internal_auth_data(ex_sss_boot_ctx_t *pCtx,
    uint8_t *p_to_be_signed_buf,
    size_t *to_be_signed_len,
    uint8_t *pk_tee_ecka,
    size_t publicKeyLen)
{
    AX_UNUSED_ARG(pCtx);
    sss_status_t status                       = kStatus_SSS_Success;
    uint8_t internal_auth_pk_tee_ecka_tag[]   = INTERNAL_AUTH_PK_TEE_ECKA_TAG;
    size_t internal_auth_pk_tee_ecka_tag_size = sizeof(internal_auth_pk_tee_ecka_tag);

    uint8_t eckey_fixed_params[] = ECKEY_PARAMS;
    /* Copy fixed ECKey params of InternalAuthenticate */
    memcpy(&p_to_be_signed_buf[*to_be_signed_len], eckey_fixed_params, sizeof(eckey_fixed_params));
    (*to_be_signed_len) += sizeof(eckey_fixed_params);
    /* Create 0x7F49 TLV */
    memcpy(&p_to_be_signed_buf[*to_be_signed_len], internal_auth_pk_tee_ecka_tag, internal_auth_pk_tee_ecka_tag_size);
    (*to_be_signed_len) += internal_auth_pk_tee_ecka_tag_size;
    /* Length of value of 0x7F49 */
    uint8_t *pinternal_auth_pk_tee_ecka_len   = &p_to_be_signed_buf[(*to_be_signed_len)++];
    p_to_be_signed_buf[(*to_be_signed_len)++] = 0xB0;                  /* PK.TEE.ECKA Tag */
    p_to_be_signed_buf[(*to_be_signed_len)++] = (uint8_t)publicKeyLen; /* PK.TEE.ECKA Tag */
    memcpy(&p_to_be_signed_buf[*to_be_signed_len], pk_tee_ecka, publicKeyLen);
    (*to_be_signed_len) += publicKeyLen;
    p_to_be_signed_buf[(*to_be_signed_len)++] = 0xF0; /* ECCurve identifier Tag */
    p_to_be_signed_buf[(*to_be_signed_len)++] = 0x01; /* ECCurve identifier Length */
    p_to_be_signed_buf[(*to_be_signed_len)++] = 0x03; /* ECCurve identifier Value */
    *pinternal_auth_pk_tee_ecka_len =
        (uint8_t)(publicKeyLen + 2 /* Tag & Length for 0xF0 */ + 3 /* TLV for ECCurve Identifier */);

    return status;
}
