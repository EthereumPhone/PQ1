/* Copyright 2019,2020,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SSS_APIS_INC_FSL_SSS_PYTHON_EXPORT_H_
#define SSS_APIS_INC_FSL_SSS_PYTHON_EXPORT_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "../../sss/inc/fsl_sss_se05x_types.h"


smStatus_t Se05x_API_DeleteAll_Iterative(pSe05xSession_t session_ctx);

smStatus_t Se05x_API_WritePCR_WithType(pSe05xSession_t session_ctx,
    const SE05x_INS_t ins_type,
    pSe05xPolicy_t policy,
    uint32_t pcrID,
    const uint8_t *initialValue,
    size_t initialValueLen,
    const uint8_t *inputData,
    size_t inputDataLen);

smStatus_t Se05x_API_ReadIDList(pSe05xSession_t session_ctx,
    uint16_t outputOffset,
    uint8_t filter,
    uint8_t *pmore,
    uint8_t *idlist,
    size_t *pidlistLen);

smStatus_t Se05x_API_ReadSize(
    pSe05xSession_t session_ctx, uint32_t objectID, uint16_t *psize);

smStatus_t Se05x_API_ReadCryptoObjectList(
    pSe05xSession_t session_ctx, uint8_t *idlist, size_t *pidlistLen);

sss_status_t sss_util_openssl_write_pkcs12(const char *pkcs12_cert,
    const char *password,
    const char *ref_key,
    long ref_key_length,
    const char *cert,
    long cert_length);

sss_status_t sss_util_openssl_read_pkcs12(const char* pkcs12_cert, const char* password, uint8_t * private_key, uint8_t * cert);

smStatus_t Se05x_API_WriteSymmKey(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_KeyID_t kekID,
    const uint8_t *keyValue,
    size_t keyValueLen,
    const SE05x_INS_t ins_type,
    const SE05x_SymmKeyType_t type);

smStatus_t Se05x_API_WriteECKey(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_ECCurve_t curveID,
    const uint8_t *privKey,
    size_t privKeyLen,
    const uint8_t *pubKey,
    size_t pubKeyLen,
	const SE05x_INS_t ins_type,
    const SE05x_KeyPart_t key_part);


sss_status_t sss_se05x_create_object_policy_buffer(
    sss_policy_t *policies, uint8_t *pbuff, size_t *buf_len);


sss_status_t sss_se05x_refresh_session(
    sss_se05x_session_t *session, void *connectionData);

/** Similar to @ref sss_se05x_asymmetric_sign_digest,
 *
 * but hashing/digest done by SE
 */
sss_status_t sss_se05x_asymmetric_sign(sss_se05x_asymmetric_t *context,
    uint8_t *srcData,
    size_t srcLen,
    uint8_t *signature,
    size_t *signatureLen);

/** Similar to @ref sss_se05x_asymmetric_verify_digest,
 * but hashing/digest done by SE
 *
 */
sss_status_t sss_se05x_asymmetric_verify(sss_se05x_asymmetric_t *context,
    uint8_t *srcData,
    size_t srcLen,
    uint8_t *signature,
    size_t signatureLen);

smStatus_t Se05x_API_GetVersion(pSe05xSession_t session_ctx, uint8_t *pappletVersion, size_t *appletVersionLen);


 /** @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] keyPairId keyPairId [1:kSE05x_TAG_1]
 * @param[in] pskId pskId [2:kSE05x_TAG_2]
 * @param[in] hmacKeyId hmacKeyId [3:kSE05x_TAG_3]
 * @param[in] inputData inputData [4:kSE05x_TAG_4]
 * @param[in] inputDataLen Length of inputData
 */
smStatus_t Se05x_API_TLSCalculatePreMasterSecret(pSe05xSession_t session_ctx,
    uint32_t keyPairId,
    uint32_t pskId,
    uint32_t hmacKeyId,
    const uint8_t *inputData,
    size_t inputDataLen);

 /** @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[out] randomValue  [0:kSE05x_TAG_1]
 * @param[in,out] prandomValueLen Length for randomValue
 */
smStatus_t Se05x_API_TLSGenerateRandom(pSe05xSession_t session_ctx, uint8_t *randomValue, size_t *prandomValueLen);


 /**
 * @param[in]  session_ctx     The session context
 * @param[in]  objectID        The object id
 * @param[in]  digestAlgo      The digest algorithm
 * @param[in]  label           The label
 * @param[in]  labelLen        The label length
 * @param[in]  random          The random
 * @param[in]  randomLen       The random length
 * @param[in]  reqLen          The request length
 * @param      outputData      The output data
 * @param      poutputDataLen  The poutput data length
 * @param[in]  tlsprf          The tlsprf
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_TLSPerformPRF(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint8_t digestAlgo,
    const uint8_t *label,
    size_t labelLen,
    const uint8_t *random,
    size_t randomLen,
    uint16_t reqLen,
    uint8_t *outputData,
    size_t *poutputDataLen,
    const SE05x_TLSPerformPRFType_t tlsprf);

/**
 * @param[in]  session_ctx       The session context
 * @param[in]  policy            The policy
 * @param[in]  maxAttempt        The maximum attempt
 * @param[in]  objectID          The object id
 * @param[in]  userId            The user identifier
 * @param[in]  userIdLen         The user identifier length
 * @param[in]  attestation_type  The attestation type
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_WriteUserID(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    const uint8_t *userId,
    size_t userIdLen,
    const SE05x_AttestationType_t attestation_type);

/**
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] policy policy [1:kSE05x_TAG_POLICY]
 * @param[in] objectID object id [2:kSE05x_TAG_1]
 * @param[in] size size [3:kSE05x_TAG_2]
 */
smStatus_t Se05x_API_CreateCounter(
    pSe05xSession_t session_ctx, pSe05xPolicy_t policy, uint32_t objectID, uint16_t size);

/**
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 * @param[in] size size [3:kSE05x_TAG_2]
 * @param[in] value value [4:kSE05x_TAG_3]
 */
smStatus_t Se05x_API_SetCounterValue(pSe05xSession_t session_ctx, uint32_t objectID, uint16_t size, uint64_t value);

/**
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_IncCounter(pSe05xSession_t session_ctx, uint32_t objectID);

smStatus_t Se05x_API_ExportObject(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSAKeyComponent_t rsaKeyComp,
    uint8_t *data,
    size_t *pdataLen);

smStatus_t Se05x_API_ImportObject(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSAKeyComponent_t rsaKeyComp,
    const uint8_t *serializedObject,
    size_t serializedObjectLen);

smStatus_t Se05x_API_PBKDF2_extended(pSe05xSession_t session_ctx,
    uint32_t objectID,
    const uint8_t *salt,
    size_t saltLen,
    uint32_t saltID,
    uint16_t count,
    SE05x_MACAlgo_t macAlgo,
    uint16_t requestedLen,
    uint32_t derivedSessionKeyID,
    uint8_t *derivedSessionKey,
    size_t *pderivedSessionKeyLen);

/**
 * @brief      Symmetric key derivation (salt in key object)
 * Refer to ::sss_derive_key_one_go in case the salt is not available as a key object.
 *
 * @param      context           Pointer to derive key context
 * @param      saltKeyObject     Reference to salt. The salt key object must reside in the same keystore as the derive key context.
 * @param[in]  info              Input data buffer, typically with some fixed info.
 * @param[in]  infoLen           Length of info buffer in bytes.
 * @param      derivedKeyObject  Reference to a derived key
 * @param[in]  deriveDataLen     The derive data length
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_derive_key_sobj_one_go(sss_derive_key_t *context,
    sss_object_t *saltKeyObject,
    const uint8_t *info,
    size_t infoLen,
    sss_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/**
 * @param[in]   session_ctx Session Context [0:kSE05x_pSession]
 * @param[in]   memoryType  Memory Type [1:kSE05x_TAG_1]
 * @param       pfreeMem    pfree memory
 */
smStatus_t Se05x_API_GetFreeMemory(pSe05xSession_t session_ctx, SE05x_MemoryType_t memoryType, uint32_t *pfreeMem);
#endif /* SSS_APIS_INC_FSL_SSS_PYTHON_EXPORT_H_ */
