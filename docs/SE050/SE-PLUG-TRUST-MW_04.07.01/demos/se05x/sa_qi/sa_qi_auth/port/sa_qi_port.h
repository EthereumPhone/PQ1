/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SA_QI_PORT_H__
#define __SA_QI_PORT_H__

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <fsl_sss_util_asn1_der.h>

#include <nxLog_App.h>

#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>

#include <mbedtls/asn1.h>

extern ex_sss_boot_ctx_t gex_qi_auth_ctx;

int port_getRandomNonce(uint8_t *nonce, size_t *pNonceLen);
void port_parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPucPublicKey, size_t *pucPublicKeylen);
int port_hostVerifyCertificateChain(
    uint8_t *response_buffer, size_t response_size, uint16_t pucCertOffset, uint16_t manufacturerCertLenOffset);
int port_hostVerifyChallenge(uint8_t *pPublicKey,
    size_t publicKeyLen,
    uint8_t *pCertificateChainHash,
    uint8_t *pChallengeRequest,
    uint8_t *pChallengeResponse);

#endif // __SA_QI_PORT_H__
