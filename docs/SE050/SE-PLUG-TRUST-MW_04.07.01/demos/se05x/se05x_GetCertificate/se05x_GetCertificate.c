/* Copyright 2019,2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/base64.h"
#include "mbedtls/x509_crt.h"

static ex_sss_boot_ctx_t gex_sss_se_cert;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_se_cert)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1
#define MAX_FILE_NAME_SIZE 255

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

static int convertdertopemformat(const unsigned char *int_ca_cert_der,
    size_t len_der,
    unsigned char *int_ca_cert_pem,
    int dst_buf_len,
    U16 *outlength);

void usage()
{
    LOG_W("Usage:");
    LOG_W("\tse05x_GetCertificate <keyId> <filename>");
    LOG_W("\t<keyId> should be in HEX format");
    LOG_W(
        "\t<filename> is the location where certificate will be stored in PEM "
        "format");
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    int argc            = gex_sss_argc;
    const char **argv   = gex_sss_argv;
    int ret             = 0;

    if (argc < 3) {
        usage();
        return status;
    }

    char file_name[MAX_FILE_NAME_SIZE] = {0};
    FILE *fp                           = NULL;
    strncpy(file_name, argv[2], sizeof(file_name) - 1);

    unsigned long id = strtoul(argv[1], NULL, 16);
    if (id == 0) {
        LOG_E("Parse cmd line args for id using strtoul failed");
        return kStatus_SSS_Fail;
    }

    if (id > UINT32_MAX) {
        LOG_E("Key ID invalid");
        status = kStatus_SSS_Fail;
        goto exit;
    }
    uint32_t keyId = (uint32_t)(id);

    sss_object_t obj;
    uint8_t key[1025]  = {0};
    size_t keyByteLen  = sizeof(key) - 1; // Last byte is for null termination
    size_t keyBitLen   = keyByteLen * 8;
    unsigned char *p   = NULL;
    unsigned char *end = NULL;
    size_t len         = 0;

    uint8_t pem_cert[2048] = {0};
    uint8_t *ppem_cert     = &pem_cert[0];
    U16 pem_cert_size      = 0;
    mbedtls_x509_crt certificate;

    status = sss_key_object_init(&obj, &pCtx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&obj, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_get_key(&pCtx->ks, &obj, key, &keyByteLen, &keyBitLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    mbedtls_x509_crt_init(&certificate);

    ret = mbedtls_x509_crt_parse(&certificate, (const unsigned char *)key, keyByteLen);
    if (ret != 0) {
        LOG_E("Unable to parse certificate");
        goto exit;
    }

    /* Parse the certificate ASN.1 structure to get the
    * actual length of the certificate (TBS + SignAlgo + Signature)
    * This is required when reading Trust Provisioned certificates
    * because the TP certificates could have 0 padding at the end
    * and directly converting to base64 format and writing to file
    * would result in an invalid certificate.
    */
    p   = key;
    end = key + keyByteLen;

    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }

    /* Add TAG + LEN to the total length */
    keyByteLen = len + (size_t)(p - key);

    ret = convertdertopemformat(key, keyByteLen, ppem_cert, (int)sizeof(pem_cert), &pem_cert_size);
    if (ret != 0) {
        LOG_E("Converting DER to PEM failed");
        goto exit;
    }

    fp = fopen(file_name, "wb+");
    if (fp == NULL) {
        LOG_E("Error opening file");
        goto exit;
    }

    if (fwrite(pem_cert, 1, pem_cert_size - 1, fp) != (size_t)(pem_cert_size - 1)) {
        LOG_E("Error writing file");
        goto exit;
    }

exit:
    if (fp != NULL) {
        if (fclose(fp) != 0) {
            LOG_E("fclose Error");
        }
    }
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_GetCertificate Example Success !!!...");
    }
    else {
        LOG_E("se05x_GetCertificate Example Failed !!!...");
    }
    mbedtls_x509_crt_free(&certificate);
    sss_key_object_free(&obj);
    return status;
}

static int convertdertopemformat(const unsigned char *int_ca_cert_der,
    size_t len_der,
    unsigned char *int_ca_cert_pem,
    int dst_buf_len,
    U16 *outlength)
{
    int ret            = 1;
    size_t len_out     = 0;
    const char start[] = "-----BEGIN CERTIFICATE-----\n";
    const char end[]   = "\n-----END CERTIFICATE-----\n";

    if (dst_buf_len >= (int)strlen(start)) {
        strcpy((char *)int_ca_cert_pem, start);
    }
    ret = mbedtls_base64_encode(&int_ca_cert_pem[sizeof(start) - 1],
        dst_buf_len - sizeof(start) - sizeof(end) + 1,
        &len_out,
        int_ca_cert_der,
        len_der);
    if (ret == 0 && ((dst_buf_len - sizeof(start) + 1 - len_out) >= sizeof(end))) {
        strncpy((char *)&int_ca_cert_pem[sizeof(start) - 1 + len_out], end, sizeof(end));
        *outlength = (U16)len_out + sizeof(start) + sizeof(end) - 1;
    }
    else {
        *outlength = 0;
        ret        = 1;
    }
    return ret;
}
