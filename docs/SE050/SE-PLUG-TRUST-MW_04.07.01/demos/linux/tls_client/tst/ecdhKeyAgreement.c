/**
 * @file ecdhKeyAgreement.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 * Copyright 2019 NXP
 *
 * This software is owned or controlled by NXP and may only be used
 * strictly in accordance with the applicable license terms.  By expressly
 * accepting such terms or by downloading, installing, activating and/or
 * otherwise using the software, you are agreeing that you have read, and
 * that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you
 * may not retain, install, activate or otherwise use the software.
 *
 * @par Description:
 * Illustrate a Diffie-Hellman key agreement operation between a Remote
 * and a Local party.
 * The Local party uses a key pair stored in the Secure Element.
 * The shared secret is established once from the perspective of the Local
 * party and once from the perspective of the Remote party. Bundling these
 * operations in one program is for illustration purposes only.
 *
 * Precondition:
 * - The first key pair been provisioned and a key reference file
 *   (...../ecc_key_kp_0_ref.pem) is available.
 * - A pem file containing the key pair representing the 'remote' entity is
 *   available (...../remote_ecc_kp.pem)
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include "sm_types.h"

#define A70CM_PROBE_EXEC_OK             0
#define A70CM_PROBE_EXEC_FAILED         1
#define A70CM_PROBE_ERR_IP_ADR_MISSING 10
#define A70CM_PROBE_ERR_CANNOT_CONNECT 11
#define A70CM_PROBE_ERR_SELECT_FAILS   12
#define A70CM_PROBE_NOT_IMPLEMENTED    20
#define A70CM_PROBE_CHECK_USAGE        21
#define A70CM_PROBE_ARG_COUNT_MISTAKE  22
#define A70CM_PROBE_FILE_OPEN_FAILED   23
#define A70CM_PROBE_FILE_PEM_READ_FAILED   24
#define A70CM_PROBE_ARG_VALUE_ERROR    25
#define A70CM_PROBE_BIT_CURVE_ERROR    26
#define A70CM_PROBE_DYN_ALLOC_ERROR    27
#define A70CM_PROBE_EXEC_HALTED        28
#define A70CM_PROBE_FILE_PEM_WRITE_FAILED  29
#define A70CM_PROBE_BUF_TOO_SMALL      30

/*
  The following macro defines a function body with the following
  function signature:

  EC_KEY *PEM_read_eckey(FILE *fp, EC_KEY **x, pem_password_cb *cb, void *u)
*/
IMPLEMENT_PEM_read_fp(eckey, EC_KEY, "EC PRIVATE KEY", ECPrivateKey)

/* App version */
const int v_major = 0;
const int v_minor = 9;
const int v_patch = 2;

static void printKey(size_t len, unsigned char* key_data);

// Ensure the following key file has been created on your system
// and the A71CH has been provisioned accordingly
// ---------------------------------------------------------------
const char *localKpRefPem = "../credentials/prime256v1/tls_client_key_ref.pem";


// Ensure the following key file has been created on your system
// ---------------------------------------------------------------
const char *remoteKpPem = "../credentials/prime256v1/tls_server_key.pem";

#define OK_STATUS      0
#define FAILURE_STATUS 1

int main()
{
    FILE *fpLocalKp = NULL;
    FILE *fpRemoteKp = NULL;
    EC_KEY *ecLocalKp = NULL;
    EC_KEY *ecRemoteKp = NULL;
    U8 secretLocal[128];
    int secretLocalLen = sizeof(secretLocal);
    U8 secretRemote[128];
    int secretRemoteLen = sizeof(secretRemote);
    size_t secretSize;
    int fieldSize = 0;
    int nStatus = 0;
    int flagSuccess = 1;
    ENGINE *e;

    printf("ecdhKeyAgreement (Rev.%d.%d.%d)\n", v_major, v_minor, v_patch);

    OpenSSL_add_all_algorithms();

    if (!(e = ENGINE_by_id("e4sss")))
    {
        fprintf(stderr, "Error finding OpenSSL Engine by id (id = %s)\n", "e4sss");
        flagSuccess = 0;
        goto leaving;
    }
    else
    {
        unsigned int logLevel = 0x05;
        fprintf(stderr, "Setting log level OpenSSL-engine %s to 0x%02X.\n", "e4sss", logLevel);
        // Illustrates setting log level of e2a71ch engine.
        // 0x04 : Error message
        // 0x02 : Debug messages
        // 0x01 : Flow messages
        // (0x07 corresponds to all, which is the default)
        ENGINE_ctrl(e, ENGINE_CMD_BASE, logLevel, NULL, NULL);
    }

    // Local Party reads ECC ref file
    fpLocalKp = fopen(localKpRefPem, "r");
    if (!fpLocalKp)
    {
        printf("Unable to open the file: %s\n", localKpRefPem);
        return A70CM_PROBE_FILE_OPEN_FAILED;
    }
    ecLocalKp = PEM_read_eckey(fpLocalKp, NULL, NULL, NULL);
    if (ecLocalKp == NULL)
    {
        printf("Failed to extract ECC key from %s.\n", localKpRefPem);
        fclose(fpLocalKp);
        return A70CM_PROBE_FILE_PEM_READ_FAILED;
    }
    fclose(fpLocalKp);

    // Remote Party reads ECC file
    fpRemoteKp = fopen(remoteKpPem, "r");
    if (!fpRemoteKp)
    {
        printf("Unable to open the file: %s\n", remoteKpPem);
        return A70CM_PROBE_FILE_OPEN_FAILED;
    }
    ecRemoteKp = PEM_read_eckey(fpRemoteKp, NULL, NULL, NULL);
    if (ecRemoteKp == NULL)
    {
        printf("Failed to extract ECC key from %s.\n", remoteKpPem);
        fclose(fpRemoteKp);
        return A70CM_PROBE_FILE_PEM_READ_FAILED;
    }
    fclose(fpRemoteKp);

    // Parties exchange the public key
    // ... this is implicit in this demo code

    // Local Party calculates the pre-master secret
    fieldSize = EC_GROUP_get_degree(EC_KEY_get0_group(ecRemoteKp));
    secretSize = (fieldSize + 7) / 8;
    if (secretSize > secretLocalLen) {return A70CM_PROBE_BUF_TOO_SMALL;}

    // In case the OpenSSL engine has been loaded, the ECDH calculation will use
    // the private key stored inside the Secure Element.
    secretLocalLen = ECDH_compute_key(secretLocal, secretSize, EC_KEY_get0_public_key(ecRemoteKp),
                        ecLocalKp, NULL);

    if (secretLocalLen <= 0)
    {
        printf("Call to ECDH_compute_key() failed with error code %d.\n", secretLocalLen);
        return A70CM_PROBE_EXEC_FAILED;
    }
    else
    {
        printf("Local party calculated shared secret of size %d:\n", secretLocalLen);
        printKey(secretLocalLen, secretLocal);
    }

    // printf("ENGINE_unregister_ECDH(e). Before\n");
    // ENGINE_unregister_ECDH(e);
    // printf("ENGINE_unregister_ECDH(e). After\n");

    printf("Start Remote party.\n");
    printf("******************.\n");

    // Remote Party calculates the pre-master secret
    secretRemoteLen = sizeof(secretRemote);
    // Calculate the size of the buffer for the shared secret
    fieldSize = EC_GROUP_get_degree(EC_KEY_get0_group(ecLocalKp));
    secretSize = (fieldSize + 7) / 8;
    if (secretSize > secretRemoteLen) {return A70CM_PROBE_BUF_TOO_SMALL;}

    // As the OpenSSL engine has been unloaded, the ECDH calculation will simply use
    // the OpenSSL SW implemnentation.
    secretRemoteLen = ECDH_compute_key(secretRemote, secretSize, EC_KEY_get0_public_key(ecLocalKp),
                        ecRemoteKp, NULL);
    if (secretRemoteLen <= 0)
    {
        printf("Call to ECDH_compute_key() failed with error code %d.\n", secretRemoteLen);
        return A70CM_PROBE_EXEC_FAILED;
    }
    else
    {
        printf("Remote party calculated shared secret of size %d:\n", secretRemoteLen);
        printKey(secretRemoteLen, secretRemote);
    }

    // Compare the two (pre-)master secrets
    if (secretLocalLen == secretRemoteLen)
    {
        int i = 0;
        for (i=0; i<secretLocalLen; i++)
        {
            if (secretLocal[i] != secretRemote[i])
            {
                flagSuccess &= 0;
                break;
            }
        }
    }
    else
    {
        flagSuccess &= 0;
    }

    printf("Appendix\n");
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    printf("ENGINE_unregister_ECDH(e). Before\n");
    ENGINE_unregister_ECDH(e);
    printf("ENGINE_unregister_ECDH(e). After\n");
#else
    printf("ENGINE_unregister_EC(e). Before\n");
    ENGINE_unregister_EC(e);
    printf("ENGINE_unregister_EC(e). After\n");
#endif
    ENGINE_finish(e);
    ENGINE_free(e);

    secretRemoteLen = ECDH_compute_key(secretRemote, secretSize, EC_KEY_get0_public_key(ecLocalKp),
                        ecRemoteKp, NULL);

    EVP_cleanup();

leaving:

    printf("\n******** ECDH Calculation. Result = %s ********\n",
        (flagSuccess == 1) ? "Pass" : "Fail");
    nStatus = (flagSuccess == 1) ? OK_STATUS : FAILURE_STATUS;

    return nStatus;
}

/* Print a hex array utility */
static void printKey(size_t len, unsigned char* arr)
{
    int i;
    for (i=0; i<(int)len; i++)
    {
        if ( (i%16 == 0) && (i != 0) ) { printf("\n"); }
        printf("%02x:", arr[i]);
    }
    printf("\n");
}
