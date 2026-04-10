/*
 *  Simple DTLS client demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  Copyright 2019-2023 NXP
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/* clang-format off */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_SSL_CLI_C) || !defined(MBEDTLS_SSL_PROTO_DTLS) ||    \
    !defined(MBEDTLS_NET_C)  || !defined(MBEDTLS_TIMING_C) ||             \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) ||        \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_RSA_C) ||      \
    !defined(MBEDTLS_CERTS_C) || !defined(MBEDTLS_PEM_PARSE_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_SSL_CLI_C and/or MBEDTLS_SSL_PROTO_DTLS and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_TIMING_C and/or "
                   "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
                   "MBEDTLS_X509_CRT_PARSE_C and/or MBEDTLS_RSA_C and/or "
                   "MBEDTLS_CERTS_C and/or MBEDTLS_PEM_PARSE_C not defined.\n");
    return( 0 );
}
#else

#include <string.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/timing.h"

/* +S */

#ifdef TGT_A71CH
#   include "sm_printf.h"
#endif

#if SSS_HAVE_MBEDTLS_ALT_SSS
#include "sss_mbedtls.h"
#endif

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <nxLog_App.h>

#if defined(SMCOM_JRCP_V2) && SSS_HAVE_SE05X_VER_GTE_07_02
#include "smCom.h"
#include "smComJRCP.h"
#include "sm_types.h"
#endif

static ex_sss_boot_ctx_t gex_sss_demo_boot_ctx;
ex_sss_boot_ctx_t *pex_sss_demo_boot_ctx = &gex_sss_demo_boot_ctx;
static ex_sss_cloud_ctx_t gex_sss_demo_tls_ctx;
ex_sss_cloud_ctx_t *pex_sss_demo_tls_ctx = &gex_sss_demo_tls_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_demo_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1
#define EX_SSS_BOOT_DO_ERASE 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

#define SSS_PUBKEY_INDEX_CA 0x7DCCBB22 //(1u)
#define SSS_KEYPAIR_INDEX_CLIENT_PRIVATE 0x20181001 //(2u)
#define SSS_CERTIFICATE_INDEX 0x20181002 //(3u)

/*The size of the client certificate should be checked when script is used to store it in GP storage and updated here */
#define SIZE_CLIENT_CERTIFICATE 2048
/* -S */

/* Uncomment out the following line to default to IPv4 and disable IPv6 */
#define FORCE_IPV4

#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"

#ifdef FORCE_IPV4
#define SERVER_ADDR "127.0.0.1"     /* Forces IPv4 */
#else
#define SERVER_ADDR "::1"
#endif

#define MESSAGE     "Echo this"

#define READ_TIMEOUT_MS 1000
#define MAX_RETRY       5


#define DFL_DEBUG_LEVEL         1
#define DFL_CA_FILE             ""
#define DFL_FORCE_CIPHER        0
#define DFL_KEY_FILE ""
#define DFL_CRT_FILE ""
#define DFL_MIN_VERSION         -1
#define DFL_MAJ_VERSION         -1
#define DFL_CURVES              NULL

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_FS_IO)
#define USAGE_IO \
    "    ca_file=%%s          The single file containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded)\n"
#else
#define USAGE_IO \
    "    No file operations available (MBEDTLS_FS_IO not defined)\n"
#endif /* MBEDTLS_FS_IO */
#else
#define USAGE_IO ""
#endif /* MBEDTLS_X509_CRT_PARSE_C */


#define USAGE \
    "    debug_level=%%d      default: 0 (disabled)\n"      \
     USAGE_IO


#define CURVE_LIST_SIZE 20

/*
 * global options
 */
struct options
{
    int debug_level;            /* level of debugging                       */
    const char *ca_file;        /* the file with the CA certificate(s)      */
    const char *crt_file;     /* the file with the client certificate     */
    const char *key_file;     /* the file with the client key             */
    int force_ciphersuite[2]; /* protocol/ciphersuite to use, or all      */
    int min_version;            /* minimum protocol version accepted        */
    int max_version;            /* minimum protocol version accepted        */
    const char *curves;       /* list of supported elliptic curves        */
} opt;

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *) ctx);
}

// int main(int argc, char *argv[])
sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    int ret = 0, len, i;
    int client_certificate_loaded = 0;
    bool useKeysFromSM = true;
    sss_status_t ret_code;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers = "dtls_client";
    int retry_left = MAX_RETRY;
    uint8_t aclient_cer[SIZE_CLIENT_CERTIFICATE] = {0};

#if defined(MBEDTLS_ECP_C)
    mbedtls_ecp_group_id curve_list[CURVE_LIST_SIZE];
    const mbedtls_ecp_curve_info *curve_cur;
#endif

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    mbedtls_timing_delay_context timer;

    char *p, *q;

#if defined(SMCOM_JRCP_V2) && SSS_HAVE_SE05X_VER_GTE_07_02
    uint32_t start_nvmCount = 0;
    uint32_t end_nvmCount = 0;
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init( &clicert );
    mbedtls_pk_init( &pkey );
    mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(SMCOM_JRCP_V2) && SSS_HAVE_SE05X_VER_GTE_07_02
    {
        uint32_t status = kStatus_SSS_Fail;
        sss_se05x_session_t *pSe05xSession = (sss_se05x_session_t *)&pCtx->session;
        status = smComJRCP_NvmCount(pSe05xSession->s_ctx.conn_ctx, &start_nvmCount);
        if (status == SMCOM_OK) {
            mbedtls_printf("NVM count at start : %u \n", start_nvmCount);
        }
    }
#endif

    if( gex_sss_argc == 1 )
    {
    usage:
        if( ret == 0 )
            ret = 1;

        mbedtls_printf( USAGE_IO );

        mbedtls_printf("\n");
        goto exit;
    }

    opt.debug_level         = DFL_DEBUG_LEVEL;
    opt.ca_file             = DFL_CA_FILE;
    opt.crt_file            = DFL_CRT_FILE;
    opt.key_file            = DFL_KEY_FILE;
    opt.force_ciphersuite[0] = DFL_FORCE_CIPHER;
    opt.min_version         = MBEDTLS_SSL_MINOR_VERSION_3;
    opt.max_version         = MBEDTLS_SSL_MAJOR_VERSION_3;
    opt.curves              = DFL_CURVES;

    for( i = 1; i < gex_sss_argc; i++ )
    {
        p = (char *) gex_sss_argv[i];
		if ((q = strchr(p, '=')) == NULL)
			continue;
        *q++ = '\0';

        if( strcmp( p, "debug_level" ) == 0 )
        {
            opt.debug_level = atoi( q );
            if( opt.debug_level < 0 || opt.debug_level > 65535 )
                goto usage;
        }
        else if( strcmp( p, "ca_file" ) == 0 )
            opt.ca_file = q;
		else if (strcmp(p, "crt_file") == 0)
			opt.crt_file = q;
		else if (strcmp(p, "key_file") == 0)
			opt.key_file = q;
        else if( strcmp( p, "force_ciphersuite" ) == 0 )
        {
            opt.force_ciphersuite[0] = mbedtls_ssl_get_ciphersuite_id(q);

            if( opt.force_ciphersuite[0] == 0 )
            {
                ret = 2;
                goto usage;
            }
            opt.force_ciphersuite[1] = 0;
        }
        else if (strcmp(p, "curves") == 0)
            opt.curves = q;
        else
            continue;
    }

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( opt.debug_level );
#endif

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    if (useKeysFromSM) {
        sss_status_t status;

        /* doc+:initialize-key-objs */

        /* pex_sss_demo_tls_ctx->obj will have the private key handle */
        status = sss_key_object_init(&pex_sss_demo_tls_ctx->obj, &pCtx->ks);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_init for keyPair Failed...\n");
            return kStatus_SSS_Fail;
        }

        status = sss_key_object_get_handle(
            &pex_sss_demo_tls_ctx->obj, SSS_KEYPAIR_INDEX_CLIENT_PRIVATE);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_get_handle  for keyPair Failed...\n");
            return kStatus_SSS_Fail;
        }

        /* pex_sss_demo_tls_ctx->obj will have the private key handle */
        status = sss_key_object_init(&pex_sss_demo_tls_ctx->pub_obj, &pCtx->ks);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_init for Pub key Failed...\n");
            return kStatus_SSS_Fail;
        }

        /* pex_sss_demo_tls_ctx->obj will have the public key of couter part */
        status = sss_key_object_get_handle(
            &pex_sss_demo_tls_ctx->pub_obj, SSS_PUBKEY_INDEX_CA);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_get_handle  for extPubkey Failed...\n");
            return kStatus_SSS_Fail;
        }

        /* pex_sss_demo_tls_ctx->dev_cert will have the our device certificate */
        status =
            sss_key_object_init(&pex_sss_demo_tls_ctx->dev_cert, &pCtx->ks);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_init for Pub key Failed...\n");
            return kStatus_SSS_Fail;
        }

        status = sss_key_object_get_handle(
            &pex_sss_demo_tls_ctx->dev_cert, SSS_CERTIFICATE_INDEX);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_get_handle  for client Cert Failed...\n");
            return kStatus_SSS_Fail;
        }
        /* doc-:initialize-key-objs */
    }
    else {
        printf("WARNING!!!!!!!!!!!! using keys from file system");
    }


#if defined(MBEDTLS_ECP_C)
    if( opt.curves != NULL )
    {
        p = (char *)opt.curves;
        i = 0;

        if( strcmp( p, "none" ) == 0 )
        {
            curve_list[0] = MBEDTLS_ECP_DP_NONE;
        }
        else if( strcmp( p, "default" ) != 0 )
        {
            /* Leave room for a final NULL in curve list */
            while( i < CURVE_LIST_SIZE - 1 && *p != '\0' )
            {
                q = p;

                /* Terminate the current string */
                while (*p != ',' && *p != '\0')
                    p++;
                if (*p == ',')
                    *p++ = '\0';

                if( ( curve_cur = mbedtls_ecp_curve_info_from_name( q ) ) != NULL )
                {
                    curve_list[i++] = curve_cur->grp_id;
                }
                else
                {
                    mbedtls_printf("unknown curve %s\n", q);
                    mbedtls_printf("supported curves: ");
                    for (curve_cur = mbedtls_ecp_curve_list();
                         curve_cur->grp_id != MBEDTLS_ECP_DP_NONE;
                         curve_cur++ )
                    {
                        mbedtls_printf("%s ", curve_cur->name);
                    }
                    mbedtls_printf("\n");
                    goto exit;
                }
            }

            mbedtls_printf("Number of curves: %d\n", i);

            if( i == CURVE_LIST_SIZE - 1 && *p != '\0' )
            {
                mbedtls_printf( "curves list too long, maximum %d",
                                CURVE_LIST_SIZE - 1 );
                goto exit;
            }

            curve_list[i] = MBEDTLS_ECP_DP_NONE;
        }
    }
#endif /* MBEDTLS_ECP_C */


    if( opt.force_ciphersuite[0] > 0 )
    {
        const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
        ciphersuite_info =
            mbedtls_ssl_ciphersuite_from_id( opt.force_ciphersuite[0] );

        if (opt.max_version != -1 &&
            ciphersuite_info->min_minor_ver > opt.max_version )
        {
            mbedtls_printf("forced ciphersuite not allowed with this protocol version\n");
            ret = 2;
            goto usage;
        }
        if (opt.min_version != -1 &&
            ciphersuite_info->max_minor_ver < opt.min_version )
        {
            mbedtls_printf("forced ciphersuite not allowed with this protocol version\n");
            ret = 2;
            goto usage;
        }

        /* If the server selects a version that's not supported by
        * this suite, then there will be no common ciphersuite... */
        if (opt.max_version == -1 ||
            opt.max_version > ciphersuite_info->max_minor_ver )
        {
            opt.max_version = ciphersuite_info->max_minor_ver;
        }
        if( opt.min_version < ciphersuite_info->min_minor_ver )
        {
            opt.min_version = ciphersuite_info->min_minor_ver;
            /* DTLS starts with TLS 1.1 */
            if (opt.min_version < MBEDTLS_SSL_MINOR_VERSION_2)
                opt.min_version = MBEDTLS_SSL_MINOR_VERSION_2;
        }

        /* Enable RC4 if needed and not explicitly disabled */
        // if( ciphersuite_info->cipher == MBEDTLS_CIPHER_ARC4_128 )
        // {
        //     if( opt.arc4 == MBEDTLS_SSL_ARC4_DISABLED )
        //     {
        //         mbedtls_printf("forced RC4 ciphersuite with RC4 disabled\n");
        //         ret = 2;
        //         goto usage;
        //     }

        //     opt.arc4 = MBEDTLS_SSL_ARC4_ENABLED;
        // }
    }

    /*
     * 0. Load certificates
     */
    mbedtls_printf("  . Loading the CA root certificate ...");
    fflush(stdout);

#if defined(MBEDTLS_FS_IO)

    if( strlen( opt.ca_file ) ){
            if( strcmp( opt.ca_file, "none" ) == 0 ) {
                ret = 0;
            }
            else {
                ret = mbedtls_x509_crt_parse_file( &cacert, opt.ca_file );
            }
    }
    else
#endif

#if defined(MBEDTLS_CERTS_C)
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas_pem,
                                 mbedtls_test_cas_pem_len);
#else
    {
        ret = 1;
        mbedtls_printf("MBEDTLS_CERTS_C not defined.");
    }
#endif
    if (useKeysFromSM) {
        /* doc+:use-public-key-from-se */
        // for private key, we use the KEY from SE.
        mbedtls_pk_free(&cacert.pk);
        ret = sss_mbedtls_associate_pubkey(&cacert.pk, &pex_sss_demo_tls_ctx->pub_obj);
        /* doc-:use-public-key-from-se */
    }
    if (ret < 0) {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                       (unsigned int) -ret);
        goto exit;
    }

#if defined(MBEDTLS_FS_IO)
	if (strlen(opt.crt_file)) {
		if (strcmp(opt.crt_file, "none") == 0)
		{

			/* doc+:load-certificate-from-se */
			size_t KeyBitLen = SIZE_CLIENT_CERTIFICATE * 8;
			size_t KeyByteLen = SIZE_CLIENT_CERTIFICATE;

			ret_code = sss_key_store_get_key(
				&pCtx->ks, &pex_sss_demo_tls_ctx->dev_cert, aclient_cer, &KeyByteLen, &KeyBitLen);

			ret = mbedtls_x509_crt_parse_der(&clicert,
				(const unsigned char *)aclient_cer,
				sizeof(aclient_cer));
			if ((ret_code == kStatus_SSS_Success) && (ret == 0)) {
				client_certificate_loaded = 1;
			}
			/* doc-:load-certificate-from-se */
		}
		else

			ret = mbedtls_x509_crt_parse_file(&clicert, opt.crt_file);

	}
    else
#endif
#if defined(MBEDTLS_CERTS_C)
        ret = mbedtls_x509_crt_parse( &clicert,
                (const unsigned char *) mbedtls_test_cli_crt,
            mbedtls_test_cli_crt_len);
#else
    {
        ret = 1;
        mbedtls_printf("MBEDTLS_CERTS_C not defined.");
    }
#endif
    if (useKeysFromSM) {
        // for private key, we use the KEY from SE.
        mbedtls_pk_free(&clicert.pk);
    }
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                        -ret );
        goto exit;
    }


#if defined(MBEDTLS_FS_IO)
    if (useKeysFromSM) {
        /* doc+:set-handle-to-use-private-key-from-se */
        sss_mbedtls_associate_keypair(&pkey, &pex_sss_demo_tls_ctx->obj);
        /* doc-:set-handle-to-use-private-key-from-se */
    }
	else if (strlen(opt.key_file)) {
		if (strcmp(opt.key_file, "none") == 0) {
			ret = 0;
		}
		else {
			ret = mbedtls_pk_parse_keyfile(&pkey, opt.key_file, "");
		}
	}
    else
#endif
#if defined(MBEDTLS_CERTS_C)
        ret = mbedtls_pk_parse_key( &pkey,
                (const unsigned char *) mbedtls_test_cli_key,
                    mbedtls_test_cli_key_len, NULL, 0 );
#else
    {
        ret = 1;
        mbedtls_printf("MBEDTLS_CERTS_C not defined.");
    }
#endif


    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned -0x%x\n\n",
                        -ret );
        goto exit;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);

    /*
     * 1. Start the connection
     */
    mbedtls_printf("  . Connecting to udp/%s/%s...", SERVER_NAME, SERVER_PORT);
    fflush(stdout);

    if ((ret = mbedtls_net_connect(&server_fd, SERVER_ADDR,
                                   SERVER_PORT, MBEDTLS_NET_PROTO_UDP)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    mbedtls_printf("  . Setting up the DTLS structure...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    if(useKeysFromSM)
    {
        if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &clicert, &pkey ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n",
                            ret );
            goto exit;
        }
    }
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    mbedtls_ssl_conf_read_timeout(&conf, READ_TIMEOUT_MS);

#if defined(MBEDTLS_ECP_C)
    if( opt.curves != NULL &&
        strcmp( opt.curves, "default" ) != 0 )
    {
        mbedtls_ssl_conf_curves(&conf, curve_list);
    }
#endif

    if (opt.force_ciphersuite[0] != DFL_FORCE_CIPHER) {
        mbedtls_ssl_conf_ciphersuites(&conf, opt.force_ciphersuite);
    }

    if(opt.min_version != DFL_MIN_VERSION)
        mbedtls_ssl_conf_min_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.min_version );

    if(opt.max_version != DFL_MAJ_VERSION)
        mbedtls_ssl_conf_max_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.max_version );

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if (pex_sss_demo_tls_ctx->obj.cipherType == kSSS_CipherType_EC_NIST_P ||
        pex_sss_demo_tls_ctx->obj.cipherType == kSSS_CipherType_EC_NIST_K ||
        pex_sss_demo_tls_ctx->obj.cipherType == kSSS_CipherType_EC_BRAINPOOL ||
        pex_sss_demo_tls_ctx->obj.cipherType == kSSS_CipherType_EC_MONTGOMERY ||
        pex_sss_demo_tls_ctx->obj.cipherType == kSSS_CipherType_EC_TWISTED_ED)
    {
        if (useKeysFromSM) {
            /* doc+:use-private-key-for-ecdh */
            ret = sss_mbedtls_associate_ecdhctx(ssl.handshake, &pex_sss_demo_tls_ctx->obj, &pCtx->host_ks);
            /* doc-:use-private-key-for-ecdh */
        }
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd,
                        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    mbedtls_printf(" ok\n");

    /*
     * 4. Handshake
     */
    mbedtls_printf("  . Performing the DTLS handshake...");
    fflush(stdout);

    do {
        ret = mbedtls_ssl_handshake(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                       (unsigned int) -ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf("  . Verifying peer X.509 certificate...");

    /* In real life, we would have used MBEDTLS_SSL_VERIFY_REQUIRED so that the
     * handshake would not succeed if the peer's cert is bad.  Even if we used
     * MBEDTLS_SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
        char vrfy_buf[512];

        mbedtls_printf(" failed\n");

        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        mbedtls_printf("%s\n", vrfy_buf);
    } else {
        mbedtls_printf(" ok\n");
    }

    /*
     * 6. Write the echo request
     */
send_request:
    mbedtls_printf("  > Write to server:");
    fflush(stdout);

    len = sizeof(MESSAGE) - 1;

    do {
        ret = mbedtls_ssl_write(&ssl, (unsigned char *) MESSAGE, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret < 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
        goto exit;
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n\n%s\n\n", len, MESSAGE);

    /*
     * 7. Read the echo response
     */
    mbedtls_printf("  < Read from server:");
    fflush(stdout);

    len = sizeof(buf) - 1;
    memset(buf, 0, sizeof(buf));

    do {
        ret = mbedtls_ssl_read(&ssl, buf, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret <= 0) {
        switch (ret) {
            case MBEDTLS_ERR_SSL_TIMEOUT:
                mbedtls_printf(" timeout\n\n");
                if (retry_left-- > 0) {
                    goto send_request;
                }
                goto exit;

            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                mbedtls_printf(" connection was closed gracefully\n");
                ret = 0;
                goto close_notify;

            default:
                mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n\n", (unsigned int) -ret);
                goto exit;
        }
    }
    else {
        printf("\nPASS : 200 OK\n");
    }
    len = ret;
    mbedtls_printf(" %d bytes read\n\n%s\n\n", len, buf);

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    mbedtls_printf("  . Closing the connection...");

    /* No error checking, the connection might be closed already */
    do {
        ret = mbedtls_ssl_close_notify(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    ret = 0;

    mbedtls_printf(" done\n");

    /*
     * 9. Final clean-ups and exit
     */
exit:

#if defined(SMCOM_JRCP_V2) && SSS_HAVE_SE05X_VER_GTE_07_02
    {
        uint32_t status = kStatus_SSS_Fail;
        sss_se05x_session_t *pSe05xSession = (sss_se05x_session_t *)&pCtx->session;
        status = smComJRCP_NvmCount(pSe05xSession->s_ctx.conn_ctx, &end_nvmCount);
        if (status == SMCOM_OK) {
            mbedtls_printf("NVM count at end : %u \n", end_nvmCount);
        }

        /* Ignore one nvm write for rsa sign for the first time */
        if (end_nvmCount > start_nvmCount + 1) {
            mbedtls_printf("NVM write not expected\n");
        }
    }
#endif

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&server_fd);

    mbedtls_x509_crt_free(&clicert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

// #if defined(_WIN32)
//     mbedtls_printf("  + Press Enter to exit this program.\n");
//     fflush(stdout); getchar();
// #endif

    /* Shell can not handle large exit numbers -> 1 for errors */
    if (ret < 0) {
        return kStatus_SSS_Fail;
    }

    return kStatus_SSS_Success;
}
#endif /* MBEDTLS_SSL_CLI_C && MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_NET_C &&
          MBEDTLS_TIMING_C && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_RSA_C && MBEDTLS_CERTS_C &&
          MBEDTLS_PEM_PARSE_C */
