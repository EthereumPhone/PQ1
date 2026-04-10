/*
 * FreeRTOS FreeRTOS LTS Qualification Tests preview
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file core_pkcs11_test.c
 * @brief Integration tests for the corePKCS11 implementation.
 */

#include "test_execution_config.h"
#if ( CORE_PKCS11_TEST_ENABLED == 1 )

/* Standard includes. */
#include <stdlib.h>
#include <string.h>

/* corePKCS11 includes. */
#include "core_pki_utils.h"
#include "core_pkcs11.h"

/* Developer mode provisioning. */
#include "dev_mode_key_provisioning.h"

/* Test includes. */
#include "unity_fixture.h"
#include "unity.h"

/**
 *  @brief Declaring MBEDTLS_ALLOW_PRIVATE_ACCESS allows access to mbedtls "private" fields.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

/* mbedTLS includes. */
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/oid.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"

/* corePKCS11 test includes. */
#include "platform_function.h"
#include "rsa_test_credentials.h"
#include "ecdsa_test_credentials.h"

/* Test configuration includes. */
#include "test_param_config.h"

/*-----------------------------------------------------------*/

/**
 * @brief The index of the slot that should be used to open sessions for PKCS #11 tests.
 *
 * corePKCS11 utilities are also used in this test. Currenlty, the slot number has to be 0.
 */
#define PKCS11_TEST_SLOT_NUMBER                ( 0 )

/**
 * @brief Number of simultaneous tasks for multithreaded tests.
 *
 * Each task consumes both stack and heap space, which may cause memory allocation
 * failures if too many tasks are created.
 */
#define PKCS11_TEST_MULTI_THREAD_TASK_COUNT    ( 2 )

/**
 * @brief The number of iterations of the test that will run in multithread tests.
 *
 * A single iteration of Signing and Verifying may take up to a minute on some
 * boards. Ensure that PKCS11_TEST_WAIT_THREAD_TIMEOUT_MS is long enough to accommodate
 * all iterations of the loop.
 */
#define PKCS11_TEST_MULTI_THREAD_LOOP_COUNT    ( 10 )

/**
 * @brief All tasks of the SignVerifyRoundTrip_MultitaskLoop test must finish within
 * this timeout, or the test will fail.
 */
#define PKCS11_TEST_WAIT_THREAD_TIMEOUT_MS     ( 1000000UL )

/**
 * @brief The test make use of the unity TEST_PRINTF function to print log. Log function
 * is disabled if not supported. For IDT test, this function should be disabled.
 */
#ifndef TEST_PRINTF
    #define TEST_PRINTF( ... )
#endif

/**
 * @brief At least one of RSA KEY and EC KEY mechanism must be supported.
 */
#if ( PKCS11_TEST_RSA_KEY_SUPPORT == 0 ) && ( PKCS11_TEST_EC_KEY_SUPPORT == 0 )
    #error "RSA or Elliptic curve keys (or both) must be supported."
#endif

/**
 * @brief At least one of the key provisioning functions must be supported.
 */
#if ( PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT == 0 ) && ( PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT == 0 ) && ( PKCS11_TEST_PREPROVISIONED_SUPPORT == 0 )
    #error "The device must have some mechanism configured to provision the PKCS #11 stack."
#endif

/**
 * @brief Preprovision must not be tested with other provisiong method enabled.
 */
#if ( PKCS11_TEST_PREPROVISIONED_SUPPORT != 0 ) && ( ( PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT != 0 ) || ( PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT != 0 ) )
    #error "Preprovision mechanism must be tested alone without other provision mechanism enabled."
#endif

/**
 * @brief Preprovision must be tested with only one key function.
 */
#if ( PKCS11_TEST_PREPROVISIONED_SUPPORT != 0 ) && ( PKCS11_TEST_RSA_KEY_SUPPORT != 0 ) && ( PKCS11_TEST_EC_KEY_SUPPORT != 0 )
    #error "Preprovision mechanism must be tested with only one key function enabled."
#endif

/**
 * @brief Random buffer size for random number generate test.
 */
#define PKCS11_TEST_RAND_BUFFER_SIZE    ( 10 )

/**
 * @brief Test RSA certificate value length.
 */
#define CERTIFICATE_VALUE_LENGTH        ( 949 )

/**
 * @brief EC point length.
 *
 * Reference core_pkcs11_mbedtls.c for length explanation.
 */
#define PKCS11_TEST_EC_POINT_LENGTH     ( ( 32UL * 2UL ) + 1UL + 1UL + 1UL )

/*-----------------------------------------------------------*/

typedef enum CredentialsProvisioned
{
    eNone,                /* Device is not provisioned.  All credentials have been destroyed. */
    eRsaTest,             /* Provisioned using the RSA test credentials located in this file. */
    eEllipticCurveTest,   /* Provisioned using EC test credentials located in this file. */
    eClientCredential,    /* Provisioned using the credentials in aws_clientcredential_keys. */
    eGeneratedEc,         /* Provisioned using elliptic curve generated on device.  Private key unknown.  No corresponding certificate. */
    eGeneratedRsa,
    eDeliberatelyInvalid, /* Provisioned using credentials that are meant to trigger an error condition. */
    eStateUnknown         /* State of the credentials is unknown. */
} CredentialsProvisioned_t;

typedef enum provisionMethod
{
    eProvisionPreprovisioned,
    eProvisionImportPrivateKey,
    eProvisionGenerateKeyPair,
    eProvisionUnknown
} provisionMethod_t;

/* Data structure to store results of multi-thread tests. */
typedef struct MultithreadTaskParams
{
    uint32_t xTaskNumber;
    CK_RV xTestResult;
    void * pvTaskData;
} MultithreadTaskParams_t;

/* Data structure to hold sign verify multi-thread test data. */
typedef struct SignVerifyMultiThread
{
    CK_SESSION_HANDLE xSession;
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xPublicKey;
    mbedtls_ecp_keypair * pxEcdsaContext; /* Pointer to the pre-parsed ECDSA key. */
} SignVerifyMultiThread_t;

/* Data structure to hold get attribute multi-thread test data. */
typedef struct GetAttributeValueMultiThread
{
    CK_SESSION_HANDLE xSession;
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xPublicKey;
    CK_OBJECT_HANDLE xCertificate;
} GetAttributeValueMultiThread_t;

/* Test function pointer to be called by object test helper. Object test helper setup
 * credentials with different provision method and call the test function. */
typedef void ( * testFunctionPointer_t )( provisionMethod_t testProvisionMethod );

/*-----------------------------------------------------------*/

/* PKCS #11 Globals.
 * These are used to reduce setup and tear down calls. */
static CK_SESSION_HANDLE xGlobalSession = 0;
static CK_FUNCTION_LIST_PTR pxGlobalFunctionList = NULL_PTR;

/* Digest test input data. */
static CK_BYTE x896BitInput[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

/* Digest test hash data. */
static CK_BYTE xSha256HashOf896BitInput[] =
{
    0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
    0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1
};

/* Task parameters for each test thread. */
static MultithreadTaskParams_t xGlobalTaskParams[ PKCS11_TEST_MULTI_THREAD_TASK_COUNT ];

/* RSA test credentials. */
static const char cValidRSACertificate[] = RSA_TEST_VALID_CERTIFICATE;
static const char cValidRSAPublicKey[] = RSA_TEST_VALID_PUBLIC_KEY;
static const char cValidRSAPrivateKey[] = RSA_TEST_VALID_PRIVATE_KEY;

/* ECDSA test credentials. */
static const char cValidECDSACertificate[] = ECDSA_TEST_VALID_CERTIFICATE;
static const char cValidECDSAPublicKey[] = ECDSA_TEST_VALID_PUBLIC_KEY;
static const char cValidECDSAPrivateKey[] = ECDSA_TEST_VALID_PRIVATE_KEY;

/* Testing provisioning method. */
static const provisionMethod_t pkcs11TestProvisionMethod[] =
{
    #if ( PKCS11_TEST_PREPROVISIONED_SUPPORT == 1 )
        eProvisionPreprovisioned,
    #endif
    #if ( PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT == 1 )
        eProvisionImportPrivateKey,
    #endif
    #if ( PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT == 1 )
        eProvisionGenerateKeyPair
    #endif
};
static uint32_t xNumTestProvisionMethod = sizeof( pkcs11TestProvisionMethod ) / sizeof( provisionMethod_t );

static const provisionMethod_t pkcs11TestRsaProvisionMethod[] =
{
    #if ( PKCS11_TEST_PREPROVISIONED_SUPPORT == 1 )
        eProvisionPreprovisioned,
    #endif
    #if ( PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT == 1 )
        eProvisionImportPrivateKey
    #endif
};
static uint32_t xNumTestRsaProvisionMethod = sizeof( pkcs11TestRsaProvisionMethod ) / sizeof( provisionMethod_t );

/* The StartFinish test group is for General Purpose,
 * Session, Slot, and Token management functions.
 * These tests do not require provisioning. */
TEST_GROUP( Full_PKCS11_StartFinish );

/* Tests for determing the capabilities of the PKCS #11 module. */
TEST_GROUP( Full_PKCS11_Capabilities );

/* The NoKey test group is for test of cryptographic functionality
 * that do not require keys.  Covers digesting and randomness.
 * These tests do not require provisioning. */
TEST_GROUP( Full_PKCS11_NoObject );

/* The RSA test group is for tests that require RSA keys. */
TEST_GROUP( Full_PKCS11_RSA );

/* The EC test group is for tests that require elliptic curve keys. */
TEST_GROUP( Full_PKCS11_EC );

/*-----------------------------------------------------------*/

/* This helper function can be found in corePKCS11 mbedtls_utils.c
 * (https://github.com/FreeRTOS/corePKCS11/blob/main/source/dependency/3rdparty/mbedtls_utils/mbedtls_utils.c) */
extern int PKI_RSA_RSASSA_PKCS1_v15_Encode( const unsigned char * hash,
                                            size_t dst_len,
                                            unsigned char * dst );

/* This helper function can be found in corePKCS11 mbedtls_utils.c
 * (https://github.com/FreeRTOS/corePKCS11/blob/main/source/dependency/3rdparty/mbedtls_utils/mbedtls_utils.c) */
extern int convert_pem_to_der( const unsigned char * pucInput,
                               size_t xLen,
                               unsigned char * pucOutput,
                               size_t * pxOlen );

/*-----------------------------------------------------------*/

/* Test helper function to get the slot ID for testing. This function should be called
 * in the test cases only. The cryptoki must already be initialized and pxGlobalFunctionList
 * is provided. C_GetSlotList is verified in PKCS11_GetSlotList. */
static CK_SLOT_ID prvGetTestSlotId( void )
{
    CK_RV xResult;
    CK_SLOT_ID * pxSlotId = NULL;
    CK_SLOT_ID xSlotId;
    CK_ULONG xSlotCount = 0;

    TEST_ASSERT( pxGlobalFunctionList != NULL );

    /* Get the slot count. */
    xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, NULL, &xSlotCount );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to get slot count." );
    TEST_ASSERT_GREATER_THAN_MESSAGE( 0, xSlotCount, "Slot count incorrectly updated." );

    /* Allocate memory to receive the list of slots. */
    pxSlotId = pvPortMalloc( sizeof( CK_SLOT_ID ) * ( xSlotCount ) );
    TEST_ASSERT_MESSAGE( ( NULL != pxSlotId ), "Failed malloc memory for slot list." );

    /* Call C_GetSlotList again to receive all slots with tokens present. */
    xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, pxSlotId, &xSlotCount );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to get slot count." );
    xSlotId = pxSlotId[ PKCS11_TEST_SLOT_NUMBER ];

    vPortFree( pxSlotId );
    return xSlotId;
}

/*-----------------------------------------------------------*/

/* Test helper function to get the function list. This function should be called in
 * test cases only. C_GetFunctionList is verified in PKCS11_GetFunctionList test case. */
static CK_FUNCTION_LIST_PTR prvGetFunctionList( void )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;

    xResult = C_GetFunctionList( &pxFunctionList );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "C_GetFunctionList should returns CKR_OK with valid parameter." );

    /* Ensure that pxFunctionList was changed by C_GetFunctionList. */
    TEST_ASSERT_MESSAGE( ( NULL != pxFunctionList ), "C_GetFunctionList should returns valid function list pointer." );

    return pxFunctionList;
}

/*-----------------------------------------------------------*/

/* Test helper function to reset the cryptoki to uninitialized state. */
static CK_RV prvBeforeRunningTests( void )
{
    CK_RV xResult;

    /* Initialize the function list */
    xResult = C_GetFunctionList( &pxGlobalFunctionList );

    if( xResult == CKR_OK )
    {
        /* Close the last session if it was not closed already. */
        pxGlobalFunctionList->C_Finalize( NULL );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Test helper function to create and wait test thread. */
static void prvMultiThreadHelper( FRTestThreadFunction_t pvTaskFxnPtr )
{
    // uint32_t xTaskNumber;
    // int retThreadTimedJoin;
    // FRTestThreadHandle_t threadHandles[ PKCS11_TEST_MULTI_THREAD_TASK_COUNT ];

    // /* Create all the tasks. */
    // for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    // {
    //     xGlobalTaskParams[ xTaskNumber ].xTaskNumber = xTaskNumber;
    //     xGlobalTaskParams[ xTaskNumber ].xTestResult = 0;
    //     threadHandles[ xTaskNumber ] = FRTest_ThreadCreate( pvTaskFxnPtr, &( xGlobalTaskParams[ xTaskNumber ] ) );
    //     TEST_ASSERT_MESSAGE( threadHandles[ xTaskNumber ] != NULL, "Create thread failed." );
    // }

    // /* Wait for all tasks to finish. */
    // for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    // {
    //     retThreadTimedJoin = FRTest_ThreadTimedJoin( threadHandles[ xTaskNumber ], PKCS11_TEST_WAIT_THREAD_TIMEOUT_MS );

    //     if( retThreadTimedJoin != 0 )
    //     {
    //         xGlobalTaskParams[ xTaskNumber ].xTestResult = CKR_GENERAL_ERROR;
    //         TEST_PRINTF( "Waiting for task %u to finish in multi-threaded test failed %d.",
    //                      xTaskNumber, retThreadTimedJoin );
    //     }
    // }

    // /* Check the tasks' results. */
    // if( TEST_PROTECT() )
    // {
    //     for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    //     {
    //         if( xGlobalTaskParams[ xTaskNumber ].xTestResult != 0 )
    //         {
    //             TEST_PRINTF( "Multi thread task %d returned failure.",
    //                          xGlobalTaskParams[ xTaskNumber ].xTaskNumber );
    //             TEST_FAIL();
    //         }
    //     }
    // }
}

/*-----------------------------------------------------------*/

/* Test helper function to destroy the test objects. */
static CK_RV prvDestroyTestCredentials( void )
{
    CK_RV xResult = CKR_OK;
    CK_RV xDestroyResult = CKR_OK;
    CK_OBJECT_HANDLE xObject = CK_INVALID_HANDLE;
    CK_ULONG ulLabelCount = 0;

    CK_BYTE * pxPkcsLabels[] =
    {
        ( CK_BYTE * ) PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS,
        ( CK_BYTE * ) PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
        ( CK_BYTE * ) PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
        #if ( PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 )
            ( CK_BYTE * ) PKCS11_TEST_LABEL_CODE_VERIFICATION_KEY,
            ( CK_BYTE * ) PKCS11_TEST_LABEL_JITP_CERTIFICATE,
            ( CK_BYTE * ) PKCS11_TEST_LABEL_ROOT_CERTIFICATE
        #endif
    };
    CK_OBJECT_CLASS xClass[] =
    {
        CKO_CERTIFICATE,
        CKO_PRIVATE_KEY,
        CKO_PUBLIC_KEY,
        #if ( PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 )
            CKO_PUBLIC_KEY,
            CKO_CERTIFICATE,
            CKO_CERTIFICATE
        #endif
    };

    xDestroyResult = xDestroyProvidedObjects( xGlobalSession,
                                              pxPkcsLabels,
                                              xClass,
                                              sizeof( xClass ) / sizeof( CK_OBJECT_CLASS ) );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to destroy credentials." );

    for( ulLabelCount = 0;
         ulLabelCount < sizeof( xClass ) / sizeof( CK_OBJECT_CLASS );
         ulLabelCount++ )
    {
        xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                                ( char * ) pxPkcsLabels[ ulLabelCount ],
                                                strlen( ( char * ) pxPkcsLabels[ ulLabelCount ] ),
                                                xClass[ ulLabelCount ],
                                                &xObject );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Found an object after deleting it." );
        TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE == xObject ), "Object found after it was destroyed." );
    }

    return xDestroyResult;
}

/*-----------------------------------------------------------*/

/* Test helper function to provision RSA test credentials or return RSA key handles. */
static void prvProvisionRsaCredentialsWithKeyImport( CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                                     CK_OBJECT_HANDLE_PTR pxPublicKeyHandle,
                                                     CK_OBJECT_HANDLE_PTR pxCertificateHandle )
{
    CK_RV xResult;

    /* Create a public key. */
    xResult = xProvisionPublicKey( xGlobalSession,
                                   ( uint8_t * ) cValidRSAPublicKey,
                                   sizeof( cValidRSAPublicKey ),
                                   CKK_RSA,
                                   ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                   pxPublicKeyHandle );

    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create RSA public key." );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != ( *pxPublicKeyHandle ) ), "Invalid object handle returned for RSA public key." );

    /* Create a private key. */
    xResult = xProvisionPrivateKey( xGlobalSession,
                                    ( uint8_t * ) cValidRSAPrivateKey,
                                    sizeof( cValidRSAPrivateKey ),
                                    ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                    pxPrivateKeyHandle );

    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create RSA private key." );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != ( *pxPrivateKeyHandle ) ), "Invalid object handle returned for RSA private key." );

    /* Create a certificate. */
    xResult = xProvisionCertificate( xGlobalSession,
                                     ( uint8_t * ) cValidRSACertificate,
                                     sizeof( cValidRSACertificate ),
                                     ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                     pxCertificateHandle );

    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create RSA certificate." );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != ( *pxCertificateHandle ) ), "Invalid object handle returned for RSA certificate." );
}

/*-----------------------------------------------------------*/

static void prvProvisionRsaTestCredentials( provisionMethod_t testProvisionMethod,
                                            CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                            CK_OBJECT_HANDLE_PTR pxCertificateHandle,
                                            CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    if( testProvisionMethod == eProvisionImportPrivateKey )
    {
        prvProvisionRsaCredentialsWithKeyImport( pxPrivateKeyHandle, pxCertificateHandle, pxPublicKeyHandle );
    }
    else
    {
        /* Do nothing for the preprovision test cases. */
    }
}

/*-----------------------------------------------------------*/

/* Assumes that device is already provisioned at time of calling. */
static void prvFindObjectTest( CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                               CK_OBJECT_HANDLE_PTR pxCertificateHandle,
                               CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xTestObjectHandle = CK_INVALID_HANDLE;

    /* Happy Path - Find a previously created object. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            sizeof( PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) - 1,
                                            CKO_PRIVATE_KEY,
                                            pxPrivateKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to find private key after closing and reopening a session." );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != ( *pxPrivateKeyHandle ) ), "Invalid object handle found for private key." );

    /* TODO: Add the code sign key and root ca. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                            sizeof( PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS ) - 1,
                                            CKO_PUBLIC_KEY,
                                            pxPublicKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to find public key after closing and reopening a session." );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != ( *pxPublicKeyHandle ) ), "Invalid object handle found for public key key." );

    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                            sizeof( PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS ) - 1,
                                            CKO_CERTIFICATE,
                                            pxCertificateHandle );

    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to find certificate after closing and reopening a session." );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != ( *pxCertificateHandle ) ), "Invalid object handle found for certificate." );

    /* Try to find an object that has never been created. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            ( char * ) "This label doesn't exist",
                                            sizeof( "This label doesn't exist" ) - 1,
                                            CKO_PUBLIC_KEY,
                                            &xTestObjectHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Incorrect error code finding object that doesn't exist" );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE == xTestObjectHandle ), "Incorrect error code finding object that doesn't exist" );
}

/*-----------------------------------------------------------*/

static void prvProvisionEcCredentialsWithKeyImport( CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                                    CK_OBJECT_HANDLE_PTR pxCertificateHandle,
                                                    CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;

    xResult = xProvisionPublicKey( xGlobalSession,
                                   ( uint8_t * ) cValidECDSAPublicKey,
                                   sizeof( cValidECDSAPublicKey ),
                                   CKK_EC,
                                   ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                   pxPublicKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create EC public key." );
    TEST_ASSERT_MESSAGE( ( 0 != ( *pxPublicKeyHandle ) ), "Invalid object handle returned for EC public key." );

    xResult = xProvisionPrivateKey( xGlobalSession,
                                    ( uint8_t * ) cValidECDSAPrivateKey,
                                    sizeof( cValidECDSAPrivateKey ),
                                    ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                    pxPrivateKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create EC private key." );
    TEST_ASSERT_MESSAGE( ( 0 != ( *pxPrivateKeyHandle ) ), "Invalid object handle returned for EC private key." );

    xResult = xProvisionCertificate( xGlobalSession,
                                     ( uint8_t * ) cValidECDSACertificate,
                                     sizeof( cValidECDSACertificate ),
                                     ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                     pxCertificateHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create EC certificate." );
    TEST_ASSERT_MESSAGE( ( 0 != ( *pxCertificateHandle ) ), "Invalid object handle returned for EC certificate." );
}

/*-----------------------------------------------------------*/

void prvProvisionEcCredentialsWithGenerateKeyPair( CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                                   CK_OBJECT_HANDLE_PTR pxCertificateHandle,
                                                   CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;
    CK_ATTRIBUTE xTemplate;
    CK_KEY_TYPE xKeyType = 0;
    CK_BBOOL xProvisionKeyNeeded = CK_FALSE;

    /* Check if there is an EC private key in there already. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            sizeof( PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) - 1,
                                            CKO_PRIVATE_KEY,
                                            pxPrivateKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to find private key." );
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                            sizeof( PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS ) - 1,
                                            CKO_PUBLIC_KEY,
                                            pxPublicKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to find public key." );

    if( *pxPrivateKeyHandle != CK_INVALID_HANDLE )
    {
        xTemplate.type = CKA_KEY_TYPE;
        xTemplate.pValue = &xKeyType;
        xTemplate.ulValueLen = sizeof( CK_KEY_TYPE );
        xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, *pxPrivateKeyHandle, &xTemplate, 1 );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to find private key's type." );

        if( xKeyType != CKK_EC )
        {
            xProvisionKeyNeeded = CK_TRUE;
        }
    }

    if( *pxPrivateKeyHandle == CK_INVALID_HANDLE )
    {
        xProvisionKeyNeeded = CK_TRUE;
    }

    if( xProvisionKeyNeeded == CK_TRUE )
    {
        xResult = xProvisionGenerateKeyPairEC( xGlobalSession, ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS, ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS, pxPrivateKeyHandle, pxPublicKeyHandle );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to generate key pair." );
        TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != ( *pxPrivateKeyHandle ) ), "Invalid object handle returned for EC private key." );
        TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != ( *pxPublicKeyHandle ) ), "Invalid object handle returned for EC public key." );
    }

    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                            sizeof( PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS ) - 1,
                                            CKO_CERTIFICATE,
                                            pxCertificateHandle );

    /* NOTE: This certificate is for object storage and retrieval purposes only, and does not correspond to the key pair generated. */
    if( *pxCertificateHandle == CK_INVALID_HANDLE )
    {
        xResult = xProvisionCertificate( xGlobalSession,
                                         ( uint8_t * ) cValidECDSACertificate,
                                         sizeof( cValidECDSACertificate ),
                                         ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                         pxCertificateHandle );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create EC certificate." );
        TEST_ASSERT_MESSAGE( ( 0 != ( *pxCertificateHandle ) ), "Invalid object handle returned for EC certificate." );
    }
}

/*-----------------------------------------------------------*/

static void prvProvisionEcTestCredentials( provisionMethod_t testProvisionMethod,
                                           CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                           CK_OBJECT_HANDLE_PTR pxCertificateHandle,
                                           CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    if( testProvisionMethod == eProvisionImportPrivateKey )
    {
        prvProvisionEcCredentialsWithKeyImport( pxPrivateKeyHandle, pxCertificateHandle, pxPublicKeyHandle );
    }
    else if( testProvisionMethod == eProvisionGenerateKeyPair )
    {
        prvProvisionEcCredentialsWithGenerateKeyPair( pxPrivateKeyHandle, pxCertificateHandle, pxPublicKeyHandle );
    }
    else
    {
        /* Do nothing for the preprovision test cases. */
    }
}

/*-----------------------------------------------------------*/

/* RSA object test helper to run the test function with all enabled provisioning method. */
static void prvRsaObjectTestHelper( testFunctionPointer_t testFunction )
{
    volatile uint32_t provisionIndex;
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xCertificateHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;

    for( provisionIndex = 0; provisionIndex < xNumTestRsaProvisionMethod; provisionIndex++ )
    {
        if( TEST_PROTECT() )
        {
            if( pkcs11TestRsaProvisionMethod[ provisionIndex ] != eProvisionPreprovisioned )
            {
                /* Destory previous provisioned credentials. */
                prvDestroyTestCredentials();

                prvProvisionRsaTestCredentials( pkcs11TestRsaProvisionMethod[ provisionIndex ],
                                                &xPrivateKeyHandle,
                                                &xCertificateHandle,
                                                &xPublicKeyHandle );
            }

            testFunction( pkcs11TestRsaProvisionMethod[ provisionIndex ] );
        }
        else
        {
            /* Break the provision loop if test failed. */
            break;
        }
    }
}

/*-----------------------------------------------------------*/

/* EC object test helper to run the test function with all enabled provisioning method. */
static void prvEcObjectTestHelper( testFunctionPointer_t testFunction )
{
    volatile uint32_t provisionIndex;
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xCertificateHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;

    for( provisionIndex = 0; provisionIndex < xNumTestProvisionMethod; provisionIndex++ )
    {
        if( TEST_PROTECT() )
        {
            if( pkcs11TestProvisionMethod[ provisionIndex ] != eProvisionPreprovisioned )
            {
                /* Destory previous provisioned credentials. */
                prvDestroyTestCredentials();

                prvProvisionEcTestCredentials( pkcs11TestProvisionMethod[ provisionIndex ],
                                               &xPrivateKeyHandle,
                                               &xCertificateHandle,
                                               &xPublicKeyHandle );
            }

            testFunction( pkcs11TestProvisionMethod[ provisionIndex ] );
        }
        else
        {
            /* Break the provision loop if test failed. */
            break;
        }
    }
}

/*--------------------------------------------------------*/
/*-------------- StartFinish Tests ---------------------- */
/*--------------------------------------------------------*/

TEST_SETUP( Full_PKCS11_StartFinish )
{
}

/*-----------------------------------------------------------*/

TEST_TEAR_DOWN( Full_PKCS11_StartFinish )
{
}

/*-----------------------------------------------------------*/

TEST_GROUP_RUNNER( Full_PKCS11_StartFinish )
{
    RUN_TEST_CASE( Full_PKCS11_StartFinish, PKCS11_StartFinish_FirstTest );
    RUN_TEST_CASE( Full_PKCS11_StartFinish, PKCS11_GetFunctionList );
    RUN_TEST_CASE( Full_PKCS11_StartFinish, PKCS11_InitializeFinalize );
    RUN_TEST_CASE( Full_PKCS11_StartFinish, PKCS11_GetSlotList );
    RUN_TEST_CASE( Full_PKCS11_StartFinish, PKCS11_OpenSessionCloseSession );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_StartFinish, PKCS11_StartFinish_FirstTest )
{
    CK_RV xResult;

    /* Finalize the PKCS #11 module to get it in a known state.
     * Set up the PKCS #11 function list pointer. */
    xResult = prvBeforeRunningTests();

    /* prvBeforeRunningTests finalizes the PKCS #11 modules so that tests will start
     * in a known state.  It is OK if the module was not previously initialized. */
    if( xResult == CKR_CRYPTOKI_NOT_INITIALIZED )
    {
        xResult = CKR_OK;
    }

    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Setup for the PKCS #11 routine failed.  Test module will start in an unknown state." );
}

/*-----------------------------------------------------------*/

/* C_GetFunctionList is the only Cryptoki function which an application may
 * call before calling C_Initialize. It is tested as first test. */
TEST( Full_PKCS11_StartFinish, PKCS11_GetFunctionList )
{
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_RV xResult;

    /* Call the C_GetFunctionList with NULL parameters. */
    xResult = C_GetFunctionList( NULL );
    TEST_ASSERT_MESSAGE( ( CKR_ARGUMENTS_BAD == xResult ), "CKR_ARGUMENTS_BAD should be returned if C_GetFunctionList is called with NULL pointer." );

    /* Call the C_GetFunctionList with valid parameters. */
    xResult = C_GetFunctionList( &pxFunctionList );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "C_GetFunctionList should returns CKR_OK with valid parameter." );

    /* Ensure that pxFunctionList was changed by C_GetFunctionList. */
    TEST_ASSERT_MESSAGE( ( NULL != pxFunctionList ), "C_GetFunctionList should returns valid function list pointer." );
}

/*-----------------------------------------------------------*/

/* C_Initialize initialize the Cryptoki library. C_Finalize is called to indicate
 * that an application is finished with the Cryptoki library. They are required by
 * other PKCS11 APIs. This test validate the implementaion of C_Initialize and C_Finalize
 * with valid/invalid parameters and function call order. */
TEST( Full_PKCS11_StartFinish, PKCS11_InitializeFinalize )
{
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_RV xResult;

    xResult = C_GetFunctionList( &pxFunctionList );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to get function list." );
    TEST_ASSERT_MESSAGE( ( NULL != pxFunctionList ), "Invalid function list pointer." );

    xResult = xInitializePKCS11();
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 module." );

    if( TEST_PROTECT() )
    {
        /* Call initialize a second time.  Since this call may be made many times,
         * it is important that PKCS #11 implementations be tolerant of multiple calls. */
        xResult = xInitializePKCS11();
        TEST_ASSERT_MESSAGE( ( CKR_CRYPTOKI_ALREADY_INITIALIZED == xResult ), "Second PKCS #11 module initialization. " );

        /* C_Finalize should fail if pReserved isn't NULL. */
        xResult = pxFunctionList->C_Finalize( ( CK_VOID_PTR ) 0x1234 );
        TEST_ASSERT_MESSAGE( ( CKR_ARGUMENTS_BAD == xResult ), "Negative Test: Finalize with invalid argument." );

        /* C_Finalize with pReserved is NULL should return CKR_OK if C_Initalize is called successfully before. */
        xResult = pxFunctionList->C_Finalize( NULL );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Finalize failed." );

        /* Call C_Finalize a second time. Since C_Finalize may be called multiple times,
         * it is important that the PKCS #11 module is tolerant of multiple calls. */
        xResult = pxFunctionList->C_Finalize( NULL );
        TEST_ASSERT_MESSAGE( ( CKR_CRYPTOKI_NOT_INITIALIZED == xResult ), "Second PKCS #11 finalization failed." );
    }
    else
    {
        /* Run the finalize again in case test abort. */
        ( void ) pxFunctionList->C_Finalize( NULL );
    }
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_StartFinish, PKCS11_GetSlotList )
{
    CK_RV xResult;
    CK_SLOT_ID * pxSlotId = NULL;
    CK_ULONG xSlotCount = 0;
    CK_ULONG xExtraSlotCount = 0;

    /* Get the function list. */
    pxGlobalFunctionList = prvGetFunctionList();

    xResult = xInitializePKCS11();
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 module." );

    /* Happy path test. */
    /* When a NULL slot pointer is passed in, the number of slots should be updated. */
    xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, NULL, &xSlotCount );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to get slot count." );
    TEST_ASSERT_GREATER_THAN_MESSAGE( 0, xSlotCount, "Slot count incorrectly updated." );

    /* Allocate memory to receive the list of slots, plus one extra. */
    pxSlotId = pvPortMalloc( sizeof( CK_SLOT_ID ) * ( xSlotCount + 1 ) );
    TEST_ASSERT_MESSAGE( ( NULL != pxSlotId ), "Failed malloc memory for slot list." );

    if( TEST_PROTECT() )
    {
        /* Call C_GetSlotList again to receive all slots with tokens present. */
        xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, pxSlotId, &xSlotCount );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to get slot count." );

        /* Off the happy path. */
        /* Make sure that number of slots returned is updated when extra buffer room exists. */
        xExtraSlotCount = xSlotCount + 1;
        xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, pxSlotId, &xExtraSlotCount );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to get slot list." );
        TEST_ASSERT_MESSAGE( ( xSlotCount == xExtraSlotCount ), "Failed to update the number of slots." );

        /* Claim that the buffer to receive slots is too small. */
        xSlotCount = 0;
        xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, pxSlotId, &xSlotCount );
        TEST_ASSERT_MESSAGE( ( CKR_BUFFER_TOO_SMALL == xResult ), "Negative Test: Improper handling of too-small slot buffer." );

        xResult = pxGlobalFunctionList->C_Finalize( NULL );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Finalize failed." );
    }
    else
    {
        /* Run the finalize again in case test abort. */
        ( void ) pxGlobalFunctionList->C_Finalize( NULL );
    }

    /* Free previous allocated memory. */
    vPortFree( pxSlotId );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_StartFinish, PKCS11_OpenSessionCloseSession )
{
    CK_SLOT_ID xSlotId = 0;
    CK_SESSION_HANDLE xSession = 0;
    CK_RV xResult = CKR_OK;

    /* Get function list. */
    pxGlobalFunctionList = prvGetFunctionList();

    /* Initialize PKCS11. */
    xResult = xInitializePKCS11();
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 module." );

    if( TEST_PROTECT() )
    {
        /* Get test slot ID. */
        xSlotId = prvGetTestSlotId();

        /* Open session with valid parameters should return CKR_OK. */
        xResult = pxGlobalFunctionList->C_OpenSession( xSlotId,
                                                       CKF_SERIAL_SESSION, /* This flag is mandatory for PKCS #11 legacy reasons. */
                                                       NULL,               /* Application defined pointer. */
                                                       NULL,               /* Callback function. */
                                                       &xSession );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to open session." );

        xResult = pxGlobalFunctionList->C_CloseSession( xSession );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to close session." );

        xResult = pxGlobalFunctionList->C_Finalize( NULL );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Finalize failed." );

        /* Negative tests. */
        /* Try to open a session without having initialized the module. */
        xResult = pxGlobalFunctionList->C_OpenSession( xSlotId,
                                                       CKF_SERIAL_SESSION, /* This flag is mandatory for PKCS #11 legacy reasons. */
                                                       NULL,               /* Application defined pointer. */
                                                       NULL,               /* Callback function. */
                                                       &xSession );
        TEST_ASSERT_MESSAGE( ( CKR_CRYPTOKI_NOT_INITIALIZED == xResult ),
                             "Negative Test: Opened a session before initializing module." );
    }
    else
    {
        /* Run the finalize again in case test abort. */
        ( void ) pxGlobalFunctionList->C_Finalize( NULL );
    }
}

/*--------------------------------------------------------*/
/*-------------- Capabilities Tests --------------------- */
/*--------------------------------------------------------*/

TEST_SETUP( Full_PKCS11_Capabilities )
{
    CK_RV xResult;

    xResult = xInitializePKCS11();
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 module." );
    xResult = xInitializePkcs11Session( &xGlobalSession );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to open PKCS #11 session." );
}

/*-----------------------------------------------------------*/

TEST_TEAR_DOWN( Full_PKCS11_Capabilities )
{
    CK_RV xResult;

    xResult = pxGlobalFunctionList->C_CloseSession( xGlobalSession );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to close session." );
    xResult = pxGlobalFunctionList->C_Finalize( NULL );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to finalize session." );
}

/*-----------------------------------------------------------*/

TEST_GROUP_RUNNER( Full_PKCS11_Capabilities )
{
    /* Reset the cryptoki to uninitialize state. */
    prvBeforeRunningTests();

    RUN_TEST_CASE( Full_PKCS11_Capabilities, PKCS11_Capabilities );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_Capabilities, PKCS11_Capabilities )
{
    CK_RV xResult = 0;
    CK_SLOT_ID xSlotId;
    CK_MECHANISM_INFO MechanismInfo = { 0 };

    /* Determine the number of slots. */
    xSlotId = prvGetTestSlotId();

    /* Check for RSA PKCS #1 signing support. */
    xResult = pxGlobalFunctionList->C_GetMechanismInfo( xSlotId, CKM_RSA_PKCS, &MechanismInfo );
    TEST_ASSERT_TRUE_MESSAGE( ( CKR_OK == xResult || CKR_MECHANISM_INVALID == xResult ),
                              "C_GetMechanismInfo CKM_RSA_PKCS returns unexpected value." );

    if( CKR_OK == xResult )
    {
        TEST_ASSERT_TRUE( 0 != ( CKF_SIGN & MechanismInfo.flags ) );

        TEST_ASSERT_TRUE( MechanismInfo.ulMaxKeySize >= pkcs11RSA_2048_MODULUS_BITS &&
                          MechanismInfo.ulMinKeySize <= pkcs11RSA_2048_MODULUS_BITS );

        /* Check for pre-padded signature verification support. This is required
         * for round-trip testing. */
        xResult = pxGlobalFunctionList->C_GetMechanismInfo( xSlotId, CKM_RSA_X_509, &MechanismInfo );
        TEST_ASSERT_TRUE( CKR_OK == xResult );

        TEST_ASSERT_TRUE( 0 != ( CKF_VERIFY & MechanismInfo.flags ) );

        TEST_ASSERT_TRUE( MechanismInfo.ulMaxKeySize >= pkcs11RSA_2048_MODULUS_BITS &&
                          MechanismInfo.ulMinKeySize <= pkcs11RSA_2048_MODULUS_BITS );

        TEST_PRINTF( "%s", "The PKCS #11 module supports RSA signing." );
    }

    /* Check for ECDSA support, if applicable. */
    xResult = pxGlobalFunctionList->C_GetMechanismInfo( xSlotId, CKM_ECDSA, &MechanismInfo );
    TEST_ASSERT_TRUE( CKR_OK == xResult || CKR_MECHANISM_INVALID == xResult );

    if( CKR_OK == xResult )
    {
        TEST_ASSERT_TRUE( 0 != ( ( CKF_SIGN | CKF_VERIFY ) & MechanismInfo.flags ) );

        TEST_ASSERT_TRUE( MechanismInfo.ulMaxKeySize >= pkcs11ECDSA_P256_KEY_BITS &&
                          MechanismInfo.ulMinKeySize <= pkcs11ECDSA_P256_KEY_BITS );

        TEST_PRINTF( "%s", "The PKCS #11 module supports ECDSA." );
    }

    #if ( PKCS11_TEST_PREPROVISIONED_SUPPORT != 1 )
        /* Check for elliptic-curve key generation support. */
        xResult = pxGlobalFunctionList->C_GetMechanismInfo( xSlotId, CKM_EC_KEY_PAIR_GEN, &MechanismInfo );
        TEST_ASSERT_TRUE( CKR_OK == xResult || CKR_MECHANISM_INVALID == xResult );

        if( CKR_OK == xResult )
        {
            TEST_ASSERT_TRUE( 0 != ( CKF_GENERATE_KEY_PAIR & MechanismInfo.flags ) );

            TEST_ASSERT_TRUE( MechanismInfo.ulMaxKeySize >= pkcs11ECDSA_P256_KEY_BITS &&
                              MechanismInfo.ulMinKeySize <= pkcs11ECDSA_P256_KEY_BITS );

            TEST_PRINTF( "%s", "The PKCS #11 module supports elliptic-curve key generation." );
        }
    #endif /* if ( PKCS11_TEST_PREPROVISIONED_SUPPORT != 1 ) */

    /* SHA-256 support is required. */
    xResult = pxGlobalFunctionList->C_GetMechanismInfo( xSlotId, CKM_SHA256, &MechanismInfo );
    TEST_ASSERT_TRUE( CKR_OK == xResult );
    TEST_ASSERT_TRUE( 0 != ( CKF_DIGEST & MechanismInfo.flags ) );

    /* Report on static configuration for key import support. */
    #if ( 1 == PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT )
        TEST_PRINTF( "%s", "The PKCS #11 module supports private key import." );
    #endif
}

/*--------------------------------------------------------*/
/*-------------- No Object Tests ------------------------ */
/*--------------------------------------------------------*/

TEST_SETUP( Full_PKCS11_NoObject )
{
    CK_RV xResult;

    xResult = xInitializePKCS11();
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 module." );

    xResult = xInitializePkcs11Session( &xGlobalSession );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to open PKCS #11 session." );
}

/*-----------------------------------------------------------*/

TEST_TEAR_DOWN( Full_PKCS11_NoObject )
{
    CK_RV xResult;

    xResult = pxGlobalFunctionList->C_CloseSession( xGlobalSession );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to close session." );

    xResult = pxGlobalFunctionList->C_Finalize( NULL );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to finalize session." );
}

/*-----------------------------------------------------------*/

TEST_GROUP_RUNNER( Full_PKCS11_NoObject )
{
    /* Reset the cryptoki to uninitialize state. */
    prvBeforeRunningTests();

    RUN_TEST_CASE( Full_PKCS11_NoObject, PKCS11_Digest );
    RUN_TEST_CASE( Full_PKCS11_NoObject, PKCS11_Digest_ErrorConditions );
    RUN_TEST_CASE( Full_PKCS11_NoObject, PKCS11_GenerateRandom );
    RUN_TEST_CASE( Full_PKCS11_NoObject, PKCS11_GenerateRandomMultiThread );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_NoObject, PKCS11_Digest )
{
    CK_RV xResult = 0;

    CK_MECHANISM xDigestMechanism;

    CK_BYTE xDigestResult[ pkcs11SHA256_DIGEST_LENGTH ] = { 0 };
    CK_ULONG xDigestLength = 0;

    /* Hash with SHA256 */
    xDigestMechanism.mechanism = CKM_SHA256;

    xResult = pxGlobalFunctionList->C_DigestInit( xGlobalSession, &xDigestMechanism );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );

    /* Subtract one because this hash was performed on the characters without the null terminator. */
    xResult = pxGlobalFunctionList->C_DigestUpdate( xGlobalSession, x896BitInput, sizeof( x896BitInput ) - 1 );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );

    /* Call C_DigestFinal on a NULL buffer to get the buffer length required. */
    xResult = pxGlobalFunctionList->C_DigestFinal( xGlobalSession, NULL, &xDigestLength );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );
    TEST_ASSERT_EQUAL( pkcs11SHA256_DIGEST_LENGTH, xDigestLength );

    xResult = pxGlobalFunctionList->C_DigestFinal( xGlobalSession, xDigestResult, &xDigestLength );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );
    TEST_ASSERT_EQUAL_INT8_ARRAY( xSha256HashOf896BitInput, xDigestResult, pkcs11SHA256_DIGEST_LENGTH );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_NoObject, PKCS11_Digest_ErrorConditions )
{
    CK_RV xResult = 0;
    CK_MECHANISM xDigestMechanism;
    CK_BYTE xDigestResult[ pkcs11SHA256_DIGEST_LENGTH ] = { 0 };
    CK_ULONG xDigestLength = 0;

    /* Make sure that no NULL pointers in functions to be called in this test. */
    TEST_ASSERT_NOT_EQUAL( NULL, pxGlobalFunctionList->C_DigestInit );
    TEST_ASSERT_NOT_EQUAL( NULL, pxGlobalFunctionList->C_DigestUpdate );
    TEST_ASSERT_NOT_EQUAL( NULL, pxGlobalFunctionList->C_DigestFinal );

    /* Invalid hash mechanism. */
    xDigestMechanism.mechanism = 0x253; /*253 doesn't correspond to anything. */

    xResult = pxGlobalFunctionList->C_DigestInit( xGlobalSession, &xDigestMechanism );
    TEST_ASSERT_EQUAL( CKR_MECHANISM_INVALID, xResult );

    /* Null Session. */
    xDigestMechanism.mechanism = CKM_SHA256;
    xResult = pxGlobalFunctionList->C_DigestInit( ( CK_SESSION_HANDLE ) NULL, &xDigestMechanism );
    TEST_ASSERT_EQUAL( CKR_SESSION_HANDLE_INVALID, xResult );

    /* Make sure that digest update fails if DigestInit did not succeed. */
    xResult = pxGlobalFunctionList->C_DigestUpdate( xGlobalSession, x896BitInput, sizeof( x896BitInput ) - 1 );
    TEST_ASSERT_EQUAL( CKR_OPERATION_NOT_INITIALIZED, xResult );

    /* Initialize the session properly. */
    xResult = pxGlobalFunctionList->C_DigestInit( xGlobalSession, &xDigestMechanism );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );

    /* Try to update digest with a NULL session handle. */
    xResult = pxGlobalFunctionList->C_DigestUpdate( ( CK_SESSION_HANDLE ) NULL, x896BitInput, sizeof( x896BitInput ) - 1 );
    TEST_ASSERT_EQUAL( CKR_SESSION_HANDLE_INVALID, xResult );

    /* DigestUpdate correctly.  Note that digest is not terminated because we didn't tell the session handle last time. */
    xResult = pxGlobalFunctionList->C_DigestUpdate( xGlobalSession, x896BitInput, sizeof( x896BitInput ) - 1 );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );

    /* Call C_DigestFinal on a buffer that is too small. */
    xDigestLength = pkcs11SHA256_DIGEST_LENGTH - 1;
    xResult = pxGlobalFunctionList->C_DigestFinal( xGlobalSession, xDigestResult, &xDigestLength );
    TEST_ASSERT_EQUAL( CKR_BUFFER_TOO_SMALL, xResult );

    /* Call C_DigestFinal on a NULL session handle. */
    xDigestLength = pkcs11SHA256_DIGEST_LENGTH;
    xResult = pxGlobalFunctionList->C_DigestFinal( ( CK_SESSION_HANDLE ) NULL, xDigestResult, &xDigestLength );
    TEST_ASSERT_EQUAL( CKR_SESSION_HANDLE_INVALID, xResult );

    /* Call C_DigestFinal on a proper buffer size. Note that Digest is not terminated if error is "buffer too small" or if session handle wasn't present. */
    xDigestLength = pkcs11SHA256_DIGEST_LENGTH;
    xResult = pxGlobalFunctionList->C_DigestFinal( xGlobalSession, xDigestResult, &xDigestLength );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );
    TEST_ASSERT_EQUAL_INT8_ARRAY( xSha256HashOf896BitInput, xDigestResult, pkcs11SHA256_DIGEST_LENGTH );

    /* Call C_DigestUpdate after the digest operation has been completed. */
    xResult = pxGlobalFunctionList->C_DigestUpdate( xGlobalSession, x896BitInput, sizeof( x896BitInput ) - 1 );
    TEST_ASSERT_EQUAL( CKR_OPERATION_NOT_INITIALIZED, xResult );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_NoObject, PKCS11_GenerateRandom )
{
    CK_RV xResult = 0;
    uint32_t xSameSession = 0;
    uint32_t xDifferentSessions = 0;
    int i;

    CK_BYTE xBuf1[ PKCS11_TEST_RAND_BUFFER_SIZE ];
    CK_BYTE xBuf2[ PKCS11_TEST_RAND_BUFFER_SIZE ];
    CK_BYTE xBuf3[ PKCS11_TEST_RAND_BUFFER_SIZE ];

    /* Generate random bytes twice. */
    if( CKR_OK == xResult )
    {
        xResult = pxGlobalFunctionList->C_GenerateRandom( xGlobalSession, xBuf1, PKCS11_TEST_RAND_BUFFER_SIZE );
    }

    if( CKR_OK == xResult )
    {
        xResult = pxGlobalFunctionList->C_GenerateRandom( xGlobalSession, xBuf2, PKCS11_TEST_RAND_BUFFER_SIZE );
    }

    if( CKR_OK == xResult )
    {
        /* Close the session and PKCS #11 module */
        if( NULL != pxGlobalFunctionList )
        {
            ( void ) pxGlobalFunctionList->C_CloseSession( xGlobalSession );
        }
    }

    /* Re-open PKCS #11 session. */
    xResult = xInitializePkcs11Session( &xGlobalSession );

    if( CKR_OK == xResult )
    {
        xResult = pxGlobalFunctionList->C_GenerateRandom( xGlobalSession, xBuf3, PKCS11_TEST_RAND_BUFFER_SIZE );
    }

    /* Check that the result is good. */
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "C_GenerateRandom returns unexpected value." );

    /* Check that the random bytes generated within session
     * and between initializations of PKCS module are not the same. */
    for( i = 0; i < PKCS11_TEST_RAND_BUFFER_SIZE; i++ )
    {
        if( xBuf1[ i ] == xBuf2[ i ] )
        {
            xSameSession++;
        }

        if( xBuf1[ i ] == xBuf3[ i ] )
        {
            xDifferentSessions++;
        }
    }

    if( ( xSameSession > 1 ) || ( xDifferentSessions > 1 ) )
    {
        TEST_PRINTF( "First Random Bytes: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                     xBuf1[ 0 ], xBuf1[ 1 ], xBuf1[ 2 ], xBuf1[ 3 ], xBuf1[ 4 ],
                     xBuf1[ 5 ], xBuf1[ 6 ], xBuf1[ 7 ], xBuf1[ 8 ], xBuf1[ 9 ] );

        TEST_PRINTF( "Second Set of Random Bytes: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                     xBuf2[ 0 ], xBuf2[ 1 ], xBuf2[ 2 ], xBuf2[ 3 ], xBuf2[ 4 ],
                     xBuf2[ 5 ], xBuf2[ 6 ], xBuf2[ 7 ], xBuf2[ 8 ], xBuf2[ 9 ] );

        TEST_PRINTF( "Third Set of Random Bytes:  %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                     xBuf3[ 0 ], xBuf3[ 1 ], xBuf3[ 2 ], xBuf3[ 3 ], xBuf3[ 4 ],
                     xBuf3[ 5 ], xBuf3[ 6 ], xBuf3[ 7 ], xBuf3[ 8 ], xBuf3[ 9 ] );
    }

    TEST_ASSERT_LESS_THAN( 2, xSameSession );
    TEST_ASSERT_LESS_THAN( 2, xDifferentSessions );
}

/*-----------------------------------------------------------*/

/* Thread function of generateRandomMultiThread test. */
static void prvGenerateRandomMultiThreadTask( void * pvParameters )
{
    MultithreadTaskParams_t * pxMultiTaskParam = pvParameters;
    uint32_t xCount;
    CK_RV xResult;
    CK_BYTE xRandomData[ PKCS11_TEST_RAND_BUFFER_SIZE ];
    CK_SESSION_HANDLE xSession;

    memcpy( &xSession, pxMultiTaskParam->pvTaskData, sizeof( CK_SESSION_HANDLE ) );

    for( xCount = 0; xCount < PKCS11_TEST_MULTI_THREAD_LOOP_COUNT; xCount++ )
    {
        xResult = pxGlobalFunctionList->C_GenerateRandom( xSession,
                                                          xRandomData,
                                                          sizeof( xRandomData ) );

        if( xResult != CKR_OK )
        {
            TEST_PRINTF( "GenerateRandom multi-thread task failed.  Error: %ld ", xResult );
            break;
        }
    }

    /* Report the result of the loop. */
    pxMultiTaskParam->xTestResult = xResult;
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_NoObject, PKCS11_GenerateRandomMultiThread )
{
    uint32_t xTaskNumber;
    CK_SESSION_HANDLE xSessionHandle[ PKCS11_TEST_MULTI_THREAD_TASK_COUNT ];

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xInitializePkcs11Session( &xSessionHandle[ xTaskNumber ] );
        xGlobalTaskParams[ xTaskNumber ].pvTaskData = &xSessionHandle[ xTaskNumber ];
    }

    prvMultiThreadHelper( prvGenerateRandomMultiThreadTask );

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        pxGlobalFunctionList->C_CloseSession( xSessionHandle[ xTaskNumber ] );
    }
}

/*--------------------------------------------------------*/
/*-------------- RSA Tests ------------------------------ */
/*--------------------------------------------------------*/

TEST_SETUP( Full_PKCS11_RSA )
{
    CK_RV xResult;

    xResult = xInitializePKCS11();
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 module." );

    xResult = xInitializePkcs11Session( &xGlobalSession );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to open PKCS #11 session." );
}

/*-----------------------------------------------------------*/

TEST_TEAR_DOWN( Full_PKCS11_RSA )
{
    CK_RV xResult;

    xResult = pxGlobalFunctionList->C_CloseSession( xGlobalSession );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to close session." );

    xResult = pxGlobalFunctionList->C_Finalize( NULL );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to finalize session." );
}

/*-----------------------------------------------------------*/

TEST_GROUP_RUNNER( Full_PKCS11_RSA )
{
    #if ( PKCS11_TEST_RSA_KEY_SUPPORT == 1 )
        /* Reset the cryptoki to uninitialize state. */
        prvBeforeRunningTests();

        #if ( PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT == 1 )
            RUN_TEST_CASE( Full_PKCS11_RSA, PKCS11_RSA_CreateObject );
        #endif

        // Generating RSA keys is not currently supported.
        // #if ( PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT == 1 )
        //    RUN_TEST_CASE( Full_PKCS11_RSA, PKCS11_RSA_GenerateKeyPair );
        // #endif


        RUN_TEST_CASE( Full_PKCS11_RSA, PKCS11_RSA_FindObject );
        RUN_TEST_CASE( Full_PKCS11_RSA, PKCS11_RSA_GetAttributeValue );
        RUN_TEST_CASE( Full_PKCS11_RSA, PKCS11_RSA_Sign );

        /* RSA multi-threaded test. */
        RUN_TEST_CASE( Full_PKCS11_RSA, PKCS11_RSA_FindObjectMultiThread );
        RUN_TEST_CASE( Full_PKCS11_RSA, PKCS11_RSA_GetAttributeValueMultiThread );

        /* Always destroy objects last. */
        #if ( PKCS11_TEST_PREPROVISIONED_SUPPORT != 1 )
            RUN_TEST_CASE( Full_PKCS11_RSA, PKCS11_RSA_DestroyObject );
        #endif
    #endif /* if ( PKCS11_TEST_RSA_KEY_SUPPORT == 1 ) */
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_RSA, PKCS11_RSA_CreateObject )
{
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xCertificateHandle = CK_INVALID_HANDLE;

    #if ( PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 )
        CK_RV xResult;
        CK_OBJECT_HANDLE xRootCertificateHandle = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE xCodeSignPublicKeyHandle = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE xJITPCertificateHandle = CK_INVALID_HANDLE;
    #endif /* if ( PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 ) */

    prvProvisionRsaCredentialsWithKeyImport( &xPrivateKeyHandle, &xPublicKeyHandle, &xCertificateHandle );

    #if ( PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 )
        xResult = xProvisionCertificate( xGlobalSession,
                                         ( uint8_t * ) cValidRSACertificate,
                                         sizeof( cValidRSACertificate ),
                                         PKCS11_TEST_LABEL_ROOT_CERTIFICATE,
                                         &xRootCertificateHandle );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create root RSA certificate." );
        TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xRootCertificateHandle ),
                             "Invalid object handle returned for RSA root certificate." );

        xResult = xProvisionCertificate( xGlobalSession,
                                         ( uint8_t * ) cValidRSACertificate,
                                         sizeof( cValidRSACertificate ),
                                         PKCS11_TEST_LABEL_JITP_CERTIFICATE,
                                         &xJITPCertificateHandle );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create JITP RSA certificate." );
        TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xJITPCertificateHandle ),
                             "Invalid object handle returned for RSA JITP certificate." );

        xResult = xProvisionPublicKey( xGlobalSession,
                                       ( uint8_t * ) cValidRSAPublicKey,
                                       sizeof( cValidRSAPublicKey ),
                                       CKK_RSA,
                                       PKCS11_TEST_LABEL_CODE_VERIFICATION_KEY,
                                       &xCodeSignPublicKeyHandle );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create RSA code sign public key." );
        TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xCodeSignPublicKeyHandle ),
                             "Invalid object handle returned for RSA code sign public key." );
    #endif /* if ( PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 ) */
}

/*-----------------------------------------------------------*/

static void prvTestRsaFindObject( provisionMethod_t testProvisionMethod )
{
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xCertificateHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;

    prvFindObjectTest( &xPrivateKeyHandle, &xCertificateHandle, &xPublicKeyHandle );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_RSA, PKCS11_RSA_FindObject )
{
    prvRsaObjectTestHelper( prvTestRsaFindObject );
}

/*-----------------------------------------------------------*/

/* Thread function of PKCS11_FindObjectMultiThread test cases for EC and RSA.
 * Repeatedly tries to find previously provisioned private key and certificate. */
static void prvFindObjectMultiThreadTask( void * pvParameters )
{
    MultithreadTaskParams_t * pxMultiTaskParam = pvParameters;
    uint32_t xCount;
    CK_RV xResult;
    CK_OBJECT_HANDLE xHandle;
    CK_SESSION_HANDLE xSession;

    memcpy( &xSession, pxMultiTaskParam->pvTaskData, sizeof( CK_SESSION_HANDLE ) );

    for( xCount = 0; xCount < PKCS11_TEST_MULTI_THREAD_LOOP_COUNT; xCount++ )
    {
        /* Find the private key object. */
        xResult = xFindObjectWithLabelAndClass( xSession,
                                                PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                                sizeof( PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) - 1,
                                                CKO_PRIVATE_KEY,
                                                &xHandle );

        if( xResult != CKR_OK )
        {
            TEST_PRINTF( "FindObject multithreaded task failed to find private key.  Error: %ld  Count: %d ", xResult, xCount );
            break;
        }

        if( ( xHandle == CK_INVALID_HANDLE ) )
        {
            TEST_PRINTF( "FindObject multi-thread task failed to find private key.  Invalid object handle returned.  Count: %d ", xCount );
            xResult = CKR_OBJECT_HANDLE_INVALID; /* Mark xResult so that test fails. */
            break;
        }

        /* Find the certificate object. */
        xResult = xFindObjectWithLabelAndClass( xSession,
                                                PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                                sizeof( PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS ) - 1,
                                                CKO_CERTIFICATE,
                                                &xHandle );

        if( xResult != CKR_OK )
        {
            TEST_PRINTF( "FindObject multithreaded task failed to find certificate.  Error: %ld  Count: %d ", xResult, xCount );
            break;
        }

        if( ( xHandle == CK_INVALID_HANDLE ) )
        {
            TEST_PRINTF( "FindObject multi-thread task failed to find certificate.  Invalid object handle returned. Count: %d ", xCount );
            xResult = CKR_OBJECT_HANDLE_INVALID; /* Mark xResult so that test fails. */
            break;
        }

        /* Find the public key object. */
        xResult = xFindObjectWithLabelAndClass( xSession,
                                                PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                                sizeof( PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS ) - 1,
                                                CKO_PUBLIC_KEY,
                                                &xHandle );

        if( xResult != CKR_OK )
        {
            TEST_PRINTF( "FindObject multithreaded task failed to find public key.  Error: %ld  Count: %d ", xResult, xCount );
            break;
        }

        if( ( xHandle == CK_INVALID_HANDLE ) )
        {
            TEST_PRINTF( "FindObject multi-thread task failed to find public key.  Invalid object handle returned. Count: %d ", xCount );
            xResult = CKR_OBJECT_HANDLE_INVALID; /* Mark xResult so that test fails. */
            break;
        }
    }

    /* Report the result of the loop. */
    pxMultiTaskParam->xTestResult = xResult;
}

/*-----------------------------------------------------------*/

static void prvTestRsaFindObjectMultiThread( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult;
    uint32_t xTaskNumber;
    CK_SESSION_HANDLE xSessionHandle[ PKCS11_TEST_MULTI_THREAD_TASK_COUNT ];
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;
    CK_OBJECT_HANDLE xCertificateHandle;

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = xInitializePkcs11Session( &xSessionHandle[ xTaskNumber ] );

        if( xResult != CKR_USER_ALREADY_LOGGED_IN )
        {
            TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 session." );
        }

        xGlobalTaskParams[ xTaskNumber ].pvTaskData = &xSessionHandle[ xTaskNumber ];
    }

    prvFindObjectTest( &xPrivateKeyHandle, &xCertificateHandle, &xPublicKeyHandle );

    prvMultiThreadHelper( prvFindObjectMultiThreadTask );

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = pxGlobalFunctionList->C_CloseSession( xSessionHandle[ xTaskNumber ] );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to close session." );
    }
}

/*-----------------------------------------------------------*/

/* Different session trying to find token objects. */
TEST( Full_PKCS11_RSA, PKCS11_RSA_FindObjectMultiThread )
{
    prvRsaObjectTestHelper( prvTestRsaFindObjectMultiThread );
}

/*-----------------------------------------------------------*/

static void prvTestRsaGetAttributeValue( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult;
    CK_ATTRIBUTE xTemplate;
    CK_OBJECT_HANDLE xCertificateHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_BYTE xCertificateValue[ CERTIFICATE_VALUE_LENGTH ];
    CK_BYTE xKeyComponent[ ( pkcs11RSA_2048_MODULUS_BITS / 8 ) + 1 ] = { 0 };
    uint8_t * pucDerObject = NULL;
    size_t xDerLen = 0;
    int32_t lConversionReturn = 1;  /* Initialized to non-zero value. */
    int32_t lImportKeyCompare = 1;  /* Initialized to non-zero value. */

    /* Get the certificate handle. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                            sizeof( PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS ) - 1,
                                            CKO_CERTIFICATE,
                                            &xCertificateHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to find RSA certificate." );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xCertificateHandle ), "Invalid object handle found for RSA certificate." );

    /* Get the certificate value length. */
    xTemplate.type = CKA_VALUE;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificateHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CERTIFICATE_VALUE_LENGTH == xTemplate.ulValueLen ), "GetAttributeValue returned incorrect length of RSA certificate value" );

    /* Get the certificate value. */
    xTemplate.pValue = xCertificateValue;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificateHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to get RSA certificate value" );
    TEST_ASSERT_MESSAGE( ( CERTIFICATE_VALUE_LENGTH == xTemplate.ulValueLen ), "GetAttributeValue returned incorrect length of RSA certificate value" );

    if( testProvisionMethod == eProvisionImportPrivateKey )
    {
        /* Verify the imported certificate. */
        pucDerObject = pvPortMalloc( sizeof( cValidRSACertificate ) );
        TEST_ASSERT_MESSAGE( pucDerObject != NULL, "Allocate memory for RSA certificate failed." );
        xDerLen = sizeof( cValidRSACertificate );

        lConversionReturn = convert_pem_to_der( ( const unsigned char * ) cValidRSACertificate,
                                                sizeof( cValidRSACertificate ),
                                                pucDerObject,
                                                &xDerLen );

        if( lConversionReturn == 0 )
        {
            lImportKeyCompare = memcmp( xTemplate.pValue, pucDerObject, xTemplate.ulValueLen );
        }

        /* Free the allocated memory and compare. */
        vPortFree( pucDerObject );
        pucDerObject = NULL;

        if( ( lConversionReturn != 0 ) || ( lImportKeyCompare != 0 ) )
        {
            TEST_FAIL_MESSAGE( "Compare imported RSA certificate failed." );
        }
    }

    /* Get the private key handle. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            sizeof( PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) - 1,
                                            CKO_PRIVATE_KEY,
                                            &xPrivateKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to find RSA private key." );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xPrivateKeyHandle ), "Invalid object handle found for RSA private key." );

    /* Check that the private key cannot be retrieved. */
    xTemplate.type = CKA_PRIVATE_EXPONENT;
    xTemplate.pValue = xKeyComponent;
    xTemplate.ulValueLen = sizeof( xKeyComponent );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_ATTRIBUTE_SENSITIVE == xResult ), "Incorrect error code retrieved when trying to obtain private key." );
    TEST_ASSERT_EACH_EQUAL_INT8_MESSAGE( 0, xKeyComponent, sizeof( xKeyComponent ), "Private key bytes returned when they should not be." );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_RSA, PKCS11_RSA_GetAttributeValue )
{
    prvRsaObjectTestHelper( prvTestRsaGetAttributeValue );
}

/*-----------------------------------------------------------*/

static void prvTestRsaSign( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;
    CK_OBJECT_HANDLE xCertificateHandle;
    CK_MECHANISM xMechanism;
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0 };
    CK_BYTE xSignature[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    CK_ULONG xSignatureLength;
    CK_BYTE xHashPlusOid[ pkcs11RSA_SIGNATURE_INPUT_LENGTH ];

    /* Verify the signature with mbedTLS */
    mbedtls_pk_context xMbedPkContext;
    int lMbedTLSResult;

    #if MBEDTLS_VERSION_NUMBER >= 0x03000000
        mbedtls_entropy_context xEntropyContext;
        mbedtls_ctr_drbg_context xDrbgContext;
    #endif

    prvFindObjectTest( &xPrivateKeyHandle, &xCertificateHandle, &xPublicKeyHandle );

    xResult = vAppendSHA256AlgorithmIdentifierSequence( xHashedMessage, xHashPlusOid );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to append hash algorithm to RSA signature material." );

    /* The RSA X.509 mechanism assumes a pre-hashed input. */
    xMechanism.mechanism = CKM_RSA_PKCS;
    xMechanism.pParameter = NULL;
    xMechanism.ulParameterLen = 0;
    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to SignInit RSA." );

    xSignatureLength = sizeof( xSignature );
    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashPlusOid, sizeof( xHashPlusOid ), xSignature, &xSignatureLength );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to RSA Sign." );
    TEST_ASSERT_MESSAGE( ( pkcs11RSA_2048_SIGNATURE_LENGTH == xSignatureLength ), "RSA Sign returned an unexpected signature length." );

    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to SignInit RSA." );

    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashPlusOid, sizeof( xHashPlusOid ), NULL, &xSignatureLength );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to RSA Sign." );
    TEST_ASSERT_MESSAGE( ( pkcs11RSA_2048_SIGNATURE_LENGTH == xSignatureLength ), "RSA Sign should return needed signature buffer length when pucSignature is NULL." );

    mbedtls_pk_init( &xMbedPkContext );

    #if MBEDTLS_VERSION_NUMBER >= 0x03000000
        /* Initialize the RNG. */
        mbedtls_entropy_init( &xEntropyContext );
        mbedtls_ctr_drbg_init( &xDrbgContext );
    #endif

    if( TEST_PROTECT() )
    {
        #if MBEDTLS_VERSION_NUMBER < 0x03000000
            lMbedTLSResult = mbedtls_pk_parse_key( ( mbedtls_pk_context * ) &xMbedPkContext,
                                                   ( const unsigned char * ) cValidRSAPrivateKey,
                                                   sizeof( cValidRSAPrivateKey ),
                                                   NULL,
                                                   0 );
            TEST_ASSERT_MESSAGE( ( 0 == lMbedTLSResult ), "mbedTLS failed to parse valid RSA key (verification)" );

            lMbedTLSResult = mbedtls_rsa_pkcs1_verify( xMbedPkContext.pk_ctx, NULL, NULL,
                MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 32, xHashedMessage, xSignature );
            TEST_ASSERT_MESSAGE( ( 0 == xResult ), "mbedTLS failed to verify RSA signagure." );

        #else
            lMbedTLSResult = mbedtls_ctr_drbg_seed( &xDrbgContext, mbedtls_entropy_func, &xEntropyContext, NULL, 0 );
            TEST_ASSERT_MESSAGE( ( 0 == lMbedTLSResult ), "Failed to initialize DRBG" );

            lMbedTLSResult = mbedtls_pk_parse_key( ( mbedtls_pk_context * ) &xMbedPkContext,
                                                   ( const unsigned char * ) cValidRSAPrivateKey,
                                                   sizeof( cValidRSAPrivateKey ),
                                                   NULL,
                                                   0,
                                                   mbedtls_ctr_drbg_random, &xDrbgContext );
            TEST_ASSERT_MESSAGE( ( 0 == lMbedTLSResult ), "mbedTLS failed to parse valid RSA key (verification)" );

            lMbedTLSResult = mbedtls_rsa_pkcs1_verify( xMbedPkContext.pk_ctx, MBEDTLS_MD_SHA256,
                32, xHashedMessage, xSignature );
            TEST_ASSERT_MESSAGE( ( 0 == xResult ), "mbedTLS failed to verify RSA signagure." );

        #endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */
    }

    #if MBEDTLS_VERSION_NUMBER >= 0x03000000
        /* Free the RNG. */
        mbedtls_ctr_drbg_free( &xDrbgContext );
        mbedtls_entropy_free( &xEntropyContext );
    #endif

    mbedtls_pk_free( &xMbedPkContext );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_RSA, PKCS11_RSA_Sign )
{
    prvRsaObjectTestHelper( prvTestRsaSign );
}

/*-----------------------------------------------------------*/

/* Thread function of PKCS11_GetAttributeValueMultiThread test case. */
static void prvRSAGetAttributeValueMultiThreadTask( void * pvParameters )
{
    MultithreadTaskParams_t * pxMultiTaskParam = pvParameters;
    GetAttributeValueMultiThread_t * pxAttributeStruct = pxMultiTaskParam->pvTaskData;
    CK_ATTRIBUTE xTemplate;
    CK_OBJECT_HANDLE xCertificateHandle = pxAttributeStruct->xCertificate;
    CK_OBJECT_HANDLE xPrivateKeyHandle = pxAttributeStruct->xPrivateKey;
    CK_SESSION_HANDLE xSession = pxAttributeStruct->xSession;
    CK_BYTE xCertificateValue[ CERTIFICATE_VALUE_LENGTH ];
    CK_BYTE xKeyComponent[ ( pkcs11RSA_2048_MODULUS_BITS / 8 ) + 1 ] = { 0 };
    uint32_t xCount;

    if( TEST_PROTECT() )
    {
        for( xCount = 0; xCount < PKCS11_TEST_MULTI_THREAD_LOOP_COUNT; xCount++ )
        {
            /* Get the certificate value length. */
            xTemplate.type = CKA_VALUE;
            xTemplate.pValue = NULL;
            xTemplate.ulValueLen = 0;
            pxMultiTaskParam->xTestResult = pxGlobalFunctionList->C_GetAttributeValue( xSession, xCertificateHandle, &xTemplate, 1 );
            TEST_ASSERT_MESSAGE( ( CERTIFICATE_VALUE_LENGTH == xTemplate.ulValueLen ), "GetAttributeValue returned incorrect length of RSA certificate value" );

            /* Get the certificate value. */
            xTemplate.pValue = xCertificateValue;
            pxMultiTaskParam->xTestResult = pxGlobalFunctionList->C_GetAttributeValue( xSession, xCertificateHandle, &xTemplate, 1 );
            TEST_ASSERT_MESSAGE( ( CKR_OK == pxMultiTaskParam->xTestResult ), "Failed to get RSA certificate value" );
            TEST_ASSERT_MESSAGE( ( CERTIFICATE_VALUE_LENGTH == xTemplate.ulValueLen ), "GetAttributeValue returned incorrect length of RSA certificate value" );

            /* Check that the private key cannot be retrieved. */
            xTemplate.type = CKA_PRIVATE_EXPONENT;
            xTemplate.pValue = xKeyComponent;
            xTemplate.ulValueLen = sizeof( xKeyComponent );
            pxMultiTaskParam->xTestResult = pxGlobalFunctionList->C_GetAttributeValue( xSession, xPrivateKeyHandle, &xTemplate, 1 );
            TEST_ASSERT_MESSAGE( ( CKR_ATTRIBUTE_SENSITIVE == pxMultiTaskParam->xTestResult ), "Incorrect error code retrieved when trying to obtain private key." );
            TEST_ASSERT_EACH_EQUAL_INT8_MESSAGE( 0, xKeyComponent, sizeof( xKeyComponent ), "Private key bytes returned when they should not be." );

            /* Reset the test result after retrieve private key attribute test. */
            pxMultiTaskParam->xTestResult = 0;
        }
    }
}

/*-----------------------------------------------------------*/

static void prvTestRsaGetAttributeValueMultiThread( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult;
    uint32_t xTaskNumber;
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xCertificateHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;

    GetAttributeValueMultiThread_t xAttributeStruct[ PKCS11_TEST_MULTI_THREAD_TASK_COUNT ];

    prvFindObjectTest( &xPrivateKeyHandle, &xCertificateHandle, &xPublicKeyHandle );

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = xInitializePkcs11Session( &xAttributeStruct[ xTaskNumber ].xSession );
        xAttributeStruct[ xTaskNumber ].xPrivateKey = xPrivateKeyHandle;
        xAttributeStruct[ xTaskNumber ].xPublicKey = xPublicKeyHandle;
        xAttributeStruct[ xTaskNumber ].xCertificate = xCertificateHandle;

        if( xResult != CKR_USER_ALREADY_LOGGED_IN )
        {
            TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 session." );
        }

        xGlobalTaskParams[ xTaskNumber ].pvTaskData = &xAttributeStruct[ xTaskNumber ];
    }

    prvMultiThreadHelper( prvRSAGetAttributeValueMultiThreadTask );

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = pxGlobalFunctionList->C_CloseSession( xAttributeStruct[ xTaskNumber ].xSession );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to close session." );
    }
}

/*-----------------------------------------------------------*/

/* Same & different PKCS #11 sessions asking for attribute values of the same 2 objects. */
TEST( Full_PKCS11_RSA, PKCS11_RSA_GetAttributeValueMultiThread )
{
    prvRsaObjectTestHelper( prvTestRsaGetAttributeValueMultiThread );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_RSA, PKCS11_RSA_GenerateKeyPair )
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;
    CK_MECHANISM xMechanism;
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0 };
    CK_BYTE xSignature[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    CK_ULONG xSignatureLength;
    CK_BYTE xModulus[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    unsigned int ulModulusLength = 0;
    CK_BYTE xExponent[ 4 ] = { 0 };
    unsigned int ulExponentLength = 0;
    CK_BYTE xPaddedHash[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    mbedtls_rsa_context xRsaContext;

    xResult = xProvisionGenerateKeyPairRSA( xGlobalSession,
                                            ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                            &xPrivateKeyHandle,
                                            &xPublicKeyHandle );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );
    TEST_ASSERT_MESSAGE( ( 0 != xPrivateKeyHandle ), "Invalid object handle returned for RSA private key." );

    CK_ATTRIBUTE xTemplate;

    xTemplate.type = CKA_MODULUS;
    xTemplate.pValue = xModulus;
    xTemplate.ulValueLen = sizeof( xModulus );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );
    ulModulusLength = xTemplate.ulValueLen;

    xTemplate.type = CKA_PUBLIC_EXPONENT;
    xTemplate.pValue = xExponent;
    xTemplate.ulValueLen = sizeof( xExponent );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );
    ulExponentLength = xTemplate.ulValueLen;

    xResult = PKI_RSA_RSASSA_PKCS1_v15_Encode( xHashedMessage, pkcs11RSA_2048_SIGNATURE_LENGTH, xPaddedHash );
    TEST_ASSERT_EQUAL( CKR_OK, xResult );

    /* The RSA X.509 mechanism assumes a pre-hashed input. */
    xMechanism.mechanism = CKM_RSA_X_509;
    xMechanism.pParameter = NULL;
    xMechanism.ulParameterLen = 0;
    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to SignInit RSA." );

    xSignatureLength = sizeof( xSignature );
    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xPaddedHash, pkcs11RSA_2048_SIGNATURE_LENGTH, xSignature, &xSignatureLength );
    printf("\nxResult: 0x%x\n", xResult);
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to RSA Sign." );

    /* Verify the signature with mbedTLS. Set up the RSA public key. */
    #if MBEDTLS_VERSION_NUMBER < 0x03000000
        mbedtls_rsa_init( &xRsaContext, MBEDTLS_RSA_PKCS_V15, 0 );
    #else
        mbedtls_rsa_init( &xRsaContext );
    #endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */

    if( TEST_PROTECT() )
    {
        xResult = mbedtls_mpi_read_binary( &xRsaContext.N, xModulus, ulModulusLength );
        TEST_ASSERT_EQUAL( 0, xResult );
        xResult = mbedtls_mpi_read_binary( &xRsaContext.E, xExponent, ulExponentLength );
        TEST_ASSERT_EQUAL( 0, xResult );
        xRsaContext.len = pkcs11RSA_2048_SIGNATURE_LENGTH;
        xResult = mbedtls_rsa_check_pubkey( &xRsaContext );
        TEST_ASSERT_EQUAL( 0, xResult );
        #if MBEDTLS_VERSION_NUMBER < 0x03000000
            xResult = mbedtls_rsa_pkcs1_verify( &xRsaContext, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 32, xHashedMessage, xSignature );
        #else
            xResult = mbedtls_rsa_pkcs1_verify( &xRsaContext, MBEDTLS_MD_SHA256, 32, xHashedMessage, xSignature );
        #endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */
        TEST_ASSERT_MESSAGE( ( 0 == xResult ), "mbedTLS failed to parse valid RSA key (verification)" );

        /* Verify the signature with the generated public key. */
        xResult = pxGlobalFunctionList->C_VerifyInit( xGlobalSession, &xMechanism, xPublicKeyHandle );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to VerifyInit RSA." );
        xResult = pxGlobalFunctionList->C_Verify( xGlobalSession, xPaddedHash, pkcs11RSA_2048_SIGNATURE_LENGTH, xSignature, xSignatureLength );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to Verify RSA." );
    }

    mbedtls_rsa_free( &xRsaContext );
}

/*-----------------------------------------------------------*/

static void prvTestRsaDestroyObject( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult = CKR_OK;

    if( testProvisionMethod != eProvisionPreprovisioned )
    {
        xResult = prvDestroyTestCredentials();
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to destroy RSA credentials." );
    }
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_RSA, PKCS11_RSA_DestroyObject )
{
    prvRsaObjectTestHelper( prvTestRsaDestroyObject );
}

/*--------------------------------------------------------*/
/*-------------- EC Tests ------------------------------- */
/*--------------------------------------------------------*/

TEST_SETUP( Full_PKCS11_EC )
{
    CK_RV xResult;

    xResult = xInitializePKCS11();
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 module." );

    xResult = xInitializePkcs11Session( &xGlobalSession );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to open PKCS #11 session." );
}

/*-----------------------------------------------------------*/

TEST_TEAR_DOWN( Full_PKCS11_EC )
{
    CK_RV xResult;

    xResult = pxGlobalFunctionList->C_CloseSession( xGlobalSession );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to close session." );

    xResult = pxGlobalFunctionList->C_Finalize( NULL );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to finalize session." );
}

/*-----------------------------------------------------------*/

TEST_GROUP_RUNNER( Full_PKCS11_EC )
{
    #if ( PKCS11_TEST_EC_KEY_SUPPORT == 1 )
        /* Reset the cryptoki to uninitialize state. */
        prvBeforeRunningTests();

        #if ( PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT == 1 )
            RUN_TEST_CASE( Full_PKCS11_EC, PKCS11_EC_GenerateKeyPair );
        #endif

        #if ( PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT == 1 )
            RUN_TEST_CASE( Full_PKCS11_EC, PKCS11_EC_CreateObject );
        #endif

        RUN_TEST_CASE( Full_PKCS11_EC, PKCS11_EC_FindObject );
        RUN_TEST_CASE( Full_PKCS11_EC, PKCS11_EC_GetAttributeValue );
        RUN_TEST_CASE( Full_PKCS11_EC, PKCS11_EC_Sign );
        RUN_TEST_CASE( Full_PKCS11_EC, PKCS11_EC_Verify );

        RUN_TEST_CASE( Full_PKCS11_EC, PKCS11_EC_FindObjectMultiThread );
        RUN_TEST_CASE( Full_PKCS11_EC, PKCS11_EC_GetAttributeValueMultiThread );
        RUN_TEST_CASE( Full_PKCS11_EC, PKCS11_EC_SignVerifyMultiThread );

        #if ( PKCS11_TEST_PREPROVISIONED_SUPPORT != 1 )
            RUN_TEST_CASE( Full_PKCS11_EC, PKCS11_EC_DestroyObject );
        #endif
    #endif /* if ( PKCS11_TEST_EC_KEY_SUPPORT == 1 ) */
}

/*-----------------------------------------------------------*/

/*
 * 1. Generates an Elliptic Curve P256 key pair
 * 2. Calls GetAttributeValue to check generated key & that private key is not extractable.
 * 3. Constructs the public key using values from GetAttributeValue calls
 * 4. Uses private key to perform a sign operation
 * 5. Verifies the signature using mbedTLS library and reconstructed public key
 * 6. Verifies the signature using the public key just created.
 * 7. Finds the public and private key using FindObject calls
 */
TEST( Full_PKCS11_EC, PKCS11_EC_GenerateKeyPair )
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xCertificateHandle = CK_INVALID_HANDLE;

    CK_BYTE xEcPoint[ PKCS11_TEST_EC_POINT_LENGTH ] = { 0 };
    CK_BYTE xPrivateKeyBuffer[ 32 ] = { 0 };
    CK_KEY_TYPE xKeyType;
    CK_ATTRIBUTE xTemplate;
    CK_OBJECT_CLASS xClass;

    /* mbedTLS structures for verification. */
    uint8_t ucSecp256r1Oid[] = pkcs11DER_ENCODED_OID_P256; /*"\x06\x08" MBEDTLS_OID_EC_GRP_SECP256R1; */
    CK_BYTE xEcParams[ sizeof( ucSecp256r1Oid ) ] = { 0 };

    xResult = xProvisionGenerateKeyPairEC( xGlobalSession,
                                           ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                           ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                           &xPrivateKeyHandle,
                                           &xPublicKeyHandle );

    printf("\nxResult: 0x%x\n", xResult);
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Generating EC key pair failed." );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xPrivateKeyHandle ), "Invalid private key handle generated by GenerateKeyPair" );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xPublicKeyHandle ), "Invalid public key handle generated by GenerateKeyPair" );

    /* We will try to provision the certificate as well, as it is needed for the
     * tests that are not responsible for creating objects. */
    xResult = xProvisionCertificate( xGlobalSession,
                                     ( uint8_t * ) cValidECDSACertificate,
                                     sizeof( cValidECDSACertificate ),
                                     ( uint8_t * ) PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                     &xCertificateHandle );

    printf("\nxResult: 0x%x\n", xResult);
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create EC certificate." );
    TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xCertificateHandle ), "Invalid object handle returned for EC certificate." );

    /* Call GetAttributeValue to retrieve information about the keypair stored. */
    /* Check that correct object class retrieved. */
    xTemplate.type = CKA_CLASS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for length of public EC key class failed." );
    TEST_ASSERT_MESSAGE( ( sizeof( CK_OBJECT_CLASS ) == xTemplate.ulValueLen ), "Incorrect object class length returned from GetAttributeValue." );

    xTemplate.pValue = &xClass;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for private EC key class failed." );
    TEST_ASSERT_MESSAGE( ( CKO_PRIVATE_KEY == xClass ), "Incorrect object class returned from GetAttributeValue." );

    xTemplate.pValue = &xClass;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for public EC key class failed." );
    TEST_ASSERT_MESSAGE( ( CKO_PUBLIC_KEY == xClass ), "Incorrect object class returned from GetAttributeValue." );

    /* Check that both keys are stored as EC Keys. */
    xTemplate.type = CKA_KEY_TYPE;
    xTemplate.pValue = &xKeyType;
    xTemplate.ulValueLen = sizeof( CK_KEY_TYPE );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Error getting attribute value of EC key type." );
    TEST_ASSERT_MESSAGE( ( sizeof( CK_KEY_TYPE ) == xTemplate.ulValueLen ), "Length of key type incorrect in GetAttributeValue" );
    TEST_ASSERT_MESSAGE( ( CKK_EC == xKeyType ), "Incorrect key type for private key" );

    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Error getting attribute value of EC key type." );
    TEST_ASSERT_MESSAGE( ( sizeof( CK_KEY_TYPE ) == xTemplate.ulValueLen ), "Length of key type incorrect in GetAttributeValue" );
    TEST_ASSERT_MESSAGE( ( CKK_EC == xKeyType ), "Incorrect key type for public key" );

    /* Check that correct curve retrieved for private key. */
    xTemplate.type = CKA_EC_PARAMS;
    xTemplate.pValue = xEcParams;
    xTemplate.ulValueLen = sizeof( xEcParams );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Error getting attribute value of EC Parameters." );
    TEST_ASSERT_MESSAGE( ( sizeof( ucSecp256r1Oid ) == xTemplate.ulValueLen ), "Length of ECParameters identifier incorrect in GetAttributeValue" );
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE( ucSecp256r1Oid, xEcParams, xTemplate.ulValueLen, "EcParameters did not match P256 OID." );

    /* Check that the private key cannot be retrieved. */
    xTemplate.type = CKA_VALUE;
    xTemplate.pValue = xPrivateKeyBuffer;
    xTemplate.ulValueLen = sizeof( xPrivateKeyBuffer );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_ATTRIBUTE_SENSITIVE == xResult ), "Wrong error code retrieving private key" );
    TEST_ASSERT_EACH_EQUAL_INT8_MESSAGE( 0, xPrivateKeyBuffer, sizeof( xPrivateKeyBuffer ), "Private key bytes returned when they should not be" );

    /* Check that public key point can be retrieved for public key. */
    xTemplate.type = CKA_EC_POINT;
    xTemplate.pValue = xEcPoint;
    xTemplate.ulValueLen = sizeof( xEcPoint );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to retrieve EC Point." );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_EC, PKCS11_EC_CreateObject )
{
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xCertificateHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;

    #if ( PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 )
        CK_RV xResult;
        CK_OBJECT_HANDLE xRootCertificateHandle;
        CK_OBJECT_HANDLE xCodeSignPublicKeyHandle;
        CK_OBJECT_HANDLE xJITPCertificateHandle;
    #endif /* if ( PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 ) */

    prvProvisionEcCredentialsWithKeyImport( &xPrivateKeyHandle,
                                            &xCertificateHandle,
                                            &xPublicKeyHandle );

    #if ( PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 )
        xResult = xProvisionCertificate( xGlobalSession,
                                         ( uint8_t * ) cValidECDSACertificate,
                                         sizeof( cValidECDSACertificate ),
                                         PKCS11_TEST_LABEL_ROOT_CERTIFICATE,
                                         &xRootCertificateHandle );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create root EC certificate." );
        TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xRootCertificateHandle ), "Invalid object handle returned for EC root certificate." );

        xResult = xProvisionCertificate( xGlobalSession,
                                         ( uint8_t * ) cValidECDSACertificate,
                                         sizeof( cValidECDSACertificate ),
                                         PKCS11_TEST_LABEL_JITP_CERTIFICATE,
                                         &xJITPCertificateHandle );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create JITP EC certificate." );
        TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xJITPCertificateHandle ), "Invalid object handle returned for EC JITP certificate." );

        xResult = xProvisionPublicKey( xGlobalSession,
                                       ( uint8_t * ) cValidECDSAPublicKey,
                                       sizeof( cValidECDSAPublicKey ),
                                       CKK_EC,
                                       PKCS11_TEST_LABEL_CODE_VERIFICATION_KEY,
                                       &xCodeSignPublicKeyHandle );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to create EC code sign public key." );
        TEST_ASSERT_MESSAGE( ( CK_INVALID_HANDLE != xCodeSignPublicKeyHandle ), "Invalid object handle returned for EC code sign public key." );
    #endif /* if ( PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 ) */
}

/*-----------------------------------------------------------*/

static void prvTestEcFindObject( provisionMethod_t testProvisionMethod )
{
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xCertificateHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;

    prvFindObjectTest( &xPrivateKeyHandle, &xCertificateHandle, &xPublicKeyHandle );
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_EC, PKCS11_EC_FindObject )
{
    prvEcObjectTestHelper( prvTestEcFindObject );
}

/*-----------------------------------------------------------*/

static void prvTestEcGetAttributeValue( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xCertificate = CK_INVALID_HANDLE;
    CK_ATTRIBUTE xTemplate;
    CK_KEY_TYPE xKeyType = 0;
    uint8_t ucP256Oid[] = pkcs11DER_ENCODED_OID_P256;
    CK_BYTE xEcParams[ 10 ] = { 0 };
    CK_OBJECT_CLASS xClass;
    CK_BYTE xEcPointExpected[] =
    {
        0x04, 0x41, 0x04, 0xce, 0x08, 0x69, 0xf9, 0x0b, 0x2d, 0x52, 0x13, 0xa6, 0xcc, 0xa0, 0x46, 0x10,
        0xbe, 0xee, 0x06, 0x3b, 0x1a, 0x05, 0xbc, 0x9a, 0x35, 0x33, 0x0b, 0x5c, 0xa2, 0xd2, 0x5b, 0xbf,
        0x3e, 0x6d, 0xda, 0x0f, 0xf5, 0xb2, 0x93, 0x3a, 0xba, 0xa2, 0x2a, 0x4f, 0x46, 0xcc, 0x59, 0x3d,
        0x0a, 0x1b, 0x61, 0x1c, 0x5b, 0x31, 0xf9, 0x3e, 0xd4, 0x16, 0x2b, 0x61, 0x6d, 0x85, 0xad, 0x45,
        0xfd, 0x19, 0xc3
    };
    CK_BYTE xCertificateValueExpected[ 626 ];
    CK_BYTE xCertificateValue[ 626 ];
    CK_BYTE xEcPoint[ sizeof( xEcPointExpected ) ] = { 0 };
    size_t xLength = sizeof( xCertificateValueExpected );
    int lConversionReturn;

    lConversionReturn = convert_pem_to_der( ( const unsigned char * ) cValidECDSACertificate,
                                            sizeof( cValidECDSACertificate ),
                                            xCertificateValueExpected,
                                            &xLength );

    if( lConversionReturn != 0 )
    {
        TEST_PRINTF( "Failed to convert the EC certificate from PEM to DER. Error code %d ", lConversionReturn );
    }

    prvFindObjectTest( &xPrivateKey, &xCertificate, &xPublicKey );

    /* The PKCS #11 standard expects that calling GetAttributeValue with a null pointer to the value
     * will yield a success with the value length updated to the size of the buffer needed to contain
     * the attribute.
     *
     * All tests start by querying the attribute length, and followed by a query of the attribute value. */

    /***** Private Key Checks. *****/

    /* Check object class. */
    xTemplate.type = CKA_CLASS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;

    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for length of private EC key class failed." );
    TEST_ASSERT_MESSAGE( ( sizeof( CK_OBJECT_CLASS ) == xTemplate.ulValueLen ), "Incorrect object class length returned from GetAttributeValue." );

    xTemplate.pValue = &xClass;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for private EC key class failed." );
    TEST_ASSERT_MESSAGE( ( CKO_PRIVATE_KEY == xClass ), "Incorrect object class returned from GetAttributeValue." );

    /* Key type. */
    xTemplate.type = CKA_KEY_TYPE;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for length of EC key type failed." );
    TEST_ASSERT_MESSAGE( ( sizeof( CK_KEY_TYPE ) == xTemplate.ulValueLen ), "Incorrect key type length provided." );

    xTemplate.pValue = &xKeyType;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for EC key type failed." );
    TEST_ASSERT_MESSAGE( ( CKK_EC == xKeyType ), "Incorrect key type returned." );

    /* Check EC Params. */
    xTemplate.type = CKA_EC_PARAMS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for length of EC params type failed." );
    TEST_ASSERT_MESSAGE( ( sizeof( ucP256Oid ) == xTemplate.ulValueLen ), "Incorrect EC params length provided." );

    xTemplate.pValue = xEcParams;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for EC params failed." );
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE( ucP256Oid, xEcParams, sizeof( ucP256Oid ), "Incorrect ECParameters returned from GetAttributeValue" );

    /******* Public Key ********/
    /* Object class. */
    xTemplate.type = CKA_CLASS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for length of public EC key class failed." );
    TEST_ASSERT_MESSAGE( ( sizeof( CK_OBJECT_CLASS ) == xTemplate.ulValueLen ), "Incorrect object class length returned from GetAttributeValue." );

    xTemplate.pValue = &xClass;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for public EC key class failed." );
    TEST_ASSERT_MESSAGE( ( CKO_PUBLIC_KEY == xClass ), "Incorrect object class returned from GetAttributeValue." );

    /* Elliptic Curve Parameters (the OID of the curve). At this time only P256 curves are supported. */
    xTemplate.type = CKA_EC_PARAMS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for length of public key EC Params failed." );
    TEST_ASSERT_MESSAGE( ( sizeof( ucP256Oid ) == xTemplate.ulValueLen ), "Incorrect EC params length provided." );

    memset( xEcParams, 0x0, sizeof( ucP256Oid ) );
    xTemplate.pValue = xEcParams;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for EC params failed." );
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE( ucP256Oid, xEcParams, sizeof( ucP256Oid ), "Incorrect ECParameters returned from GetAttributeValue" );

    /* Elliptic curve point. */
    xTemplate.type = CKA_EC_POINT;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for length of public key EC point failed." );
    TEST_ASSERT_MESSAGE( ( sizeof( xEcPointExpected ) == xTemplate.ulValueLen ), "Incorrect EC point length provided." );

    xTemplate.pValue = xEcPoint;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for EC point failed." );

    if( testProvisionMethod == eProvisionImportPrivateKey )
    {
        /* The EC point can only be known for a public key that was previously created
         * therefore this check is only done for implementations that support importing
         * a private key, as the credentials that are on the device are all known.
         */
        TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE( xEcPointExpected, xEcPoint, sizeof( xEcPointExpected ), "Incorrect EC Point returned from GetAttributeValue" );
    }

    /****** Certificate check. *******/
    /* Object class. */
    xTemplate.type = CKA_CLASS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificate, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for length of EC certificate class failed." );

    if( testProvisionMethod != eProvisionPreprovisioned )
    {
        TEST_ASSERT_MESSAGE( ( sizeof( CK_OBJECT_CLASS ) == xTemplate.ulValueLen ), "Incorrect object class length returned from GetAttributeValue." );
    }

    xTemplate.pValue = &xClass;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificate, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for EC certificate class failed." );
    TEST_ASSERT_MESSAGE( ( CKO_CERTIFICATE == xClass ), "Incorrect object class returned from GetAttributeValue." );

    /* Certificate value (the DER encoded certificate). */
    xTemplate.type = CKA_VALUE;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificate, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for length of certificate value failed." );

    if( testProvisionMethod != eProvisionPreprovisioned )
    {
        TEST_ASSERT_MESSAGE( ( sizeof( xCertificateValueExpected ) == xTemplate.ulValueLen ), "Incorrect certificate value length" );
    }

    xTemplate.pValue = xCertificateValue;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificate, &xTemplate, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "GetAttributeValue for certificate value failed." );

    if( testProvisionMethod != eProvisionPreprovisioned )
    {
        TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE( xCertificateValueExpected, xCertificateValue, sizeof( xCertificateValueExpected ), "Incorrect certificate value returned." );
    }
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_EC, PKCS11_EC_GetAttributeValue )
{
    prvEcObjectTestHelper( prvTestEcGetAttributeValue );
}

/*-----------------------------------------------------------*/

static void prvTestEcSign( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult = CKR_OK;
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xCertificateHandle = CK_INVALID_HANDLE;

    /* Note that ECDSA operations on a signature of all 0's is not permitted. */
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0xab };
    CK_MECHANISM xMechanism;
    CK_BYTE xSignature[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    CK_ULONG xSignatureLength;
    int lMbedTLSResult;

    mbedtls_mpi xR;
    mbedtls_mpi xS;

    mbedtls_pk_context xEcdsaContext;
    mbedtls_pk_context * pxEcdsaContext = &xEcdsaContext;
    CK_ATTRIBUTE xPubKeyQuery = { CKA_EC_POINT, NULL, 0 };
    CK_BYTE * pxPublicKey = NULL;

    /* Reconstruct public key from EC Params. */
    mbedtls_ecp_keypair xKeyPair;
    mbedtls_ecp_keypair * pxKeyPair = &xKeyPair;

    /* Find objects that were previously created. This test case should be run if
     * there are objects that exists under known labels. This test case is not
     * responsible for creating the objects used for signing. */
    prvFindObjectTest( &xPrivateKeyHandle, &xCertificateHandle, &xPublicKeyHandle );

    xMechanism.mechanism = CKM_ECDSA;
    xMechanism.pParameter = NULL;
    xMechanism.ulParameterLen = 0;
    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to SignInit ECDSA." );

    xSignatureLength = sizeof( xSignature );
    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, &xSignatureLength );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to ECDSA Sign." );
    TEST_ASSERT_MESSAGE( ( pkcs11ECDSA_P256_SIGNATURE_LENGTH == xSignatureLength ), "ECDSA Sign returned an unexpected ECDSA Signature length." );

    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to SignInit ECDSA." );

    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, NULL, &xSignatureLength );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to ECDSA Sign." );
    TEST_ASSERT_MESSAGE( ( pkcs11ECDSA_P256_SIGNATURE_LENGTH == xSignatureLength ), "ECDSA Sign should return needed signature buffer length when pucSignature is NULL." );

    /* Get EC point from PKCS #11 stack. */
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xPubKeyQuery, 1 );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to query for public key length" );
    TEST_ASSERT_MESSAGE( ( 0 != xPubKeyQuery.ulValueLen ), "The size of the public key was an unexpected value." );

    pxPublicKey = pvPortMalloc( xPubKeyQuery.ulValueLen );
    TEST_ASSERT_MESSAGE( ( NULL != pxPublicKey ), "Failed to allocate space for public key." );

    if( TEST_PROTECT() )
    {
        mbedtls_mpi_init( &xR );
        mbedtls_mpi_init( &xS );

        mbedtls_pk_init( pxEcdsaContext );

        /* Initialize the info. */
        pxEcdsaContext->pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY );
        mbedtls_ecp_keypair_init( pxKeyPair );
        mbedtls_ecp_group_init( &pxKeyPair->grp );

        /* Might want to make the ECP group configurable in the future. */
        lMbedTLSResult = mbedtls_ecp_group_load( &pxKeyPair->grp,
                                                 MBEDTLS_ECP_DP_SECP256R1 );
        TEST_ASSERT_MESSAGE( ( 0 == lMbedTLSResult ), "Failed to load EC group." );

        /* Initialize the context. */
        pxEcdsaContext->pk_ctx = pxKeyPair;

        xPubKeyQuery.pValue = pxPublicKey;
        xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xPubKeyQuery, 1 );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to query for public key length" );
        TEST_ASSERT_MESSAGE( ( 0 != xPubKeyQuery.ulValueLen ), "The size of the public key was an unexpected value." );

        /* Strip the ANS.1 Encoding of type and length. Otherwise mbed TLS won't be
         * able to parse the binary EC point. */
        lMbedTLSResult = mbedtls_ecp_point_read_binary( &pxKeyPair->grp,
                                                        &pxKeyPair->Q,
                                                        ( uint8_t * ) ( xPubKeyQuery.pValue ) + 2,
                                                        xPubKeyQuery.ulValueLen - 2 );
        TEST_ASSERT_MESSAGE( ( 0 == lMbedTLSResult ), "mbedTLS failed to read binary point." );

        /* An ECDSA signature is comprised of 2 components - R & S. */

        lMbedTLSResult = mbedtls_mpi_read_binary( &xR, &xSignature[ 0 ], 32 );
        TEST_ASSERT_MESSAGE( ( 0 == lMbedTLSResult ), "mbedTLS failed to read R binary in ECDSA signature." );

        lMbedTLSResult = mbedtls_mpi_read_binary( &xS, &xSignature[ 32 ], 32 );
        TEST_ASSERT_MESSAGE( ( 0 == lMbedTLSResult ), "mbedTLS failed to read S binary in ECDSA signature." );

        lMbedTLSResult = mbedtls_ecdsa_verify( &pxKeyPair->grp, xHashedMessage, sizeof( xHashedMessage ), &pxKeyPair->Q, &xR, &xS );
        TEST_ASSERT_MESSAGE( ( 0 == lMbedTLSResult ), "mbedTLS failed to verify signature." );
    }

    mbedtls_mpi_free( &xR );
    mbedtls_mpi_free( &xS );

    pxEcdsaContext->pk_ctx = NULL;
    mbedtls_pk_free( &xEcdsaContext );

    if( pxPublicKey != NULL )
    {
        vPortFree( pxPublicKey );
    }
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_EC, PKCS11_EC_Sign )
{
    prvEcObjectTestHelper( prvTestEcSign );
}

/*-----------------------------------------------------------*/

static void prvTestEcVerify( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;
    CK_OBJECT_HANDLE xCertificateHandle;
    CK_MECHANISM xMechanism;
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0xbe };
    CK_BYTE xSignature[ pkcs11ECDSA_P256_SIGNATURE_LENGTH + 10 ] = { 0 };
    CK_BYTE xSignaturePKCS[ 64 ] = { 0 };
    size_t xSignatureLength = pkcs11ECDSA_P256_SIGNATURE_LENGTH;

    mbedtls_pk_context xPkContext;
    mbedtls_entropy_context xEntropyContext;
    mbedtls_ctr_drbg_context xDrbgContext;
    int lMbedResult;

    /* TODO: Consider switching this out for a C_GenerateRandom dependent function for ports not implementing mbedTLS. */

    /* Find objects that were previously created. This test case should be run if
     * there are objects that exists under known labels. This test case is not
     * responsible for creating the objects used for signing. */
    prvFindObjectTest( &xPrivateKeyHandle, &xCertificateHandle, &xPublicKeyHandle );

    /* Sign data w/ PKCS. */
    xMechanism.mechanism = CKM_ECDSA;
    xMechanism.pParameter = NULL;
    xMechanism.ulParameterLen = 0;
    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "SignInit failed." );
    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashedMessage, sizeof( xHashedMessage ), xSignature, ( CK_ULONG * ) &xSignatureLength );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Sign failed." );

    xResult = pxGlobalFunctionList->C_VerifyInit( xGlobalSession, &xMechanism, xPublicKeyHandle );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "VerifyInit failed." );

    xResult = pxGlobalFunctionList->C_Verify( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, sizeof( xSignaturePKCS ) );
    TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Verify failed." );

    if( testProvisionMethod == eProvisionImportPrivateKey )
    {
        /* Initialize the RNG. */
        mbedtls_entropy_init( &xEntropyContext );
        mbedtls_ctr_drbg_init( &xDrbgContext );

        /* Initialize the private key. */
        mbedtls_pk_init( &xPkContext );

        if( TEST_PROTECT() )
        {
            lMbedResult = mbedtls_ctr_drbg_seed( &xDrbgContext, mbedtls_entropy_func, &xEntropyContext, NULL, 0 );
            TEST_ASSERT_MESSAGE( ( 0 == lMbedResult ), "Failed to initialize DRBG" );

            #if MBEDTLS_VERSION_NUMBER < 0x03000000
                lMbedResult = mbedtls_pk_parse_key( &xPkContext,
                                                    ( const unsigned char * ) cValidECDSAPrivateKey,
                                                    sizeof( cValidECDSAPrivateKey ),
                                                    NULL,
                                                    0 );
                TEST_ASSERT_MESSAGE( ( 0 == lMbedResult ), "Failed to parse valid ECDSA key." );

                lMbedResult = mbedtls_pk_sign( &xPkContext, MBEDTLS_MD_SHA256, xHashedMessage, sizeof( xHashedMessage ),
                    xSignature, &xSignatureLength, mbedtls_ctr_drbg_random, &xDrbgContext );
                TEST_ASSERT_MESSAGE( ( 0 == lMbedResult ), "Failed to perform ECDSA signature." );

            #else
                lMbedResult = mbedtls_pk_parse_key( &xPkContext,
                                                    ( const unsigned char * ) cValidECDSAPrivateKey,
                                                    sizeof( cValidECDSAPrivateKey ),
                                                    NULL,
                                                    0,
                                                    mbedtls_ctr_drbg_random, &xDrbgContext );
                TEST_ASSERT_MESSAGE( ( 0 == lMbedResult ), "Failed to parse valid ECDSA key." );

                lMbedResult = mbedtls_pk_sign( &xPkContext, MBEDTLS_MD_SHA256, xHashedMessage, sizeof( xHashedMessage ),
                    xSignature, sizeof( xSignature), &xSignatureLength, mbedtls_ctr_drbg_random, &xDrbgContext );
                TEST_ASSERT_MESSAGE( ( 0 == lMbedResult ), "Failed to perform ECDSA signature." );
            #endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */

            /* Reconstruct the signature in PKCS #11 format. */
            lMbedResult = PKI_mbedTLSSignatureToPkcs11Signature( xSignaturePKCS,
                                                                 xSignature );
            TEST_ASSERT_MESSAGE( ( 0 == lMbedResult ), "Null buffers." );

            /* Verify with PKCS #11. */
            xMechanism.mechanism = CKM_ECDSA;
            xMechanism.pParameter = NULL;
            xMechanism.ulParameterLen = 0;
            xResult = pxGlobalFunctionList->C_VerifyInit( xGlobalSession, &xMechanism, xPublicKeyHandle );
            TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "VerifyInit failed." );

            xResult = pxGlobalFunctionList->C_Verify( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignaturePKCS, sizeof( xSignaturePKCS ) );
            TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Verify failed." );
        }

        mbedtls_pk_free( &xPkContext );
        mbedtls_ctr_drbg_free( &xDrbgContext );
        mbedtls_entropy_free( &xEntropyContext );
    }
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_EC, PKCS11_EC_Verify )
{
    prvEcObjectTestHelper( prvTestEcVerify );
}

/*-----------------------------------------------------------*/

static void prvTestEcFindObjectMultiThread( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult;
    uint32_t xTaskNumber;
    CK_SESSION_HANDLE xSessionHandle[ PKCS11_TEST_MULTI_THREAD_TASK_COUNT ];
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;
    CK_OBJECT_HANDLE xCertificateHandle;

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = xInitializePkcs11Session( &xSessionHandle[ xTaskNumber ] );

        if( xResult != CKR_USER_ALREADY_LOGGED_IN )
        {
            TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 session." );
        }

        xGlobalTaskParams[ xTaskNumber ].pvTaskData = &xSessionHandle[ xTaskNumber ];
    }

    prvFindObjectTest( &xPrivateKeyHandle, &xCertificateHandle, &xPublicKeyHandle );

    prvMultiThreadHelper( prvFindObjectMultiThreadTask );

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = pxGlobalFunctionList->C_CloseSession( xSessionHandle[ xTaskNumber ] );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to close session." );
    }
}

/*-----------------------------------------------------------*/

/* Different session trying to find token objects. */
TEST( Full_PKCS11_EC, PKCS11_EC_FindObjectMultiThread )
{
    prvEcObjectTestHelper( prvTestEcFindObjectMultiThread );
}

/*-----------------------------------------------------------*/

/* Thread function of PKCS11_GetAttributeValueMultiThread test case. */
static void prvECGetAttributeValueMultiThreadTask( void * pvParameters )
{
    MultithreadTaskParams_t * pxMultiTaskParam = pvParameters;
    GetAttributeValueMultiThread_t * pxAttributeStruct = pxMultiTaskParam->pvTaskData;
    CK_OBJECT_HANDLE xCertificate = pxAttributeStruct->xCertificate;
    CK_OBJECT_HANDLE xPrivateKey = pxAttributeStruct->xPrivateKey;
    uint32_t xCount;
    CK_RV xResult = CKR_OK;
    CK_SESSION_HANDLE xSession = pxAttributeStruct->xSession;
    CK_ATTRIBUTE xTemplate;
    CK_BYTE xEcParamsExpected[] = pkcs11DER_ENCODED_OID_P256;
    CK_BYTE xEcParams[ sizeof( xEcParamsExpected ) ];
    CK_BYTE xCertificateValue[ 1000 ]; /* TODO: Probably need a max cert length supported per-port. */
    int lMbedReturn;
    mbedtls_x509_crt xMbedCert;

    for( xCount = 0; xCount < PKCS11_TEST_MULTI_THREAD_LOOP_COUNT; xCount++ )
    {
        xTemplate.type = CKA_EC_PARAMS;
        xTemplate.pValue = xEcParams;
        xTemplate.ulValueLen = sizeof( xEcParams );

        xResult = pxGlobalFunctionList->C_GetAttributeValue( xSession, xPrivateKey, &xTemplate, 1 );

        if( xResult != CKR_OK )
        {
            TEST_PRINTF( "GetAttributeValue multithread test failed to get private key's EC Params.  Error: %ld  Count: %d ", xResult, xCount );
            break;
        }

        if( memcmp( xEcParams, xEcParamsExpected, sizeof( xEcParams ) ) )
        {
            TEST_PRINTF( "GetAttributeValue multithread test returned an incorrect value for EC Params.  Error: %ld  Count: %d ", xResult, xCount );
            xResult = 1;
            break;
        }

        xTemplate.type = CKA_VALUE;
        xTemplate.pValue = xCertificateValue;
        xTemplate.ulValueLen = sizeof( xCertificateValue );
        xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificate, &xTemplate, 1 );

        if( xResult != CKR_OK )
        {
            TEST_PRINTF( "GetAttributeValue multi-thread task failed to get certificate.  Error: %ld  Count: %d ", xResult, xCount );
            xResult = 1;
            break;
        }

        /* Check that the certificate parses. */
        mbedtls_x509_crt_init( &xMbedCert );

        lMbedReturn = mbedtls_x509_crt_parse( &xMbedCert, xTemplate.pValue, xTemplate.ulValueLen );

        if( lMbedReturn != 0 )
        {
            TEST_PRINTF( "GetAttributeValue multi-thread task found an invalid certificate value. Parse error: %d,  Count: %d ", lMbedReturn, xCount );
            TEST_PRINTF( "First 3 bytes of invalid certificate found are %d, %d, %d ", ( int ) xCertificateValue[ 0 ], ( int ) xCertificateValue[ 1 ], ( int ) xCertificateValue[ 2 ] );
            xResult = 1;
            break;
        }

        mbedtls_x509_crt_free( &xMbedCert );
    }

    /* Report the result of the loop. */
    pxMultiTaskParam->xTestResult = xResult;
}

/*-----------------------------------------------------------*/

static void prvTestEcGetAttributeValueMultiThread( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult;
    uint32_t xTaskNumber;
    GetAttributeValueMultiThread_t xAttributeStruct[ PKCS11_TEST_MULTI_THREAD_TASK_COUNT ];
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xCertificate;
    CK_OBJECT_HANDLE xPublicKey;

    prvFindObjectTest( &xPrivateKey, &xCertificate, &xPublicKey );

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = xInitializePkcs11Session( &xAttributeStruct[ xTaskNumber ].xSession );
        xAttributeStruct[ xTaskNumber ].xPrivateKey = xPrivateKey;
        xAttributeStruct[ xTaskNumber ].xCertificate = xCertificate;
        xAttributeStruct[ xTaskNumber ].xPublicKey = xPublicKey;

        if( xResult != CKR_USER_ALREADY_LOGGED_IN )
        {
            TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 session." );
        }

        xGlobalTaskParams[ xTaskNumber ].pvTaskData = &xAttributeStruct[ xTaskNumber ];
    }

    prvMultiThreadHelper( prvECGetAttributeValueMultiThreadTask );

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = pxGlobalFunctionList->C_CloseSession( xAttributeStruct[ xTaskNumber ].xSession );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to close session." );
    }
}

/*-----------------------------------------------------------*/

/* Same & different PKCS #11 sessions asking for attribute values of the same 2 objects. */
TEST( Full_PKCS11_EC, PKCS11_EC_GetAttributeValueMultiThread )
{
    prvEcObjectTestHelper( prvTestEcGetAttributeValueMultiThread );
}

/*-----------------------------------------------------------*/

/* Thread function of PKCS11_SignVerifyMultiThread test. */
static void prvECSignVerifyMultiThreadTask( void * pvParameters )
{
    MultithreadTaskParams_t * pxMultiTaskParam = pvParameters;
    SignVerifyMultiThread_t * pxSignStruct = pxMultiTaskParam->pvTaskData;
    CK_SESSION_HANDLE xSession = pxSignStruct->xSession;
    CK_OBJECT_HANDLE xPrivateKey = pxSignStruct->xPrivateKey;
    CK_OBJECT_HANDLE xPublicKey = pxSignStruct->xPublicKey;
    uint32_t xCount;
    CK_RV xResult;
    /* Note that ECDSA operations on a signature of all 0's is not permitted. */
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0xab };
    CK_MECHANISM xMechanism;
    CK_BYTE xSignature[ 64 ] = { 0 };
    CK_ULONG xSignatureLength;

    for( xCount = 0; xCount < PKCS11_TEST_MULTI_THREAD_LOOP_COUNT; xCount++ )
    {
        xMechanism.mechanism = CKM_ECDSA;
        xMechanism.pParameter = NULL;
        xMechanism.ulParameterLen = 0;
        xResult = pxGlobalFunctionList->C_SignInit( xSession, &xMechanism, xPrivateKey );

        if( xResult != CKR_OK )
        {
            TEST_PRINTF( "Sign multi-threaded test failed to SignInit. Error: %ld  Count: %d ", xResult, xCount );
            break;
        }

        xSignatureLength = sizeof( xSignature );
        xResult = pxGlobalFunctionList->C_Sign( xSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, &xSignatureLength );

        if( xResult != CKR_OK )
        {
            TEST_PRINTF( "Sign multi-threaded test failed to Sign. Error: %ld  Count: %d ", xResult, xCount );
            break;
        }

        xResult = pxGlobalFunctionList->C_VerifyInit( xSession, &xMechanism, xPublicKey );

        if( xResult != CKR_OK )
        {
            TEST_PRINTF( "Multithread VerifyInit failed.  Error:     %ld, Count: %d ", xResult, xCount );
            break;
        }

        xResult = pxGlobalFunctionList->C_Verify( xSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, sizeof( xSignature ) );

        if( xResult != CKR_OK )
        {
            TEST_PRINTF( "Multithread Verify failed.  Error: %ld, Count: %d ", xResult, xCount );
            break;
        }
    }

    /* Report the result of the loop. */
    pxMultiTaskParam->xTestResult = xResult;
}

/*-----------------------------------------------------------*/

static void prvTestEcSignVerifyMultiThread( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult;
    uint32_t xTaskNumber;
    SignVerifyMultiThread_t xSignStructs[ PKCS11_TEST_MULTI_THREAD_TASK_COUNT ];
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xCertificate;
    CK_OBJECT_HANDLE xPublicKey;

    prvFindObjectTest( &xPrivateKey, &xCertificate, &xPublicKey );

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = xInitializePkcs11Session( &xSignStructs[ xTaskNumber ].xSession );

        if( xResult != CKR_USER_ALREADY_LOGGED_IN )
        {
            TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to initialize PKCS #11 session." );
        }

        xSignStructs[ xTaskNumber ].xPrivateKey = xPrivateKey;
        xSignStructs[ xTaskNumber ].xPublicKey = xPublicKey;
        xGlobalTaskParams[ xTaskNumber ].pvTaskData = &xSignStructs[ xTaskNumber ];
    }

    prvMultiThreadHelper( prvECSignVerifyMultiThreadTask );

    for( xTaskNumber = 0; xTaskNumber < PKCS11_TEST_MULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = pxGlobalFunctionList->C_CloseSession( xSignStructs[ xTaskNumber ].xSession );
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ), "Failed to close session." );
    }
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_EC, PKCS11_EC_SignVerifyMultiThread )
{
    prvEcObjectTestHelper( prvTestEcSignVerifyMultiThread );
}

/*-----------------------------------------------------------*/

static void prvTestEcDestroyObject( provisionMethod_t testProvisionMethod )
{
    CK_RV xResult;

    if( testProvisionMethod != eProvisionPreprovisioned )
    {
        xResult = prvDestroyTestCredentials();
        TEST_ASSERT_MESSAGE( ( CKR_OK == xResult ),
                             "Failed to destroy credentials in test setup." );
    }
}

/*-----------------------------------------------------------*/

TEST( Full_PKCS11_EC, PKCS11_EC_DestroyObject )
{
    prvEcObjectTestHelper( prvTestEcDestroyObject );
}

/*-----------------------------------------------------------*/

int RunPkcs11Test( void )
{
    int status = -1;

    /* Initialize unity. */
    UnityFixture.Verbose = 1;
    UnityFixture.GroupFilter = 0;
    UnityFixture.NameFilter = 0;
    UnityFixture.RepeatCount = 1;
    UNITY_BEGIN();

    /* Basic general purpose and slot token management tests. */
    RUN_TEST_GROUP( Full_PKCS11_StartFinish );

    /* Cryptoki capabilities test. */
    RUN_TEST_GROUP( Full_PKCS11_Capabilities );

    /* Digest and random number generate test. */
    RUN_TEST_GROUP( Full_PKCS11_NoObject );

    /* RSA key function test. */
    RUN_TEST_GROUP( Full_PKCS11_RSA );

    /* EC key function test. */
    RUN_TEST_GROUP( Full_PKCS11_EC );

    status = UNITY_END();

    return status;
}

/*-----------------------------------------------------------*/

#endif /* if ( CORE_PKCS11_TEST_ENABLED == 1 ) */
