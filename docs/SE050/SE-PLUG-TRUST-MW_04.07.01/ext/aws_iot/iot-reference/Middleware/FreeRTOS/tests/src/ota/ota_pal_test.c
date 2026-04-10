/**
 * @file ota_pal_test.c
 * @brief Various tests for validating an implementation to the OTA PAL.
 */

#include "test_execution_config.h"
#if ( OTA_PAL_TEST_ENABLED == 1 )

/* Standard includes. */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/* Unity Test framework include. */
#include "unity_fixture.h"
#include "unity.h"

/* Include OTA headers. */
#include "ota.h"
#include "ota_appversion32.h"
#include "ota_pal.h"

#include "ota_pal_test.h"
#include "test_param_config.h"

#ifndef OTA_PAL_TEST_CERT_TYPE
    #error "Please define OTA_PAL_TEST_CERT_TYPE"
#endif

#if( OTA_PAL_TEST_CERT_TYPE == OTA_RSA_SHA1 )
    #include "aws_test_ota_pal_rsa_sha1_signature.h"
#elif( OTA_PAL_TEST_CERT_TYPE == OTA_RSA_SHA256 )
    #include "aws_test_ota_pal_rsa_sha256_signature.h"
#elif( OTA_PAL_TEST_CERT_TYPE == OTA_ECDSA_SHA256 )
    #include "aws_test_ota_pal_ecdsa_sha256_signature.h"
#else
    #error "Invalid OTA_PAL_TEST_CERT_TYPE"
#endif

/* For the otaPal_WriteBlock_WriteManyBlocks test this is the number of blocks
 * of ucDummyData to write to the non-volatile memory. */
#define testotapalNUM_WRITE_BLOCKS         10

static OtaPalTestParam_t testParam;

/*
 * @brief: This dummy data is prepended by a SHA1 hash generated from the
 * rsa-sha1-signer certificate and keys in tests/common/ota/test_files.
 *
 * The RSA SHA256 signature and ECDSA 256 signature are generated from this
 * entire data block as is.
 */
static uint8_t ucDummyData[] =
{
    0x83, 0x0b, 0xf0, 0x6a, 0x81, 0xd6, 0xca, 0xd7, 0x08, 0x22, 0x0d, 0x6a,
    0x33, 0xfa, 0x31, 0x9f, 0xa9, 0x5f, 0xb5, 0x26, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0c, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};

/* Global static OTA file context used in every test. This variable is reset to
 * all zeros before every test. */
static OtaFileContext_t xOtaFile;

/**
 * @brief Test group definition.
 */
TEST_GROUP( Full_OTA_PAL );

TEST_SETUP( Full_OTA_PAL )
{
    /* Reset the OTA file context before each test. */
    memset( &xOtaFile, 0, sizeof( xOtaFile ) );
}

TEST_TEAR_DOWN( Full_OTA_PAL )
{
    OtaPalStatus_t xOtaStatus;

    /* Abort the OTA file after every test. This closes the OTA file.
     * otaPal_Abort should only return OtaPalSuccess or OtaPalAbortFailed. */
    xOtaStatus = otaPal_Abort( &xOtaFile );
    TEST_ASSERT( OTA_PAL_MAIN_ERR( xOtaStatus ) == OtaPalSuccess ||
                 OTA_PAL_MAIN_ERR( xOtaStatus ) == OtaPalAbortFailed );
}

TEST_GROUP_RUNNER( Full_OTA_PAL )
{
    /************* otaPAL_CloseFile Tests *************/
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_CloseFile_ValidSignature );
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_CloseFile_InvalidSignatureBlockWritten );
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_CloseFile_InvalidSignatureNoBlockWritten );
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_CloseFile_NonexistingCodeSignerCertificate );

    /********** otaPal_CreateFileForRx Tests **********/
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_CreateFileForRx_CreateAnyFile );

    /* Other failure case testing for otaPal_CreateFileForRx() is not possible
     * because the MCU's underlying non-volatile memory will have to be mocked
     * to return failures for creating a new file. */

    /*************** otaPal_Abort Tests ***************/
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_Abort_OpenFile );
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_Abort_FileWithBlockWritten );
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_Abort_NullFileHandle );
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_Abort_NonExistentFile );

    /************* otaPal_WriteBlock Tests ************/
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_WriteBlock_WriteSingleByte );
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_WriteBlock_WriteManyBlocks );

    /******** otaPal_SetPlatformImageState Tests ******/
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_SetPlatformImageState_AcceptedStateWithoutClose );
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_SetPlatformImageState_InvalidImageState );
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_SetPlatformImageState_UnknownImageState );

    /* Setting the image with the accepted state is not supported because that
     * requires an image that was written, verified, and rebooted. */

    /******* otaPal_GetPlatformImageState Tests *******/
    RUN_TEST_CASE( Full_OTA_PAL, otaPal_GetPlatformImageState_InvalidImageStateFromFileCloseFailure );
}

/**
 * @brief Test otaPal_CloseFile with a valid signature and signature verification
 * certificate. Verify the success.
 */
TEST( Full_OTA_PAL, otaPal_CloseFile_ValidSignature )
{
    OtaPalStatus_t xOtaStatus;
    Sig_t xSig = { 0 };
    int16_t bytesWritten;

    /* We use a dummy file name here because closing the system designated bootable
     * image with content that is not runnable may cause issues. */
    xOtaFile.pFilePath = ( uint8_t * ) ( "test_happy_path_image.bin" );
    xOtaFile.fileSize = sizeof( ucDummyData );
    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* We still want to close the file if the test fails somewhere here. */
    if( TEST_PROTECT() )
    {
        /* Write data to the file. */
        bytesWritten = otaPal_WriteBlock( &xOtaFile,
                                           0,
                                           ucDummyData,
                                           sizeof( ucDummyData ) );
        TEST_ASSERT_EQUAL( sizeof( ucDummyData ), bytesWritten );

        xOtaFile.pSignature = &xSig;
        xOtaFile.pSignature->size = ucValidSignatureLength;
        memcpy( xOtaFile.pSignature->data, ucValidSignature, ucValidSignatureLength );
        xOtaFile.pCertFilepath = ( uint8_t * ) OTA_PAL_CERTIFICATE_FILE;

        xOtaStatus = otaPal_CloseFile( &xOtaFile );
        TEST_ASSERT_EQUAL_INT( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );
    }
}

/**
 * @brief Call otaPal_CloseFile with an invalid signature in the file context.
 * The close is called after we have a written a block of dummy data to the file.
 * Verify the correct OTA Agent level error code is returned from otaPal_CloseFile.
 */
TEST( Full_OTA_PAL, otaPal_CloseFile_InvalidSignatureBlockWritten )
{
    OtaPalStatus_t xOtaStatus;
    Sig_t xSig = { 0 };
    int16_t bytesWritten;

    /* Create a local file using the PAL. */
    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );

    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* We still want to close the file if the test fails somewhere here. */
    if( TEST_PROTECT() )
    {
        /* Write data to the file. */
        bytesWritten = otaPal_WriteBlock( &xOtaFile,
                                           0,
                                           ucDummyData,
                                           sizeof( ucDummyData ) );
        TEST_ASSERT_EQUAL( sizeof( ucDummyData ), bytesWritten );

        /* Fill out an incorrect signature. */
        xOtaFile.pSignature = &xSig;
        xOtaFile.pSignature->size = ucInvalidSignatureLength;
        memcpy( xOtaFile.pSignature->data, ucInvalidSignature, ucInvalidSignatureLength );
        xOtaFile.pCertFilepath = ( uint8_t * ) OTA_PAL_CERTIFICATE_FILE;

        /* Try to close the file. */
        xOtaStatus = otaPal_CloseFile( &xOtaFile );
        TEST_ASSERT_EQUAL( OtaPalSignatureCheckFailed, OTA_PAL_MAIN_ERR( xOtaStatus ) );
    }
}

/**
 * @brief Call otaPal_CloseFile with an invalid signature in the file context.
 * The close is called when no blocks have been written to the file.
 * Verify the correct OTA Agent level error code is returned from otaPal_CloseFile.
 */
TEST( Full_OTA_PAL, otaPal_CloseFile_InvalidSignatureNoBlockWritten )
{
    OtaPalStatus_t xOtaStatus;
    Sig_t xSig = { 0 };

    /* Create a local file using the PAL. */
    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );
    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* Fill out an incorrect signature. */
    xOtaFile.pSignature = &xSig;
    xOtaFile.pSignature->size = ucInvalidSignatureLength;
    memcpy( xOtaFile.pSignature->data, ucInvalidSignature, ucInvalidSignatureLength );
    xOtaFile.pCertFilepath = ( uint8_t * ) OTA_PAL_CERTIFICATE_FILE;

    /* We still want to close the file if the test fails somewhere here. */
    if( TEST_PROTECT() )
    {
        /* Try to close the file. */
        xOtaStatus = otaPal_CloseFile( &xOtaFile );
        TEST_ASSERT_EQUAL( OtaPalSignatureCheckFailed, OTA_PAL_MAIN_ERR( xOtaStatus ) );
    }
}

/**
 * @brief Call otaPal_CloseFile with a signature verification certificate path does
 * not exist in the system. Verify the correct OTA Agent level error code is returned
 * from otaPal_CloseFile.
 *
 * @note This test is only valid if your device uses a file system in your non-volatile memory.
 * Some devices may revert to using aws_codesigner_certificate.h if a file is not found, but
 * that option is not being enforced.
 */
TEST( Full_OTA_PAL, otaPal_CloseFile_NonexistingCodeSignerCertificate )
{
    #if ( OTA_PAL_USE_FILE_SYSTEM == 1 )
        OtaPalStatus_t xOtaStatus;
        Sig_t xSig = { 0 };
        int16_t bytesWritten;

        memset( &xOtaFile, 0, sizeof( xOtaFile ) );

        /* Create a local file using the PAL. */
        xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
        xOtaFile.fileSize = sizeof( ucDummyData );

        xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
        TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

        /* We still want to close the file if the test fails somewhere here. */
        if( TEST_PROTECT() )
        {
            /* Write data to the file. */
            bytesWritten = otaPal_WriteBlock( &xOtaFile,
                                               0,
                                               ucDummyData,
                                               sizeof( ucDummyData ) );
            TEST_ASSERT_EQUAL( sizeof( ucDummyData ), bytesWritten );

            /* Check the signature (not expected to be valid in this case). */
            xOtaFile.pSignature = &xSig;
            xOtaFile.pSignature->size = ucValidSignatureLength;
            memcpy( xOtaFile.pSignature->data, ucValidSignature, ucValidSignatureLength );
            xOtaFile.pCertFilepath = ( uint8_t * ) ( "nonexistingfile.crt" );

            xOtaStatus = otaPal_CloseFile( &xOtaFile );
            TEST_ASSERT_EQUAL( OtaPalBadSignerCert , OTA_PAL_MAIN_ERR( xOtaStatus ) );
        }
    #endif /* if ( OTA_PAL_USE_FILE_SYSTEM == 1 ) */
}

/**
 * @brief Create a file with any name, and verify success.
 */
TEST( Full_OTA_PAL, otaPal_CreateFileForRx_CreateAnyFile )
{
    OtaPalStatus_t xOtaStatus;

    memset( &xOtaFile, 0, sizeof( OtaFileContext_t ) );

    /* TEST: Create a local file using the PAL. Verify error in close. */
    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );
    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );
}

/**
 * @brief Abort on an open file. Verify success.
 */
TEST( Full_OTA_PAL, otaPal_Abort_OpenFile )
{
    OtaPalStatus_t xOtaStatus;

    memset( &xOtaFile, 0, sizeof( OtaFileContext_t ) );

    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );

    /* Create a local file using the PAL. */
    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* Signal that the download is being aborted. */
    xOtaStatus = otaPal_Abort( &xOtaFile );
    TEST_ASSERT_EQUAL_INT( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* Verify that the file handle is null. */
    TEST_ASSERT_EQUAL_INT( NULL, xOtaFile.pFile );
}

/**
 * @brief Abort after writing a block to an open file. Verify success.
 */
TEST( Full_OTA_PAL, otaPal_Abort_FileWithBlockWritten )
{
    OtaPalStatus_t xOtaStatus;
    int16_t bytesWritten;

    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );

    /* Create a local file again using the PAL. */
    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* We still want to close the file if the test fails here. */
    if( TEST_PROTECT() )
    {
        /* Write data to the file. */
        bytesWritten = otaPal_WriteBlock( &xOtaFile,
                                           0,
                                           ucDummyData,
                                           sizeof( ucDummyData ) );
        TEST_ASSERT_EQUAL( sizeof( ucDummyData ), bytesWritten );
    }

    /* Signal that the download is being aborted. */
    xOtaStatus = otaPal_Abort( &xOtaFile );
    TEST_ASSERT_EQUAL_INT( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* Verify that the file handle is null. */
    TEST_ASSERT_EQUAL_INT( NULL, xOtaFile.pFile );
}

/**
 * @brief Call otaPal_Abort on a NULL file handle. Verify there is no error.
 */
TEST( Full_OTA_PAL, otaPal_Abort_NullFileHandle )
{
    OtaPalStatus_t xOtaStatus;

    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.pFile = 0;

    xOtaStatus = otaPal_Abort( &xOtaFile );
    TEST_ASSERT_EQUAL_INT( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );
}

/**
 * @brief Verify there is no error for aborting a file that doesn't exist.
 */
TEST( Full_OTA_PAL, otaPal_Abort_NonExistentFile )
{
    OtaPalStatus_t xOtaStatus;

    xOtaFile.pFilePath = ( uint8_t * ) ( "nonexistingfile.bin" );

    xOtaStatus = otaPal_Abort( &xOtaFile );
    TEST_ASSERT_EQUAL_INT( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );
}

/**
 * @brief Write one byte of data and verify success.
 */
TEST( Full_OTA_PAL, otaPal_WriteBlock_WriteSingleByte )
{
    OtaPalStatus_t xOtaStatus;
    int16_t bytesWritten;
    uint8_t ucData = 0xAA;

    /* TEST: Write a byte of data. */
    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );
    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    if( TEST_PROTECT() )
    {
        bytesWritten = otaPal_WriteBlock( &xOtaFile, 0, &ucData, 1 );
        TEST_ASSERT_EQUAL_INT( 1, bytesWritten );
    }
}

/**
 * @brief Write many blocks of data to a file opened in the device. Verify success.
 *
 * Because of Flash property, we might not able to write same page multiple times.
 * So we write one block into one page.
 */
TEST( Full_OTA_PAL, otaPal_WriteBlock_WriteManyBlocks )
{
    OtaPalStatus_t xOtaStatus;
    int16_t bytesWritten;

    /* The page size must >= dummy data size, so that we can write whole dummy data in one operation. */
    TEST_ASSERT_LESS_OR_EQUAL( testParam.pageSize, sizeof( ucDummyData ) );

    /* Some platforms compare the offset and file size, and it's not legal to write when offset > filesize.
     * We just set file size to the number of block size to make sure file size is big enough for every write. */
    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = testParam.pageSize * testotapalNUM_WRITE_BLOCKS;
    /* TEST: Write many bytes of data. */

    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    if( TEST_PROTECT() )
    {
        int lIndex = 0;
        uint32_t writeOffset = 0;

        for( lIndex = 0; lIndex < testotapalNUM_WRITE_BLOCKS; lIndex++ )
        {
            bytesWritten = otaPal_WriteBlock( &xOtaFile, writeOffset, ucDummyData, sizeof( ucDummyData ) );
            TEST_ASSERT_EQUAL_INT( sizeof( ucDummyData ), bytesWritten );

            /* Align the writeOff with page size */
            writeOffset = writeOffset + testParam.pageSize;
        }
    }
}

/**
 * @brief Set the platform state to accepted before closing the file.
 * This should result in otaPal_SetPlatformImageState returning OtaPalCommitFailed.
 */
TEST( Full_OTA_PAL, otaPal_SetPlatformImageState_AcceptedStateWithoutClose )
{
    OtaPalStatus_t xOtaStatus;
    OtaImageState_t eImageState = OtaImageStateUnknown;
    int16_t bytesWritten;

    /* Create a local file again using the PAL. */
    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );

    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* We still want to close the file if the test fails. */
    if( TEST_PROTECT() )
    {
        /* Write data to the file. */
        bytesWritten = otaPal_WriteBlock( &xOtaFile,
                                           0,
                                           ucDummyData,
                                           sizeof( ucDummyData ) );
        TEST_ASSERT_EQUAL( sizeof( ucDummyData ), bytesWritten );

        /* Set the image state. */
        eImageState = OtaImageStateAccepted;
        xOtaStatus = otaPal_SetPlatformImageState( &xOtaFile, eImageState );
        TEST_ASSERT_EQUAL_INT( OtaPalCommitFailed, OTA_PAL_MAIN_ERR( xOtaStatus ) );
    }
}

/**
 * @brief Set an invalid platform image state exceeding the range and verify
 * the expected error code is returned.
 */
TEST( Full_OTA_PAL, otaPal_SetPlatformImageState_InvalidImageState )
{
    OtaPalStatus_t xOtaStatus;
    OtaImageState_t eImageState = OtaImageStateUnknown;
    int16_t bytesWritten;

    /* Create a local file again using the PAL. */
    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );

    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* We still want to close the file if the test fails. */
    if( TEST_PROTECT() )
    {
        /* Write data to the file. */
        bytesWritten = otaPal_WriteBlock( &xOtaFile,
                                           0,
                                           ucDummyData,
                                           sizeof( ucDummyData ) );
        TEST_ASSERT_EQUAL( sizeof( ucDummyData ), bytesWritten );

        /* Try to set an invalid image state. */
        eImageState = ( OtaImageState_t ) ( OtaLastImageState + 1 );
        xOtaStatus = otaPal_SetPlatformImageState( &xOtaFile, eImageState );
        TEST_ASSERT_EQUAL( OtaPalBadImageState, OTA_PAL_MAIN_ERR( xOtaStatus ) );
    }
}

/**
 * @brief Set the image state to unknown and verify a failure.
 */
TEST( Full_OTA_PAL, otaPal_SetPlatformImageState_UnknownImageState )
{
    OtaPalStatus_t xOtaStatus;
    OtaImageState_t eImageState = OtaImageStateUnknown;
    int16_t bytesWritten;

    /* Create a local file again using the PAL. */
    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );

    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* We still want to close the file if the test fails. */
    if( TEST_PROTECT() )
    {
        /* Write data to the file. */
        bytesWritten = otaPal_WriteBlock( &xOtaFile,
                                           0,
                                           ucDummyData,
                                           sizeof( ucDummyData ) );
        TEST_ASSERT_EQUAL( sizeof( ucDummyData ), bytesWritten );

        /* Try to set an invalid image state. */
        eImageState = OtaImageStateUnknown;
        xOtaStatus = otaPal_SetPlatformImageState( &xOtaFile, eImageState );
        TEST_ASSERT_EQUAL( OtaPalBadImageState, OTA_PAL_MAIN_ERR( xOtaStatus ) );
    }
}

/**
 * @brief Set the platform image state to aborted.
 * We cannot test a abort failed without mocking the underlying non-volatile memory.
 */
TEST( Full_OTA_PAL, otaPal_SetPlatformImageState_AbortImageState )
{
    OtaPalStatus_t xOtaStatus;
    OtaImageState_t eImageState = OtaImageStateUnknown;
    int16_t bytesWritten;

    /* Create a local file again using the PAL. */
    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );

    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* We still want to close the file if the test fails. */
    if( TEST_PROTECT() )
    {
        /* Write data to the file. */
        bytesWritten = otaPal_WriteBlock( &xOtaFile,
                                           0,
                                           ucDummyData,
                                           sizeof( ucDummyData ) );
        TEST_ASSERT_EQUAL( sizeof( ucDummyData ), bytesWritten );

        eImageState = OtaImageStateAborted;
        xOtaStatus = otaPal_SetPlatformImageState( &xOtaFile, eImageState );
        TEST_ASSERT_EQUAL_INT( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );
        eImageState = OtaImageStateUnknown;
        eImageState = otaPal_GetPlatformImageState( &xOtaFile );
        TEST_ASSERT_EQUAL( OtaImageStateAborted, eImageState);
    }
}

/**
 * @brief Verify that the current image received is in the invalid state after a
 * failure to close the file because of a bad signature.
 */
TEST( Full_OTA_PAL, otaPal_GetPlatformImageState_InvalidImageStateFromFileCloseFailure )
{
    OtaPalStatus_t xOtaStatus;
    Sig_t xSig = { 0 };
    OtaPalImageState_t ePalImageState = OtaPalImageStateUnknown;
    int16_t bytesWritten;

    /* TEST: Invalid image returned from otaPal_GetPlatformImageState(). Using a failure to close. */
    /* Create a local file again using the PAL. */
    xOtaFile.pFilePath = ( uint8_t * ) OTA_PAL_FIRMWARE_FILE;
    xOtaFile.fileSize = sizeof( ucDummyData );

    xOtaStatus = otaPal_CreateFileForRx( &xOtaFile );
    TEST_ASSERT_EQUAL( OtaPalSuccess, OTA_PAL_MAIN_ERR( xOtaStatus ) );

    /* We still want to close the file if the test fails. */
    if( TEST_PROTECT() )
    {
        /* Write data to the file. */
        bytesWritten = otaPal_WriteBlock( &xOtaFile,
                                           0,
                                           ucDummyData,
                                           sizeof( ucDummyData ) );
        TEST_ASSERT_EQUAL( sizeof( ucDummyData ), bytesWritten );

        /* Check the signature. */
        xOtaFile.pSignature = &xSig;
        xOtaFile.pSignature->size = ucInvalidSignatureLength;
        memcpy( xOtaFile.pSignature->data, ucInvalidSignature, ucInvalidSignatureLength );
        xOtaFile.pCertFilepath = ( uint8_t * ) OTA_PAL_CERTIFICATE_FILE;

        xOtaStatus = otaPal_CloseFile( &xOtaFile );
        TEST_ASSERT_EQUAL( OtaPalSignatureCheckFailed, OTA_PAL_MAIN_ERR( xOtaStatus ) );

        /* The file failed to close, so it is invalid or in an unknown state. */
        ePalImageState = otaPal_GetPlatformImageState( &xOtaFile );
        TEST_ASSERT( ( OtaPalImageStateInvalid == ePalImageState ) || ( OtaPalImageStateUnknown == ePalImageState ) );
    }
}

/*-----------------------------------------------------------*/

int RunOtaPalTest( void )
{
    int status = -1;
    SetupOtaPalTestParam( &testParam );

    /* Initialize unity. */
    UnityFixture.Verbose = 1;
    UnityFixture.GroupFilter = 0;
    UnityFixture.NameFilter = 0;
    UnityFixture.RepeatCount = 1;

    UNITY_BEGIN();

    /* Run the test group. */
    RUN_TEST_GROUP( Full_OTA_PAL );

    status = UNITY_END();
    return status;
}

/*-----------------------------------------------------------*/

#endif /* if ( OTA_TEST_ENABLED == 1 ) */
