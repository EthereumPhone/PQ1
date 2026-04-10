# OTA Platform Abstraction Layer (PAL) Test

## On this page:
1. [Introduction](#1-introduction)
2. [OTA PAL Test Cases](#2-ota-pal-test-cases)
3. [Prerequisites For OTA PAL Test](#3-prerequisites-for-ota-pal-test)
4. [Configure OTA PAL Test](#4-configure-ota-pal-test)
5. [Running OTA PAL Test](#5-running-ota-pal-test)

## 1. Introduction

OTA PAL tests help to verify OTA PAL implementation. OTA PAL interface can be found [here](https://freertos.org/Documentation/api-ref/ota-for-aws-iot-embedded-sdk/docs/doxygen/output/html/ota_pal_interface.html).

OTA PAL tests have the following required parameters that should be setup in `SetupOtaPalTestParam()` implementation:
* pageSize: page size of flash. All test writes will be aligned to this page size.

## 2. OTA PAL Test Cases

The OTA PAL tests verify the implementation by running various test cases.

|Test Case	|Test Case Detail	|Expected result	|
|---	|---	|---	|
|otaPal_CloseFile_ValidSignature	| Test otaPal_CloseFile with a valid signature and signature verification certificate	| otaPal_CloseFile returns OtaPalSuccess	|
|otaPal_CloseFile_InvalidSignatureBlockWritten	|Call otaPal_CloseFile with an invalid signature in the file context after writing a block of dummy data to the file 	| otaPal_CloseFile returns OtaPalSignatureCheckFailed	|
|otaPal_CloseFile_InvalidSignatureNoBlockWritten	| Call otaPal_CloseFile with an invalid signature in the file context without writing to the file	| otaPal_CloseFile returns OtaPalSignatureCheckFailed	|
|otaPal_CloseFile_NonexistingCodeSignerCertificate	| Call otaPal_CloseFile with a signature verification certificate path does not exist in the system.	| otaPal_CloseFile returns OtaPalBadSignerCert|
|otaPal_CreateFileForRx_CreateAnyFile	| Create a file with any name with otaPal_CreateFileForRx	| otaPal_CreateFileForRx	returns OtaPalSuccess|
|otaPal_Abort_OpenFile	|Abort on an open file 	| otaPal_Abort returns OtaPalSuccess	|
|otaPal_Abort_FileWithBlockWritten	| Abort after writing a block to an open file	| otaPal_Abort returns OtaPalSuccess	|
|otaPal_Abort_NullFileHandle	|Call otaPal_Abort on a NULL file handle 	| otaPal_Abort returns OtaPalSuccess	|
|otaPal_Abort_NonExistentFile	|Call otaPal_Abort on a non-existent file 	| otaPal_Abort returns OtaPalSuccess	|
|otaPal_WriteBlock_WriteSingleByte	| Write one byte of data into created OTA file	| otaPal_WriteBlock returns 1	|
|otaPal_WriteBlock_WriteManyBlocks	| Write multiple blocks of data into created OTA file	|otaPal_WriteBlock returns number of bytes written 	|
|otaPal_SetPlatformImageState_AcceptedStateWithoutClose	| Set the platform state to accepted before closing the file	| otaPal_SetPlatformImageState returns OtaPalCommitFailed	|
|otaPal_SetPlatformImageState_InvalidImageState	| Set an invalid platform image state exceeding the range	| otaPal_SetPlatformImageState returns	OtaPalBadImageState|
|otaPal_SetPlatformImageState_UnknownImageState	| Set the image state to unknown	| otaPal_SetPlatformImageState returns	OtaPalBadImageState |
|otaPal_GetPlatformImageState_InvalidImageStateFromFileCloseFailure	| Set the platform image state to aborted	| otaPal_SetPlatformImageState returns success	|


Assert may be used to check invalid parameters. In that case, you may need to replace
the assert macro to return negative value in your implementation
to ensure invalid parameter error can be catched by assert.<br><br>
For example, if you are using FreeRTOS configASSERT macro to check invalid parameters,
you can replace the macro with the following code:
```
#define configASSERT( x )   if( !( x ) ) { return NEGATIVE_VALUE_TO_INDICATE_ERROR; }
```

## 3. Prerequisites For OTA PAL Test

The OTA PAL test assumes the tested platform already has the following components integrated.

* **OTA PAL implementation**
    
* **Unity test framework**
    The OTA PAL tests make use of the Unity test framework. Reference the [website](https://github.com/ThrowTheSwitch/Unity) for integration guide.

## 4. Configure OTA PAL Test
Please refer to top level [README](https://github.com/FreeRTOS/FreeRTOS-Libraries-Integration-Tests/blob/main/README.md) on high level project setup.
This section covers OTA PAL test specific configuration.

1. Implement the setup function, **SetupOtaPalParam**, for OTA PAL test to provide test parameters. The following are required test parameters:

```C
typedef struct OtaPalTestParam
{
    uint32_t pageSize;
} OtaPalTestParam_t;

void SetupOtaPalTestParam( OtaPalTestParam_t * pTestParam );
```
The pageSize parameter is expected to be multiples of flash page size. The tests will handle page size alignment and OTA PAL implementation is not expected to handle page alignment explicitly. This is to align with [OTA platform interface specification](https://github.com/aws/ota-for-aws-iot-embedded-sdk/blob/1cd22fbe9cca9046c54bacbb2279098eccae13c2/source/include/ota_platform_interface.h#L213).  

## 5. Running OTA PAL Test

Open test_execution_config.h and define `OTA_PAL_TEST_ENABLED` to 1.

In test_param_config.h, update the following options:

* OTA_PAL_TEST_CERT_TYPE: Select the certificate type used
* OTA_PAL_CERTIFICATE_FILE: Path to on device certificate, if applicable.
* OTA_PAL_FIRMWARE_FILE: Name of the firmware file, if applicable.
* OTA_PAL_USE_FILE_SYSTEM: Set to 1 if the OTA PAL uses file system abtraction.

Build and flash the application using toolchain of your choice. When RunQualificationTest() is called, the OTA PAL tests will run. Test results are outputted to serial.
