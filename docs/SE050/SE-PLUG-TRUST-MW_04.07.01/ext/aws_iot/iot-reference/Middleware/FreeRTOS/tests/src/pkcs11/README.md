# PKCS #11 Test

## On this page:
1. [Introduction](#1-introduction)
2. [Prerequisites For PKCS #11 Test](#2-prerequisites-for-pkcs-11-test)
3. [PKCS #11 Test Configurations](#3-pkcs-11-test-configurations)
4. [Source Code Organization](#4-source-code-organization)
5. [Implement PKCS #11 Test Application](#5-implement-pkcs-11-test-application)
6. [Run The PKCS #11 Test](#6-run-the-pkcs-11-test)<br>
</t>6.1 [Setup the provisioning mechanism and key function](#61-setup-the-provisioning-mechanism-and-key-function)<br>
</t>6.2 [Compile and run the PKCS #11 test application](#62-compile-and-run-the-pkcs-11-test-application)<br>

## 1. Introduction
[PKCS #11 ](https://en.wikipedia.org/wiki/PKCS_11) is a standardize API to allow application software to use, create, modify and delete cryptographic objects. 
The benefit of PKCS #11 is that it allows the app to take advantage of offload crypto while mitigating the threats of private key cloning and theft.

To keep as lean as possible, FreeRTOS uses a subset of PKCS #11 APIs. Implementers are free to integrate more than our required subset of PKCS #11, but it is optional to do so. 

The PKCS #11 API functions required by FreeRTOS are described in the following table. 

FreeRTOS Library | Required PKCS #11 API Family
----------------------- | ----------------------------
Any | Initialize, Finalize, Open/Close Session, GetSlotList, Login
Provisioning Demo | GenerateKeyPair, CreateObject, DestroyObject, InitToken, GetTokenInfo
TLS | Random, Sign, FindObject, GetAttributeValue
FreeRTOS+TCP | Random, Digest
OTA | Verify, Digest, FindObject, GetAttributeValue

The PKCS #11 test validates the PKCS #11 subset implementation. The test directly exercises the PKCS #11 implementation on the device under testing. User runs the PKCS #11 test by running a test application. The test application is usually implemented by calling the provided PKCS #11 test routine from the main function. By passing this test, the PKCS #11 subset implementation is validated to support required PKCS #11 functions by FreeRTOS.

The PKCS #11 interface is defined in the open-standard documentation available here http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html.

## 2. Prerequisites For PKCS #11 Test
The PKCS #11 tests assume the tested platform already has the following components integrated.
* **The PKCS #11 APIs subset implementation**<br>
    The implementation should support the APIs list in this [section](#1-introduction).
* **corePKCS11**<br>
    The utilities in corePKCS #11 are used in PKCS #11 test. corePKCS11 library provides software based implementation. Developers can implement the required PKCS #11 APIs using hardware crypto features of their board. The PKCS #11 Test does not mandate specific implementation.
* **MbedTLS**<br>
    MbedTLS is required to verify the result of the PKCS #11 implementation.
* **Unity test framework**<br>
    PKCS #11 test make use of the Unity test framework. Reference the [website](https://github.com/ThrowTheSwitch/Unity) for integration guide.

## 3. PKCS #11 Test Configurations

The following table lists the required test configurations for PKCS #11 tests. These test configurations need to be defined in **test_param_config.h**.

|Configuration	|Description	|
|--- | --- |
|PKCS11_TEST_RSA_KEY_SUPPORT	|The porting supports RSA key functions.	|
|PKCS11_TEST_EC_KEY_SUPPORT	|The porting supports EC key functions.	|
|PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT	|The porting supports import private key. RSA and EC key import will be validated in the test if the corresponding key functions are enabled.	|
|PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT	|The porting supports keypair generation. EC keypair generation will be validated in the test if the corresponding key functions are enabled.	|
|PKCS11_TEST_PREPROVISIONED_SUPPORT	|The porting has pre-provisioned credentials. These test labels, PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS, PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS and PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS, are the labels of the pre-provisioned credentials. 	|
|PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS	|The label of the private key used in the test.	|
|PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS	|The label of the public key used in the test.	|
|PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS	|The label of the certificate used in the test.	|
|PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED	|The porting supports storage for JITP. Set 1 to enable the JITP codeverify test.	|
|PKCS11_TEST_LABEL_CODE_VERIFICATION_KEY	|The label of the code verification key used in JITP codeverify test.	|
|PKCS11_TEST_LABEL_JITP_CERTIFICATE	|The label of the JITP certificate used in JITP codeverify test.	|
|PKCS11_TEST_LABEL_ROOT_CERTIFICATE	|The label of the root certificate used in JITP codeverify test.	|


FreeRTOS libraries and reference integrations needs at least one of the key function and one of the key provisioning mechanism supported by the PKCS #11 APIs. The test must enable at least one of the following configurations:

* At least one of the key function configurations:
    * PKCS11_TEST_RSA_KEY_SUPPORT 
    *  PKCS11_TEST_EC_KEY_SUPPORT 
* At least one of the key provisioning mechanisms:
    *  PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT 
    *  PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT 
    *  PKCS11_TEST_PREPROVISIONED_SUPPORT 


Pre-provisioned device credential test can not be enabled with other provisioning mechanisms. It must be run in the following conditions:

* Enable **PKCS11_TEST_PREPROVISIONED_SUPPORT** and the other provisioning mechanisms must be disabled
* Only one of the key function, **PKCS11_TEST_RSA_KEY_SUPPORT** or **PKCS11_TEST_EC_KEY_SUPPORT**, enabled
* Setup the pre-provisioned key labels according to your key function, including **PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS**, **PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS** and **PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS**. These credentials must exist in the PKCS #11 before running the test.

You may need to run the test several times with different configurations if your implementation support pre-provisioned credentials and other provisioning mechanisms.


>Note:
Objects with label **PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS**, **PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS** and **PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS** will be destroyed during the test if any one of **PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT** and **PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT** is enabled.

## 4. Source Code Organization
The tree only lists the required files to run the PKCS #11 test.
```
./FreeRTOS-Libraries-Integration-Tests/
├── config_template
│   ├── test_execution_config_template.h
│   └── test_param_config_template.h
└── src
    ├── common
    │   └── platform_function.h
    ├── pkcs11
    │   ├── core_pkcs11_test.c
    │   ├── core_pkcs11_test.h
    │   ├── ecdsa_test_credentials.h
    │   ├── rsa_test_credentials.h
    │   └── dev_mode_key_provisioning
    │       ├── dev_mode_key_provisioning.c
    │       └── dev_mode_key_provisioning.h
    ├── qualification_test.c
    └── qualification_test.h
```

## 5. Implement PKCS #11 Test Application
1. Add [FreeRTOS-Libraries-Integration-Tests](https://github.com/FreeRTOS/FreeRTOS-Libraries-Integration-Tests) as a submodule into your project. It doesn’t matter where the submodule is placed in the project, as long as it can be built.
2. Copy **config_template/test_execution_config_template.h** and **config_template/test_param_config_template.h** to a project location in the build path, and rename them to **test_execution_config.h** and **test_param_config.h**.
3. Include relevant files into the build system. If using CMake, **qualification_test.cmake** and **src/pkcs11_test.cmake** can be used to include relevant files.
4. Implement the [platform functions](https://github.com/FreeRTOS/FreeRTOS-Libraries-Integration-Tests/blob/main/src/common/platform_function.h) required by PKCS #11 tests. 
5. Enable the PKCS #11 test config, **PKCS11_TEST_ENABLED**, in **test_execution_config.h**.
6. Implement the main function and call the **RunQualificationTest**.

The following is an example test application.

```C
#include "platform_function.h"
#include "qualification_test.h"

FRTestThreadHandle_t FRTest_ThreadCreate( FRTestThreadFunction_t threadFunc, void * pParam )
{
    /* Thread create function for multithreaded test. */
}

int FRTest_ThreadTimedJoin( FRTestThreadHandle_t threadHandle, uint32_t timeoutMs )
{
    /* Thread timed wait function for multithreaded test. */
}
void * FRTest_MemoryAlloc( size_t size )
{
    /* Malloc function to allocate memory for test. */
}

void FRTest_MemoryFree( void * ptr )
{
    /* Free function to free memory allocated by FRTest_MemoryAlloc function. */
}

void yourMainFunction( void )
{
    RunQualificationTest();
}

```

## 6. Run The PKCS #11 Test
### 6.1 Setup the provisioning mechanism and key function
Setup the provisioning mechanism and key function in **test_param_config.h** according to the device capability.
The following is a sample test_param_config.h if corePKCS11 is used for the PKCS #11 implementation.
```C
#include "core_pkcs11_config.h"

/* Setup key function. */
#define PKCS11_TEST_RSA_KEY_SUPPORT                        ( 1 )
#define PKCS11_TEST_EC_KEY_SUPPORT                         ( 1 )

/* Setup provisioning method. */
#define PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT             ( 1 )
#define PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT               ( 1 )
#define PKCS11_TEST_PREPROVISIONED_SUPPORT                 ( 0 )

/* The device credential labels. */
#define PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS       pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS
#define PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS        pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS
#define PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS       pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS

/* JITP credential labels. */
#define PKCS11_TEST_JITP_CODEVERIFY_ROOT_CERT_SUPPORTED    pkcs11configJITP_CODEVERIFY_ROOT_CERT_SUPPORTED
#define PKCS11_TEST_LABEL_CODE_VERIFICATION_KEY            pkcs11configLABEL_CODE_VERIFICATION_KEY
#define PKCS11_TEST_LABEL_JITP_CERTIFICATE                 pkcs11configLABEL_JITP_CERTIFICATE
#define PKCS11_TEST_LABEL_ROOT_CERTIFICATE                 pkcs11configLABEL_ROOT_CERTIFICATE
```

### 6.2 Compile and run the PKCS #11 test application
Compile and run the test application in your development environment.
The following is a sample test result log:
```
TEST(Full_PKCS11_StartFinish, PKCS11_StartFinish_FirstTest) PASS
TEST(Full_PKCS11_StartFinish, PKCS11_GetFunctionList) PASS
TEST(Full_PKCS11_StartFinish, PKCS11_InitializeFinalize) PASS
TEST(Full_PKCS11_StartFinish, PKCS11_GetSlotList) PASS
TEST(Full_PKCS11_StartFinish, PKCS11_OpenSessionCloseSession) PASS
TEST(Full_PKCS11_Capabilities, PKCS11_Capabilities) PASS
TEST(Full_PKCS11_NoObject, PKCS11_Digest) PASS
TEST(Full_PKCS11_NoObject, PKCS11_Digest_ErrorConditions) PASS
TEST(Full_PKCS11_NoObject, PKCS11_GenerateRandom) PASS
TEST(Full_PKCS11_NoObject, PKCS11_GenerateRandomMultiThread) PASS
TEST(Full_PKCS11_RSA, PKCS11_RSA_CreateObject) PASS
TEST(Full_PKCS11_RSA, PKCS11_RSA_FindObject) PASS
TEST(Full_PKCS11_RSA, PKCS11_RSA_GetAttributeValue) PASS
TEST(Full_PKCS11_RSA, PKCS11_RSA_Sign) PASS
TEST(Full_PKCS11_RSA, PKCS11_RSA_FindObjectMultiThread) PASS
TEST(Full_PKCS11_RSA, PKCS11_RSA_GetAttributeValueMultiThread) PASS
TEST(Full_PKCS11_RSA, PKCS11_RSA_DestroyObject) PASS
TEST(Full_PKCS11_EC, PKCS11_EC_GenerateKeyPair) PASS
TEST(Full_PKCS11_EC, PKCS11_EC_CreateObject) PASS
TEST(Full_PKCS11_EC, PKCS11_EC_FindObject) PASS
TEST(Full_PKCS11_EC, PKCS11_EC_GetAttributeValue) PASS
TEST(Full_PKCS11_EC, PKCS11_EC_Sign) PASS
TEST(Full_PKCS11_EC, PKCS11_EC_Verify) PASS
TEST(Full_PKCS11_EC, PKCS11_EC_FindObjectMultiThread) PASS
TEST(Full_PKCS11_EC, PKCS11_EC_GetAttributeValueMultiThread) PASS
TEST(Full_PKCS11_EC, PKCS11_EC_SignVerifyMultiThread) PASS
TEST(Full_PKCS11_EC, PKCS11_EC_DestroyObject) PASS

-----------------------
27 Tests 0 Failures 0 Ignored
OK

```


