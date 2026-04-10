# Transport Interface Test

## On this page:
1. [Introduction](#1-introduction)
2. [Transport Interface Test Cases](#2-transport-interface-test-cases)
3. [Prerequisites For Transport Interface Test](#3-prerequisites-for-transport-interface-test)
4. [Source Code Organization](#4-source-code-organization)
5. [Implement Transport Interface Test Application](#5-implement-transport-interface-test-application)
6. [Run The Transport Interface Test](#6-run-the-transport-interface-test)<br>
</t>6.1. [Start the echo server](#61-start-the-echo-server)<br>
</t>6.2. [Start the echo server with TLS](#62-start-the-echo-server-with-tls)<br>
</t>6.3. [Setup the host info and network credentials](#63-setup-the-host-info-and-network-credentials)<br>
</t>6.4. [Compile and run the transport interface test application](#64-compile-and-run-the-transport-interface-test-application)<br>

## 1. Introduction

Transport interface tests help to verify transport interface implementation. The implementation needs to follow the [guideline in transport interface header file](https://freertos.org/Documentation/api-ref/coreMQTT/docs/doxygen/output/html/group__mqtt__callback__types.html#gaff3e08cfa7368b526ec1f8d87d10d7c2).

The test directly exercises the transport interface on the device under testing and interacts with a remote echo server. The following are required to run the transport interface tests:

* A PC to run the provided echo server.
* A test application which runs on the device under test with transport interface implemented.

_NOTE: The writev tests are optional and can be used to verify the implementation of writev method using the scatter-gather approach._

The test application is usually implemented by calling the provided transport interface test routine from the main function.


## 2. Transport Interface Test Cases

The transport interface tests verify the implementation by running various test cases. The test cases are designed according to the guidelines in the transport interface header file.

###Mandatory Test Cases

|Test Case	|Test Case Detail	|Expected result	|
|---	|---	|---	|
|TransportSend_NetworkContextNullPtr	|Test transport interface send with NULL network context pointer handling	|Negative value should be returned	|
|TransportSend_BufferNullPtr	|Test transport interface send with NULL buffer pointer handling	|Negative value should be returned	|
|TransportSend_ZeroByteToSend	|Test transport interface send with zero byte to send handling	|Negative value should be returned	|
|TransportRecv_NetworkContextNullPtr	|Test transport interface recv with NULL network context pointer handling	|Negative value should be returned	|
|TransportRecv_BufferNullPtr	|Test transport interface recv with NULL buffer pointer handling	|Negative value should be returned	|
|TransportRecv_ZeroByteToRecv	|Test transport interface recv with zero byte to receive handling	|Negative value should be returned	|
|Transport_SendOneByteRecvCompare 	|Test send receive behavior in the following order<br>Send : 1 byte<br>Send : ( TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH - 1 ) bytes<br>Receive : TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH bytes | Send/receive/compare should have no errors |
|Transport_SendRecvOneByteCompare 	|Test send receive behavior in the following order<br>Send : TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH bytes<br>Receive : 1 byte<br>Receive : ( TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH - 1 ) bytes |Send/receive/compare should have no errors |
|Transport_SendRecvCompare 	|Test transport interface with send, receive and compare on bulk of data.<br>The data size ranges from 1 byte to TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH bytes |Send/receive/compare should have no error within timeout |
|Transport_SendRecvCompareMultithreaded 	|Test transport interface with send, receive and compare on bulk of data in multiple threads.<br>Each thread will create a network connection.<br>The data size ranges from 1 byte to TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH bytes |Send/receive/compare should have no error within timeout |
|TransportSend_RemoteDisconnect	|Test transport interface send function return value when disconnected by remote server	|Negative value should be returned	|
|TransportRecv_RemoteDisconnect	|Test transport interface receive function return value when disconnected by remote server	|Negative value should be returned	|
|TransportRecv_NoDataToReceive	|Test transport interface receive function return value when no data to receive	|0 should be returned	|
|TransportRecv_ReturnZeroRetry	|Test transport interface receive function return zero due to no data to receive. Send data to echo server then retry the receive function. Transport receive function should be able to receive data from echo server and return positive value.	|Postive value should be returned after retry transport receive	|

###Optional Test Cases

|Test Case	|Test Case Detail	|Expected result	|
|---	|---	|---	|
|TransportWritev_NetworkContextNullPtr    |Test transport interface writev with NULL network context pointer handling       |Negative value should be returned      |
|TransportWritev_BufferNullPtr    |Test transport interface writev with NULL transport vector array pointer handling       |Negative value should be returned      |
|TransportWritev_ZeroByteToSend    |Test transport interface writev with zero vector array length to send handling  |Negative value should be returned      |
|TransportWritev_OneVectorBufferNullPtr    |Test transport interface writev with one data pointer in the array pointing to NULL.  |Negative value should be returned      |
|TransportWritev_OneVectorLengthZero    |Test transport interface writev with one vector length being 0  |Negative value should be returned      |
|Transport_WritevOneByteRecvCompare    |Test writev receive behavior in the following order<br>Send : 1 byte<br>Send : ( TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH - 1 ) bytes<br>Receive : TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH bytes | Send/receive/compare should have no errors |
|Transport_WritevRecvCompare    |Test transport interface with writev, receive and compare on bulk of data.<br>The data size ranges from 1 byte to TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH bytes |Send/receive/compare should have no error within timeout |
|Transport_WritevRecvCompareMultithreaded    |Test transport interface with writev, receive and compare on bulk of data in multiple threads.<br>Each thread will create a network connection.<br>The data size ranges from 1 byte to TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH bytes |Send/receive/compare should have no error within timeout |
|TransportWritev_RemoteDisconnect    |Test transport interface writev function return value when disconnected by remote server  |Negative value should be returned      |

Assert may be used to check invalid parameters. In that case, you need to replace
the assert macro to return negative value in your transport interface implementation
to ensure invalid parameter error can be catched by assert.<br><br>
For example, if you are using FreeRTOS configASSERT macro to check invalid parameters,
you can replace the macro with the following code:
```
#define configASSERT( x )   do{ if( !( x ) ) { return NEGATIVE_VALUE_TO_INDICATE_ERROR; } } while( 0 )
```

## 3. Prerequisites For Transport Interface Test

The transport interface test assumes the tested platform already has the following components integrated.

* **Transport interface implementation**
    The transport interface implementation should be able to setup a TCP network connection.
* **Unity test framework**
    Transport interface test make use of the Unity test framework. Reference the [website](https://github.com/ThrowTheSwitch/Unity) for integration guide.

A PC which can run Go language program and has network connectivity is required to run the Go-based echo server.


## 4. Source Code Organization

Folder structure of the transport interface tests. The tree only lists the required files to run the transport interface test.

```
./FreeRTOS-Libraries-Integration-Tests
├── include
│   ├── test_execution_config.h
│   └── test_param_config.h
└── src
    ├── common
    │   ├── platform_function.h
    │   └── network_connection.h
    ├── qualification_test.c
    ├── qualification_test.h
    └── transport_interface
        ├── README.md
        ├── transport_interface_tests.c
        └── transport_interface_tests.h
```

## 5. Implement Transport Interface Test Application

Developer implements the transport interface test application with the following steps:

1. Add [FreeRTOS-Libraries-Integration-Tests](https://github.com/FreeRTOS/FreeRTOS-Libraries-Integration-Tests) as a submodule into your project. It doesn’t matter where the submodule is placed in the project, as long as it can be built.

2. Copy **config_template/test_execution_config_template.h** and **config_template/test_param_config_template.h** to a project location in the build path, and rename them to **test_execution_config.h** and **test_param_config.h**.

3. Include relevant files into the build system. If using CMake, **qualification_test.cmake** and **src/transport_interface_tests.cmake** can be used to include relevant files.

4. Implement the setup function, **SetupTransportTestParam**, for transport interface test to provide test parameters. The following are required test parameters:

```C
/**
 * @brief A struct representing transport interface test parameters.
 */
typedef struct TransportTestParam
{
    TransportInterface_t * pTransport;            /**< @brief Transport interface structure to test. */
    NetworkConnectFunc_t pNetworkConnect;         /**< @brief Network connect function pointer. */
    NetworkDisconnectFunc_t pNetworkDisconnect;   /**< @brief Network disconnect function pointer. */
    void * pNetworkCredentials;                   /**< @brief Network credentials for network connection. */
    void * pNetworkContext;                       /**< @brief Primary network context. */
    void * pSecondNetworkContext;                 /**< @brief Secondary network context. */
} TransportTestParam_t;

/**
 * @brief Customers need to implement this fuction by filling in parameters
 * in the provided TransportTestParam_t.
 *
 * @param[in] pTestParam a pointer to TransportTestParam_t struct to be filled out by
 * caller.
 */
void SetupTransportTestParam( TransportTestParam_t * pTestParam );
```

5. Implement the platform functions used in transport interface test. The following are required platform functions:
```C
/**
 * @brief Thread handle data structure definition.
 */
typedef void * FRTestThreadHandle_t;

/**
 * @brief Thread function to be executed in ThreadCreate_t function.
 *
 * @param[in] pParam The pParam parameter passed in ThreadCreate_t function.
 */
typedef void ( * FRTestThreadFunction_t )( void * pParam );

/**
 * @brief Delay function to wait for at least specified amount of time.
 *
 * @param[in] delayMs Delay in milliseconds.
 */
void FRTest_TimeDelay( uint32_t delayMs );

/**
 * @brief Thread create function for test application.
 *
 * @param[in] threadFunc The thread function to be executed in the created thread.
 * @param[in] pParam The pParam parameter passed to the thread function pParam parameter.
 *
 * @return NULL if create thread failed. Otherwise, return the handle of the created thread.
 */
FRTestThreadHandle_t FRTest_ThreadCreate( FRTestThreadFunction_t threadFunc,
                                          void * pParam );

/**
 * @brief Timed thread join function to wait for the created thread exit.
 *
 * @param[in] threadHandle The handle of the created thread to be waited.
 * @param[in] timeoutMs The timeout value of to wait for the created thread exit.
 *
 * @return 0 if the thread exits within timeoutMs. Other value will be regarded as error.
 */
int FRTest_ThreadTimedJoin( FRTestThreadHandle_t threadHandle,
                            uint32_t timeoutMs );
```

6. Enable the transport interface config, **TRANSPORT_INTERFACE_TEST_ENABLED**, in **test_execution_config.h**.

```C
#define TRANSPORT_INTERFACE_TEST_ENABLED  ( 1 )     /* Set 1 to enable the transport interface test. */
```

7. Optionally define **TRANSPORT_TEST_EXECUTE_WRITEV_TESTS**, in **test_param_config.h** to enable the execution of writev tests.

```C
#define TRANSPORT_TEST_EXECUTE_WRITEV_TESTS
```

8. Implement the main function and call the **RunQualificationTest**.

The following is an example test application.

```C
#include "transport_interface.h"
#include "transport_interface_tests.h"
#include "qualification_test.h"
#include "platform_function.h"

static NetworkContext_t xNetworkContext = { 0 };
static NetworkContext_t xSecondNetworkContext = { 0 };
static TransportInterface_t xTransport = { 0 };

static NetworkConnectStatus_t prvTransportNetworkConnect( void * pNetworkContext,
                                                          TestHostInfo_t * pHostInfo,
                                                          void * pNetworkCredentials )
{
    /* Connect the transport network. */
}

static void prvTransportNetworkDisconnect( void * pNetworkContext )
{
    /* Disconnect the transport network. */
}

void FRTest_TimeDelay( uint32_t delayMs )
{
    /* Delay function to wait for the response from network. */
}

FRTestThreadHandle_t FRTest_ThreadCreate( FRTestThreadFunction_t threadFunc, void * pParam )
{
    /* Thread create function for multithreaded test. */
}

int FRTest_ThreadTimedJoin( FRTestThreadHandle_t threadHandle, uint32_t timeoutMs )
{
    /* Thread timed wait function for multithreaded test. */
}

void SetupTransportTestParam( TransportTestParam_t * pTestParam )
{
    if( pTestParam != NULL )
    {
        /* Setup the transport interface. */
        xTransport.send = /* YourTransportSendFunction. */;
        xTransport.recv = /* YourTransportRecvFunction. */;

        pTestParam->pTransport = &xTransport;
        pTestParam->pNetworkContext = &xNetworkContext;
        pTestParam->pSecondNetworkContext = &xSecondNetworkContext;

        pTestParam->pNetworkConnect = prvTransportNetworkConnect;
        pTestParam->pNetworkDisconnect = prvTransportNetworkDisconnect;
        pTestParam->pNetworkCredentials = /* YourNetworkCredentials. */;
    }
}

void yourMainFunction( void )
{
    RunQualificationTest();
}
```

## 6. Run The Transport Interface Test

The go-based echo_server.go program located [here](../../tools/echo_server) can setup a TCP server to echo back data. This echo server is used in the transport interface test to verify the transport interface implementation.

The transport interface test starts with the following steps:

### 6.1. Start the echo server

The echo server needs a configuration file. The following is echo server configurations:

* **verbose**
    * Enable this option to output the contents of the message sent to the echo server.
* **logging**
    * Enable this option to log all messages received to a file.
* **secure-connection**
    * Enable this option to switch to using TLS for the echo server. Note you will have to complete the credential creation prerequisite.
* **server-port**
    * Specify which port to open a socket on.
* **cert-verify**
    * Verify client certificate. To enable this configuration, client certificate must be signed by server credentials.
* **server-certificate-location**
    * Relative or absolute path to the server certificate generated in the credential creation prerequisite.
* **server-key-location**
    * Relative or absolute path to the server key generated in the credential creation prerequisite.


To run the echo serve without TLS, the following configuraition file, "example_config.json", can be referenced as an example to run the echo server. 

```
{
    "verbose": false,
    "logging": false,
    "secure-connection": false,
    "server-port": "9000",
    "cert-verify": false,
    "server-certificate-location": "",
    "server-key-location": ""
}
```


The **server address** and the **server-port** information will be required in the TransportConnectHook function. “**server-port**” in the example config can be changed to different port of developer’s choice.

Example command to start the echo server

```
go run echo_server.go -config=example_config.json
```

### 6.2. Start the echo server with TLS
Developer’s can also setup the transport interface test over mutual authenticated TLS with this echo server tool. Echo server must setup with the **secure-connection** configuration and provide server certificate and key in the configuration file. TLS connection capability and client certificate will be verified by the echo server.

This [document](https://github.com/FreeRTOS/FreeRTOS-Libraries-Integration-Tests/blob/main/tools/echo_server/README.md) describes how to create self-signed credentials for the echo server. The self-signed credentials is only for test transport interface test.

To run the echo server with TLS, the following configuraition file, "example_tls_config.json", can be referenced as an example to run the echo server. This configuration assumes self-signed credentials are used for testing.
```
{
    "verbose": false,
    "logging": false,
    "secure-connection": true,
    "server-port": "9000",
    "cert-verify": true,
    "server-certificate-location": "YourServerCertifcate",
    "server-key-location": "YourServerKey"
}
```

Example command to start the echo server with TLS

```
go run echo_server.go -config=example_tls_config.json
```

### 6.3. Setup the host info and network credentials
Provide the **server-address** and **server-port** in **test_param_config.h**.
```C
#define ECHO_SERVER_ENDPOINT   "server-address"
#define ECHO_SERVER_PORT       ( server-port )
```
To run the transport interface test with TLS, network credentials need to be assigned in the SetupTransportTestParam function.
The following configurations in **test_param_config.h** need to be used in network credentials.
```C
 #define ECHO_SERVER_ROOT_CA "echo-server-root-ca"
 #define TRANSPORT_CLIENT_CERTIFICATE "transport-client-certificate"

 /* This configuration should only be used for testing purpose.
  * For qualification, the key should be generated on-device. */
 #define TRANSPORT_CLIENT_PRIVATE_KEY "transport-client-private-key"
```
The pNetworkCredentials assigned in the same SetupTransportTestParam function will be passed to the pNetworkConnect.

### 6.4. Compile and run the transport interface test application
Compile and run the test application in your development environment.<br>
The following is a sample test result log:
```
TEST(Full_TransportInterfaceTest, TransportSend_NetworkContextNullPtr) PASS
TEST(Full_TransportInterfaceTest, TransportSend_BufferNullPtr) PASS
TEST(Full_TransportInterfaceTest, TransportSend_ZeroByteToSend) PASS
TEST(Full_TransportInterfaceTest, TransportRecv_NetworkContextNullPtr) PASS
TEST(Full_TransportInterfaceTest, TransportRecv_BufferNullPtr) PASS
TEST(Full_TransportInterfaceTest, TransportRecv_ZeroByteToRecv) PASS
TEST(Full_TransportInterfaceTest, Transport_SendOneByteRecvCompare) PASS
TEST(Full_TransportInterfaceTest, Transport_SendRecvOneByteCompare) PASS
TEST(Full_TransportInterfaceTest, Transport_SendRecvCompare) PASS
TEST(Full_TransportInterfaceTest, Transport_SendRecvCompareMultithreaded) PASS
TEST(Full_TransportInterfaceTest, TransportSend_RemoteDisconnect) PASS
TEST(Full_TransportInterfaceTest, TransportRecv_RemoteDisconnect) PASS
TEST(Full_TransportInterfaceTest, TransportRecv_NoDataToReceive) PASS
TEST(Full_TransportInterfaceTest, TransportRecv_ReturnZeroRetry) PASS

-----------------------
16 Tests 0 Failures 0 Ignored
OK
```
