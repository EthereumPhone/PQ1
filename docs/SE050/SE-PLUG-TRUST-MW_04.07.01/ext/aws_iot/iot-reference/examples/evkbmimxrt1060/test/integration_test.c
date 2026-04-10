/*
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
 *
 * http://www.FreeRTOS.org
 * http://aws.amazon.com/freertos
 */

/**
 * @brief File implements the required stub code and task to run and pass the integration
 * tests.
 */

#include "core_pkcs11_config.h"
#include "test_param_config.h"
#include "test_execution_config.h"
#include "qualification_test.h"
#include "transport_interface_test.h"
#include "ota_pal_test.h"
#include "mqtt_test.h"
#include "demo_config.h"
#include "using_mbedtls.h"
#include "mflash_drv.h"
/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "fsl_common.h"
#include "fsl_trng.h"


/**
 * @brief Socket send and receive timeouts to use.  Specified in milliseconds.
 */
#define mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS    ( 750 )

/**
 * @brief Global entry time into the application to use as a reference timestamp
 * in the #prvGetTimeMs function. #prvGetTimeMs will always return the difference
 * between the current time and the global entry time. This will reduce the chances
 * of overflow for the 32 bit unsigned integer used for holding the timestamp.
 */
static uint32_t ulGlobalEntryTimeMs;

/* Function declaration. */
uint32_t MqttTestGetTimeMs( void );

/* suppress unused warnings when building without tests */
#if ( MQTT_TEST_ENABLED == 1 ) || ( TRANSPORT_INTERFACE_TEST_ENABLED == 1 )
static NetworkCredentials_t xNetworkCredentials = { 0 };
static TransportInterface_t xTransport = { 0 };
static NetworkContext_t xNetworkContext = { 0 };
static NetworkContext_t xSecondNetworkContext = { 0 };

static NetworkConnectStatus_t prvTransportNetworkConnect( void * pvNetworkContext,
                                                          TestHostInfo_t * pxHostInfo,
                                                          void * pvNetworkCredentials )
{
    TlsTransportStatus_t xStatus;

    xStatus = TLS_FreeRTOS_Connect( pvNetworkContext,
                                    pxHostInfo->pHostName,
                                    pxHostInfo->port,
                                    pvNetworkCredentials,
                                    mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS,
                                    mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS );

    configASSERT( TLS_TRANSPORT_SUCCESS == xStatus );
    return NETWORK_CONNECT_SUCCESS;
}


static void prvTransportNetworkDisconnect( void * pNetworkContext )
{
    TLS_FreeRTOS_Disconnect( pNetworkContext );
}
#endif /* if ( MQTT_TEST_ENABLED == 1 ) || ( TRANSPORT_INTERFACE_TEST_ENABLED == 1 ) */

typedef struct TaskParam
{
    StaticSemaphore_t joinMutexBuffer;
    SemaphoreHandle_t joinMutexHandle;
    FRTestThreadFunction_t threadFunc;
    void * pParam;
    TaskHandle_t taskHandle;
} TaskParam_t;

static void ThreadWrapper( void * pParam )
{
    TaskParam_t * pTaskParam = pParam;

    if( ( pTaskParam != NULL ) && ( pTaskParam->threadFunc != NULL ) && ( pTaskParam->joinMutexHandle != NULL ) )
    {
        pTaskParam->threadFunc( pTaskParam->pParam );

        /* Give the mutex. */
        xSemaphoreGive( pTaskParam->joinMutexHandle );
    }

    vTaskDelete( NULL );
}

/*-----------------------------------------------------------*/

int FRTest_GenerateRandInt()
{
    static bool first = true;
    trng_config_t trngConfig;
    int ret = 0;

    if( first )
    {
        if( TRNG_GetDefaultConfig( &trngConfig ) != kStatus_Success )
        {
            PRINTF( "TRNG_GetDefaultConfig fail.\n" );
            return( 0 );
        }

        /* Initialize TRNG */
        if( TRNG_Init( TRNG, &trngConfig ) != kStatus_Success )
        {
            PRINTF( "TRNG_Init fail.\n" );
            return( 0 );
        }

        first = false;
    }

    if( TRNG_GetRandomData( TRNG, &ret, sizeof( ret ) ) != kStatus_Success )
    {
        PRINTF( "TRNG_GetRandomData fail.\n" );
    }

    return ret;
}

/*-----------------------------------------------------------*/

FRTestThreadHandle_t FRTest_ThreadCreate( FRTestThreadFunction_t threadFunc,
                                          void * pParam )
{
    TaskParam_t * pTaskParam = NULL;
    FRTestThreadHandle_t threadHandle = NULL;
    BaseType_t xReturned;

    pTaskParam = malloc( sizeof( TaskParam_t ) );
    configASSERT( pTaskParam != NULL );

    pTaskParam->joinMutexHandle = xSemaphoreCreateBinaryStatic( &pTaskParam->joinMutexBuffer );
    configASSERT( pTaskParam->joinMutexHandle != NULL );

    pTaskParam->threadFunc = threadFunc;
    pTaskParam->pParam = pParam;

    xReturned = xTaskCreate( ThreadWrapper,    /* Task code. */
                             "ThreadWrapper",  /* All tasks have same name. */
                             8192,             /* Task stack size. */
                             pTaskParam,       /* Where the task writes its result. */
                             tskIDLE_PRIORITY, /* Task priority. */
                             &pTaskParam->taskHandle );
    configASSERT( xReturned == pdPASS );

    threadHandle = pTaskParam;

    return threadHandle;
}

/*-----------------------------------------------------------*/

int FRTest_ThreadTimedJoin( FRTestThreadHandle_t threadHandle,
                            uint32_t timeoutMs )
{
    TaskParam_t * pTaskParam = threadHandle;
    BaseType_t xReturned;
    int retValue = 0;

    /* Check the parameters. */
    configASSERT( pTaskParam != NULL );
    configASSERT( pTaskParam->joinMutexHandle != NULL );

    /* Wait for the thread. */
    xReturned = xSemaphoreTake( pTaskParam->joinMutexHandle, pdMS_TO_TICKS( timeoutMs ) );

    if( xReturned != pdTRUE )
    {
        PRINTF( "Waiting thread exist failed after %u %d. Task abort.", timeoutMs, xReturned );

        /* Return negative value to indicate error. */
        retValue = -1;

        /* There may be used after free. Assert here to indicate error. */
        configASSERT( false );
    }

    free( pTaskParam );

    return retValue;
}

/*-----------------------------------------------------------*/

void FRTest_TimeDelay( uint32_t delayMs )
{
    vTaskDelay( pdMS_TO_TICKS( delayMs ) );
}

/*-----------------------------------------------------------*/

void * FRTest_MemoryAlloc( size_t size )
{
    return pvPortMalloc( size );
}

/*-----------------------------------------------------------*/

void FRTest_MemoryFree( void * ptr )
{
    return vPortFree( ptr );
}
/*-----------------------------------------------------------*/

uint32_t FRTest_GetTimeMs()
{
    return MqttTestGetTimeMs();
}
/*-----------------------------------------------------------*/

uint32_t MqttTestGetTimeMs( void )
{
    TickType_t xTickCount = 0;
    uint32_t ulTimeMs = 0UL;

    /* Get the current tick count. */
    xTickCount = xTaskGetTickCount();

    /* Convert the ticks to milliseconds. */
    ulTimeMs = ( uint32_t ) ( xTickCount * 1000 / configTICK_RATE_HZ );

    /* Reduce ulGlobalEntryTimeMs from obtained time so as to always return the
     * elapsed time in the application. */
    ulTimeMs = ( uint32_t ) ( ulTimeMs - ulGlobalEntryTimeMs );

    return ulTimeMs;
}
/*-----------------------------------------------------------*/

#if ( MQTT_TEST_ENABLED == 1 )
void SetupMqttTestParam( MqttTestParam_t * pTestParam )
{
    configASSERT( pTestParam != NULL );

    /* Initialization of timestamp for MQTT. */
    ulGlobalEntryTimeMs = MqttTestGetTimeMs();

    /* Setup the transport interface. */
    xTransport.send = TLS_FreeRTOS_Send;
    xTransport.recv = TLS_FreeRTOS_Recv;

    xNetworkCredentials.pRootCa = ( unsigned char * ) democonfigROOT_CA_PEM;
    xNetworkCredentials.rootCaSize = sizeof( democonfigROOT_CA_PEM );
    xNetworkCredentials.pClientCertLabel = pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS;
    xNetworkCredentials.pPrivateKeyLabel = pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    xNetworkCredentials.disableSni = pdFALSE;

    pTestParam->pTransport = &xTransport;
    pTestParam->pNetworkContext = &xNetworkContext;
    pTestParam->pSecondNetworkContext = &xSecondNetworkContext;
    pTestParam->pNetworkConnect = prvTransportNetworkConnect;
    pTestParam->pNetworkDisconnect = prvTransportNetworkDisconnect;
    pTestParam->pNetworkCredentials = &xNetworkCredentials;
    pTestParam->pGetTimeMs = MqttTestGetTimeMs;
}
#endif /* if ( MQTT_TEST_ENABLED == 1 ) */
/*-----------------------------------------------------------*/

#if ( TRANSPORT_INTERFACE_TEST_ENABLED == 1 )
void SetupTransportTestParam( TransportTestParam_t * pTestParam )
{
    configASSERT( pTestParam != NULL );
    /* Setup the transport interface. */
    xTransport.send = TLS_FreeRTOS_Send;
    xTransport.recv = TLS_FreeRTOS_Recv;

    xNetworkCredentials.pRootCa = ( unsigned char * ) ECHO_SERVER_ROOT_CA;
    xNetworkCredentials.rootCaSize = sizeof( ECHO_SERVER_ROOT_CA );
    xNetworkCredentials.pClientCertLabel = pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS;
    xNetworkCredentials.pPrivateKeyLabel = pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    xNetworkCredentials.disableSni = pdFALSE;

    pTestParam->pTransport = &xTransport;
    pTestParam->pNetworkContext = &xNetworkContext;
    pTestParam->pSecondNetworkContext = &xSecondNetworkContext;
    pTestParam->pNetworkConnect = prvTransportNetworkConnect;
    pTestParam->pNetworkDisconnect = prvTransportNetworkDisconnect;
    pTestParam->pNetworkCredentials = &xNetworkCredentials;
}
#endif /* if ( TRANSPORT_INTERFACE_TEST_ENABLED == 1 ) */

#if ( OTA_PAL_TEST_ENABLED == 1 )
void SetupOtaPalTestParam( OtaPalTestParam_t * pTestParam )
{
    pTestParam->pageSize = MFLASH_PAGE_SIZE;
}
#endif /* if ( OTA_PAL_TEST_ENABLED == 1 ) */

void prvQualificationTestTask( void * pvParameters )
{
    RunQualificationTest();
    vTaskDelete( NULL );
}
