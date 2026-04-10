/*
 * FreeRTOS Integration Toolkit preview
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
 * @file transport_interface_test.c
 * @brief Integration tests for the transport interface test implementation.
 */

#include "test_execution_config.h"
#if ( TRANSPORT_INTERFACE_TEST_ENABLED == 1 )

/* Standard header includes. */
#include <string.h>
#include <stdbool.h>

/* Include for init and de-init functions. */
#include "transport_interface_test.h"

/* Include for test parameter and execution configs. */
#include "test_param_config.h"

/* Include for Unity framework. */
#include "unity.h"
#include "unity_fixture.h"

/*-----------------------------------------------------------*/

/**
 * @brief Transport Interface test buffer length.
 *
 * Length of the test buffer used in tests. Guard buffers are placed before and
 * after the topic buffer to verify that transport interface APIs do not write
 * out of bounds. The memory layout is:
 *
 *     +--------------+-------------------------------+------------+
 *     |    Guard     |    Writable Topic Buffer      |   Guard    |
 *     +--------------+-------------------------------+------------+
 *
 * Both guard buffers are filled with a known pattern before each test and are
 * verified to remain unchanged after each test.
 */
#define TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH    ( 32U )
#define TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH        ( 2048U )
#define TRANSPORT_TEST_BUFFER_SUFFIX_GUARD_LENGTH    ( 32U )
#define TRANSPORT_TEST_BUFFER_TOTAL_LENGTH        \
    ( TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH + \
      TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH +     \
      TRANSPORT_TEST_BUFFER_SUFFIX_GUARD_LENGTH )

/**
 * @brief Transport Interface test buffer guard pattern.
 */
#define TRANSPORT_TEST_BUFFER_GUARD_PATTERN        ( 0xA5 )

/**
 * @brief Transport Interface send receive retry count.
 */
#define TRANSPORT_TEST_SEND_RECEIVE_RETRY_COUNT    ( 50U )

/**
 * @brief Transport Interface writev retry count.
 */
#define TRANSPORT_TEST_WRITEV_RETRY_COUNT    ( 50U )

/**
 * @brief Transport Interface delay in milliseconds.
 *
 * The Delay time for the transport interface test to wait for the data echo-ed
 * back from transport network.
 */
#define TRANSPORT_TEST_DELAY_MS                    ( 200U )

/**
 * @brief Echo server disconnect command.
 *
 * The command to inform echo server to disconnect the test connection.
 */
#define TRANSPORT_TEST_DISCONNECT_COMMAND          "DISCONNECT"

/**
 * @brief Transport Interface disconnect delay in milliseconds.
 *
 * The Delay time for the transport interface test to wait for the send operation
 * and response from the network. The delay time should be long enough to cover different
 * network environment.
 */
#define TRANSPORT_TEST_NETWORK_DELAY_MS            ( 3000U )

/**
 * @brief Number of simultaneous tasks for multithreaded tests.
 */
#define TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT     ( 2U )

/**
 * @brief The thread parameter index used in non-multithreaded test.
 */
#define TRANSPORT_TEST_INDEX                       ( 0U )

/**
 * @brief The second thread parameter index used in multithreaded test.
 */
#define TRANSPORT_TEST_SECOND_INDEX                ( 1U )

/**
 * @brief Timeout to wait thread function finish the test.
 */
#ifndef TRANSPORT_TEST_WAIT_THREAD_TIMEOUT_MS
    #define TRANSPORT_TEST_WAIT_THREAD_TIMEOUT_MS    ( 1000000U )
#endif

/**
 * @brief Timeout to wait no data to receive test thread.
 */
#define TRANSPORT_TEST_WAIT_THREAD_RECEIVE_TIMEOUT_MS    ( 180000U )

/**
 * @brief Print progress in SendRecvCompare test.
 *
 * This debug function should be disabled if testing with IDT.
 */
#ifndef TRANSPORT_TEST_PRINT_DEBUG_PROGRESS
    #define TRANSPORT_TEST_PRINT_DEBUG_PROGRESS    ( 0 )
#endif

/**
 * @brief Print debug error message when test fail in multi-threaded test.
 *
 * Use UnityPrint for older version of Unity.
 */
#ifndef TEST_MESSAGE
    #define TEST_MESSAGE( x )    UnityPrint( x )
#endif

/*-----------------------------------------------------------*/

typedef struct threadParameter
{
    NetworkContext_t * pNetworkContext;
    uint8_t transportTestBuffer[ TRANSPORT_TEST_BUFFER_TOTAL_LENGTH ];
    bool xNetworkConnected;
    bool stopFlag;
    bool xResult;
} threadParameter_t;

/*-----------------------------------------------------------*/

#if ( TRANSPORT_INTERFACE_TEST_ENABLED == 1 )
    #ifndef ECHO_SERVER_ENDPOINT
        #error "Please define ECHO_SERVER_ENDPOINT"
    #endif

    #ifndef ECHO_SERVER_PORT
        #error "Please define ECHO_SERVER_PORT"
    #endif
#endif /* if ( TRANSPORT_INTERFACE_TEST_ENABLED == 1 ) */

/*-----------------------------------------------------------*/

/**
 * @brief Struct of test parameters filled in by user.
 */
static TransportTestParam_t testParam = { 0 };

/**
 * @brief Info of the server to connect to for tests.
 */
static TestHostInfo_t testHostInfo = { 0 };

/**
 * @brief Transport Interface used in test cases.
 */
static TransportInterface_t * pTestTransport = NULL;

/**
 * @brief Thread paramter to hold the network context and test buffer.
 */
static threadParameter_t threadParameter[ TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT ];

/**
 * @brief Test group for transport interface test.
 */
TEST_GROUP( Full_TransportInterfaceTest );

/*-----------------------------------------------------------*/

/**
 * @brief Initialize the test data with 0,1,...,255,0,1,...
 */
static void prvInitializeTestData( uint8_t * pTransportTestBuffer,
                                   uint32_t testSize )
{
    uint32_t i;

    for( i = 0U; i < testSize; i++ )
    {
        pTransportTestBuffer[ i ] = ( uint8_t ) i;
    }
}

/*-----------------------------------------------------------*/

/**
 * @brief Verify the data received and buffer after testSize should remain unchanged.
 *
 * The received data is verified with the pattern initialized in prvInitializeTestData.
 * The test buffer after testSize should remain unchanged.
 */
static bool prvVerifyTestData( uint8_t * pTransportTestBuffer,
                               uint32_t testSize,
                               uint32_t maxBufferSize )
{
    uint32_t i;
    bool retValue = true;

    /* Check the data received is correct. */
    for( i = 0U; i < testSize; i++ )
    {
        if( ( ( uint8_t ) i ) != pTransportTestBuffer[ i ] )
        {
            TEST_MESSAGE( "Received data is not the same as expected." );
            retValue = false;
            break;
        }
    }

    /* Check the buffer after testSize is unchanged. */
    if( ( retValue == true ) && ( testSize < maxBufferSize ) )
    {
        for( i = 0U; i < ( maxBufferSize - testSize ); i++ )
        {
            if( pTransportTestBuffer[ testSize + i ] != TRANSPORT_TEST_BUFFER_GUARD_PATTERN )
            {
                TEST_MESSAGE( "Buffer after testSize should not be altered." );
                retValue = false;
                break;
            }
        }
    }

    return retValue;
}


/*-----------------------------------------------------------*/

/**
 * @brief Send the data over transport network with retry.
 *
 * The send API may return less bytes then requested. If the transport send function
 * returns zero, it should represent the send operation can be retired by calling
 * the API function. The retry operation is handled in this function.
 */
static bool prvTransportSendData( TransportInterface_t * pTransport,
                                  NetworkContext_t * pNetworkContext,
                                  uint8_t * pTransportTestBuffer,
                                  uint32_t sendSize )
{
    uint32_t transferTotal = 0U;
    int32_t transportResult = 0;
    uint32_t i;
    bool retValue = true;

    for( i = 0U; i < TRANSPORT_TEST_SEND_RECEIVE_RETRY_COUNT; i++ )
    {
        transportResult = pTransport->send( pNetworkContext,
                                            &pTransportTestBuffer[ transferTotal ],
                                            sendSize - transferTotal );

        /* Send should not have any error. */
        if( transportResult < 0 )
        {
            TEST_MESSAGE( "Transport send data should not have any error." );
            retValue = false;
            break;
        }

        if( ( sendSize - transferTotal ) < ( uint32_t ) transportResult )
        {
            TEST_MESSAGE( "More data is sent than expected." );
            retValue = false;
            break;
        }

        transferTotal = transferTotal + ( uint32_t ) transportResult;

        if( sendSize == transferTotal )
        {
            /* All the data is sent. Break the retry loop. */
            break;
        }
    }

    /* Check if all the data is sent. */
    if( sendSize != transferTotal )
    {
        TEST_MESSAGE( "Fail to send all the data expected." );
        retValue = false;
    }

    return retValue;
}

/*-----------------------------------------------------------*/
#ifdef TRANSPORT_TEST_EXECUTE_WRITEV_TESTS
/**
 * @brief Send the data over transport network using writev with retry.
 *
 * The writev API may return less bytes then requested. If the transport writev function
 * returns zero, it should represent that the writev operation can be retried by calling
 * the API function. The retry operation is handled in this function.
 */
static bool prvTransportWritevData( TransportInterface_t * pTransport,
                                    NetworkContext_t * pNetworkContext,
                                    TransportOutVector_t * pTransportTestVectorArray,
                                    size_t ioVecCount )
{
    int32_t transportResult = 0;
    uint32_t i;
    bool retValue = true;
    int32_t bytesToSend = 0;
    int32_t bytesSentOrError = 0;
    TransportOutVector_t * pIoVectIterator;
    size_t vectorsToBeSent = ioVecCount;

    /* Count the total number of bytes to be sent as outlined in the vector. */
    for( pIoVectIterator = pTransportTestVectorArray; pIoVectIterator <= &( pTransportTestVectorArray[ ioVecCount - 1U ] ); pIoVectIterator++ )
    {
        bytesToSend += ( int32_t ) pIoVectIterator->iov_len;
    }

    /* Reset the iterator to point to the first entry in the array. */
    pIoVectIterator = pTransportTestVectorArray;

    for( i = 0U; i < TRANSPORT_TEST_WRITEV_RETRY_COUNT; i++ )
    {
        uint32_t bytesSentThisVector = 0U;

        transportResult = pTransport->writev( pNetworkContext,
                                              pIoVectIterator,
                                              vectorsToBeSent );

        /* Send should not have any error. */
        if( transportResult < 0 )
        {
            TEST_MESSAGE( "Transport send data should not have any error." );
            retValue = false;
            break;
        }

        if( ( bytesToSend - bytesSentOrError ) < transportResult )
        {
            TEST_MESSAGE( "More data is sent than expected." );
            retValue = false;
            break;
        }

        bytesSentOrError += transportResult;
        bytesSentThisVector += transportResult;

        if( bytesToSend == bytesSentOrError )
        {
            /* All the data is sent. Break the retry loop. */
            break;
        }

        /* Increment the vector iterator based on the number of bytes sent. */
        while( ( pIoVectIterator <= &( pTransportTestVectorArray[ ioVecCount - 1U ] ) ) &&
               ( bytesSentThisVector >= pIoVectIterator->iov_len ) )
        {
            bytesSentThisVector -= ( uint32_t ) pIoVectIterator->iov_len;
            pIoVectIterator++;

            /* Update the number of vector which are yet to be sent. */
            vectorsToBeSent--;
        }

        /* Some of the bytes from the current vector pointed to by the vector iterator were sent
         * as well, update the length and the pointer to data in this vector. */
        if( ( bytesSentThisVector > 0U ) &&
            ( pIoVectIterator <= &( pTransportTestVectorArray[ ioVecCount - 1U ] ) ) )
        {
            /* Update the pointer to data to point to the first byte which needs to be sent in the next iteration. */
            pIoVectIterator->iov_base = ( const void * ) &( ( ( const uint8_t * ) pIoVectIterator->iov_base )[ bytesSentThisVector ] );
            pIoVectIterator->iov_len -= bytesSentThisVector;
        }
    }

    /* Check if all the data is sent. */
    if( bytesToSend != bytesSentOrError )
    {
        TEST_MESSAGE( "Fail to send all the data expected." );
        retValue = false;
    }

    return retValue;
}
#endif

/*-----------------------------------------------------------*/

/**
 * @brief Receive the data from transport network with retry.
 *
 * The receive API may return less btyes then requested. If the transport receive
 * function returns zero, it should represent the read operation can be retried
 * by calling the API function. The retry operation is handled in this function.
 */
static bool prvTransportRecvData( TransportInterface_t * pTransport,
                                  NetworkContext_t * pNetworkContext,
                                  uint8_t * pTransportTestBuffer,
                                  uint32_t recvSize )
{
    uint32_t transferTotal = 0U;
    int32_t transportResult = 0;
    uint32_t i;
    bool retValue = true;

    /* Initialize the receive buffer with TRANSPORT_TEST_BUFFER_GUARD_PATTERN. */
    memset( &( pTransportTestBuffer[ 0 ] ), TRANSPORT_TEST_BUFFER_GUARD_PATTERN, recvSize );

    for( i = 0U; i < TRANSPORT_TEST_SEND_RECEIVE_RETRY_COUNT; i++ )
    {
        transportResult = pTransport->recv( pNetworkContext,
                                            &pTransportTestBuffer[ transferTotal ],
                                            recvSize - transferTotal );

        /* Receive should not have any error. */
        if( transportResult < 0 )
        {
            TEST_MESSAGE( "Transport receive data should not have any error." );
            retValue = false;
            break;
        }

        if( ( recvSize - transferTotal ) < ( uint32_t ) transportResult )
        {
            TEST_MESSAGE( "More data is received than expected." );
            retValue = false;
            break;
        }

        transferTotal = transferTotal + transportResult;

        if( recvSize > transferTotal )
        {
            retValue = prvVerifyTestData( &pTransportTestBuffer[ transferTotal ], 0, ( recvSize - transferTotal ) );
        }
        else
        {
            /* This is test testSize == transferTotal case. All the data is received.
             * Break the retry loop. */
            break;
        }

        /* Delay to wait for the test data from the transport network. */
        FRTest_TimeDelay( TRANSPORT_TEST_DELAY_MS );
    }

    /* Check if all the data is recevied. */
    if( recvSize != transferTotal )
    {
        retValue = false;
        TEST_MESSAGE( "Fail to receive all the data expected." );
    }

    return retValue;
}

/*-----------------------------------------------------------*/

/**
 * @brief Verify the buffer guard of the test buffer.
 */
static void prvVerifyTestBufferGuard( uint8_t * pTransportTestBuffer )
{
    /* Prefix and Suffix guard buffers must never change. */
    TEST_ASSERT_EACH_EQUAL_HEX8_MESSAGE( TRANSPORT_TEST_BUFFER_GUARD_PATTERN,
                                         pTransportTestBuffer,
                                         TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH,
                                         "transportTestBuffer prefix guard should not be altered." );
    TEST_ASSERT_EACH_EQUAL_HEX8_MESSAGE( TRANSPORT_TEST_BUFFER_GUARD_PATTERN,
                                         &( pTransportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH +
                                                                  TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH ] ),
                                         TRANSPORT_TEST_BUFFER_SUFFIX_GUARD_LENGTH,
                                         "transportTestBuffer suffix guard should not be altered." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Thread function of the send/receive/compare test.
 */
static void prvSendRecvCompareFunc( void * pParam )
{
    threadParameter_t * pThreadParameter = pParam;
    uint8_t * pTransportTestBufferStart =
        &( pThreadParameter->transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    uint32_t testBufferSize;
    NetworkContext_t * pNetworkContext = pThreadParameter->pNetworkContext;

    pThreadParameter->xResult = true;

    for( testBufferSize = 1U; testBufferSize <= TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH; testBufferSize = testBufferSize + 1 )
    {
        /* Initialize the test data buffer. */
        prvInitializeTestData( pTransportTestBufferStart, testBufferSize );

        /* Send the test data to the server. */
        if( pThreadParameter->xResult == true )
        {
            pThreadParameter->xResult = prvTransportSendData( pTestTransport,
                                                              pNetworkContext,
                                                              pTransportTestBufferStart,
                                                              testBufferSize );
        }

        /* Receive the test data from server. */
        if( pThreadParameter->xResult == true )
        {
            pThreadParameter->xResult = prvTransportRecvData( pTestTransport,
                                                              pNetworkContext,
                                                              pTransportTestBufferStart,
                                                              testBufferSize );
        }

        /* Compare the test data received from server. */
        if( pThreadParameter->xResult == true )
        {
            pThreadParameter->xResult = prvVerifyTestData( pTransportTestBufferStart,
                                                           testBufferSize,
                                                           TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
        }

        if( ( pThreadParameter->stopFlag == true ) || ( pThreadParameter->xResult == false ) )
        {
            break;
        }

        #if ( TRANSPORT_TEST_PRINT_DEBUG_PROGRESS == 1 )
            /* Output information to indicate the test is running. */
            UNITY_OUTPUT_CHAR( '.' );
        #endif
    }
}

/*-----------------------------------------------------------*/

#ifdef TRANSPORT_TEST_EXECUTE_WRITEV_TESTS
/**
 * @brief Thread function of the writev/receive/compare test.
 */
static void prvWritevRecvCompareFunc( void * pParam )
{
    threadParameter_t * pThreadParameter = pParam;
    uint8_t * pTransportTestBufferStart =
        &( pThreadParameter->transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    uint32_t testBufferSize;
    NetworkContext_t * pNetworkContext = pThreadParameter->pNetworkContext;
    TransportOutVector_t pTransportTestVectorArray[ 5U ];
    size_t ioVecCount;

    pThreadParameter->xResult = true;

    for( testBufferSize = 1U; testBufferSize <= TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH; testBufferSize = testBufferSize + 1 )
    {
        if( testBufferSize % 5 == 0 )
        {
            ioVecCount = 5U;
        }
        else if( testBufferSize % 3 == 0 )
        {
            ioVecCount = 3U;
        }
        else if( testBufferSize % 2 == 0 )
        {
            ioVecCount = 2U;
        }
        else
        {
            ioVecCount = 1U;
        }

        for( size_t index = 0U; index < ioVecCount; index ++ )
        {
            pTransportTestVectorArray[ index ].iov_base = &pTransportTestBufferStart[ index * ( testBufferSize / ioVecCount ) ];;
            pTransportTestVectorArray[ index ].iov_len = testBufferSize / ioVecCount;
        }

        /* Initialize the test data buffer. */
        prvInitializeTestData( pTransportTestBufferStart, testBufferSize );

        /* Send the test data to the server. */
        if( pThreadParameter->xResult == true )
        {
            pThreadParameter->xResult = prvTransportWritevData( pTestTransport, pNetworkContext, pTransportTestVectorArray,
                                                                ioVecCount );
        }

        /* Receive the test data from server. */
        if( pThreadParameter->xResult == true )
        {
            pThreadParameter->xResult = prvTransportRecvData( pTestTransport, pNetworkContext, pTransportTestBufferStart,
                                                              testBufferSize );
        }

        /* Compare the test data received from server. */
        if( pThreadParameter->xResult == true )
        {
            pThreadParameter->xResult = prvVerifyTestData( pTransportTestBufferStart, testBufferSize,
                                                           TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
        }

        if( ( pThreadParameter->stopFlag == true ) || ( pThreadParameter->xResult == false ) )
        {
            break;
        }

        #if ( TRANSPORT_TEST_PRINT_DEBUG_PROGRESS == 1 )
            /* Output information to indicate the test is running. */
            UNITY_OUTPUT_CHAR( '.' );
        #endif
    }
}
#endif

/*-----------------------------------------------------------*/

static void prvRetunZeroRetryFunc( void * pParam )
{
    threadParameter_t * pThreadParameter = pParam;
    int32_t transportResult = 0;
    /* Pointer of writable test buffer. */
    uint8_t * pTransportTestBufferStart =
        &( pThreadParameter->transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    NetworkContext_t * pNetworkContext = pThreadParameter->pNetworkContext;

    pThreadParameter->xResult = true;

    /* Receive from remote server. No data will be recevied since no data is sent. */
    transportResult = pTestTransport->recv( pNetworkContext,
                                            pTransportTestBufferStart,
                                            TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );

    if( transportResult != 0 )
    {
        TEST_MESSAGE( "No data to receive should return 0." );
        pThreadParameter->xResult = false;
    }

    /* The buffer should remain unchanged when zero returned. */
    if( pThreadParameter->xResult == true )
    {
        pThreadParameter->xResult = prvVerifyTestData( pTransportTestBufferStart, 0, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    }

    /* Send some data to echo server then retry the receive operation. The receive
     * operation should be able to receive all the data. */
    /* Initialize the test data. */
    prvInitializeTestData( pTransportTestBufferStart, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );

    /* Send the test data to the server. */
    if( pThreadParameter->xResult == true )
    {
        pThreadParameter->xResult = prvTransportSendData( pTestTransport, pNetworkContext,
            pTransportTestBufferStart, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    }

    /* Receive the test data from server. */
    if( pThreadParameter->xResult == true )
    {
        pThreadParameter->xResult = prvTransportRecvData( pTestTransport, pNetworkContext,
            pTransportTestBufferStart, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    }

    /* Compare the test data received from server. */
    if( pThreadParameter->xResult == true )
    {
        pThreadParameter->xResult = prvVerifyTestData( pTransportTestBufferStart,
            TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    }
}

/*-----------------------------------------------------------*/

static void prvNoDataToReceiveFunc( void * pParam )
{
    threadParameter_t * pThreadParameter = pParam;
    int32_t transportResult = 0;
    /* Pointer of writable test buffer. */
    uint8_t * pTransportTestBufferStart =
        &( pThreadParameter->transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    NetworkContext_t * pNetworkContext = pThreadParameter->pNetworkContext;

    pThreadParameter->xResult = true;

    /* Receive from remote server. No data will be recevied since no data is sent. */
    transportResult = pTestTransport->recv( pNetworkContext,
                                            pTransportTestBufferStart,
                                            TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );

    if( transportResult != 0 )
    {
        TEST_MESSAGE( "No data to receive should return 0." );
        pThreadParameter->xResult = false;
    }

    /* The buffer should remain unchanged when zero returned. */
    if( pThreadParameter->xResult == true )
    {
        pThreadParameter->xResult = prvVerifyTestData( pTransportTestBufferStart, 0, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    }
}

/*-----------------------------------------------------------*/

/**
 * @brief Test setup function for transport interface test.
 */
TEST_SETUP( Full_TransportInterfaceTest )
{
    NetworkConnectStatus_t networkConnectResult = NETWORK_CONNECT_SUCCESS;
    uint8_t * pTransportTestBuffer = threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer;
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;
    uint32_t threadIndex;

    /* Reset the threadParameter status. */
    for( threadIndex = 0U; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        threadParameter[ threadIndex ].xNetworkConnected = false;
        threadParameter[ threadIndex ].xResult = false;
        threadParameter[ threadIndex ].stopFlag = false;
    }

    /* Ensure the test parameter is valid. testParam.pNetworkCredentials is not checked here. */
    TEST_ASSERT_NOT_NULL_MESSAGE( testParam.pTransport, "testParam.pTransport should not be NULL." );
    TEST_ASSERT_NOT_NULL_MESSAGE( testParam.pTransport->send, "testParam.pTransport->send should not be NULL." );
    TEST_ASSERT_NOT_NULL_MESSAGE( testParam.pTransport->recv, "testParam.pTransport->recv should not be NULL." );
#ifdef TRANSPORT_TEST_EXECUTE_WRITEV_TESTS
    TEST_ASSERT_NOT_NULL_MESSAGE( testParam.pTransport->writev, "testParam.pTransport->writev should not be NULL." );
#endif
    TEST_ASSERT_NOT_NULL_MESSAGE( testParam.pNetworkContext, "testParam.pNetworkContext should not be NULL." );
    TEST_ASSERT_NOT_NULL_MESSAGE( testParam.pSecondNetworkContext, "testParam.pSecondNetworkContext should not be NULL." );
    TEST_ASSERT_NOT_NULL_MESSAGE( testParam.pNetworkConnect, "testParam.pNetworkConnect should not be NULL." );
    TEST_ASSERT_NOT_NULL_MESSAGE( testParam.pNetworkDisconnect, "testParam.pNetworkDisconnect should not be NULL." );

    /* Setup the trasnport structure to use the primary network context. */
    pTestTransport = testParam.pTransport;

    /* Initialize the transport test buffer with TRANSPORT_TEST_BUFFER_GUARD_PATTERN. */
    memset( pTransportTestBuffer, TRANSPORT_TEST_BUFFER_GUARD_PATTERN, TRANSPORT_TEST_BUFFER_TOTAL_LENGTH );

    /* Call the hook function implemented by the application to initialize the transport interface. */
    networkConnectResult = testParam.pNetworkConnect( pNetworkContext,
                                                      &testHostInfo, testParam.pNetworkCredentials );
    TEST_ASSERT_EQUAL_INT32_MESSAGE( NETWORK_CONNECT_SUCCESS, networkConnectResult, "Network connect failed." );
    threadParameter[ TRANSPORT_TEST_INDEX ].xNetworkConnected = true;
}

/*-----------------------------------------------------------*/

/**
 * @brief Test tear down function for transport interface test.
 */
TEST_TEAR_DOWN( Full_TransportInterfaceTest )
{
    uint8_t * pTransportTestBuffer = threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer;
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;

    prvVerifyTestBufferGuard( pTransportTestBuffer );

    /* Call the hook function implemented by the application to de-initialize the transport interface. */
    if( threadParameter[ TRANSPORT_TEST_INDEX ].xNetworkConnected == true )
    {
        testParam.pNetworkDisconnect( pNetworkContext );
        threadParameter[ TRANSPORT_TEST_INDEX ].xNetworkConnected = false;
    }
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface send with NULL network context pointer handling.
 */
TEST( Full_TransportInterfaceTest, TransportSend_NetworkContextNullPtr )
{
    int32_t sendResult = 0;
    uint8_t * pTransportTestBuffer = threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer;

    /* Send with NULL network context pointer should return negative value. */
    sendResult = pTestTransport->send( NULL,
                                       &( pTransportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] ),
                                       TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, sendResult, "Transport interface send with NULL NetworkContext_t "
                                                        "pointer should return negative value." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface send with NULL buffer pointer handling.
 */
TEST( Full_TransportInterfaceTest, TransportSend_BufferNullPtr )
{
    int32_t sendResult = 0;
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;

    /* Send with NULL buffer pointer should return negative value. */
    sendResult = pTestTransport->send( pNetworkContext, NULL, 1 );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, sendResult, "Transport interface send with NULL buffer "
                                                        "pointer should return negative value." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface send with zero byte to send handling.
 */
TEST( Full_TransportInterfaceTest, TransportSend_ZeroByteToSend )
{
    int32_t sendResult = 0;
    uint8_t * pTransportTestBuffer = threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer;
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;

    /* Send with zero byte to send should return negative value. */
    sendResult = pTestTransport->send( pNetworkContext,
                                       &( pTransportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] ),
                                       0 );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, sendResult, "Transport interface send with zero byte "
                                                        "to send should return negative value." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface recv with NULL network context pointer handling.
 */
TEST( Full_TransportInterfaceTest, TransportRecv_NetworkContextNullPtr )
{
    int32_t recvResult = 0;
    uint8_t * pTransportTestBuffer = threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer;

    /* Receive with NULL network context pointer should return negative value. */
    recvResult = pTestTransport->recv( NULL,
                                       &( pTransportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] ),
                                       TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, recvResult, "Transport interface recv with NULL network "
                                                        "context pointer should return negative value." );

    TEST_ASSERT_EACH_EQUAL_HEX8_MESSAGE( TRANSPORT_TEST_BUFFER_GUARD_PATTERN,
                                         &( pTransportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] ),
                                         TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH,
                                         "transportTestBuffer should not be altered." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface recv with NULL buffer pointer handling.
 */
TEST( Full_TransportInterfaceTest, TransportRecv_BufferNullPtr )
{
    int32_t recvResult = 0;
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;

    /* Receive with NULL buffer pointer should return negative value. */
    recvResult = pTestTransport->recv( pNetworkContext, NULL, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, recvResult, "Transport interface recv with NULL buffer "
                                                        "pointer should return negative value." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface recv zero byte to receive handling.
 */
TEST( Full_TransportInterfaceTest, TransportRecv_ZeroByteToRecv )
{
    int32_t recvResult = 0;
    uint8_t * pTransportTestBuffer = threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer;
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;

    /* Receive with zero byte to recv should return negative value. */
    recvResult = pTestTransport->recv( pNetworkContext,
                                       &( pTransportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] ),
                                       0 );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, recvResult, "Transport interface recv with zero "
                                                        "byte to recv should return negative value." );

    TEST_ASSERT_EACH_EQUAL_HEX8_MESSAGE( TRANSPORT_TEST_BUFFER_GUARD_PATTERN,
                                         &( pTransportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] ),
                                         TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH,
                                         "transportTestBuffer should not be altered." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface with send one byte, receive and compare
 *
 * Test send receive beharivor in the following order.
 * Send : 1 byte
 * Send : ( TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH - 1 ) bytes
 * Receive : TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH bytes
 */
TEST( Full_TransportInterfaceTest, Transport_SendOneByteRecvCompare )
{
    /* Pointer of writable test buffer. */
    uint8_t * pTransportTestBufferStart =
        &( threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;
    bool retValue;

    /* Initialize the test data buffer. */
    prvInitializeTestData( pTransportTestBufferStart, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );

    /* Send the test data to the server. */
    retValue = prvTransportSendData( pTestTransport, pNetworkContext, pTransportTestBufferStart, 1U );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Send test data failed." );

    /* Send the rest test data to the server. */
    retValue = prvTransportSendData( pTestTransport, pNetworkContext, &pTransportTestBufferStart[ 1 ],
                                     ( TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH - 1U ) );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Send test data failed." );

    /* Receive the test data from server. */
    retValue = prvTransportRecvData( pTestTransport, pNetworkContext, pTransportTestBufferStart,
                                     TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Receive test data failed." );

    /* Compare the test data received from server. */
    retValue = prvVerifyTestData( pTransportTestBufferStart, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH,
                                  TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Verify test data failed." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface with send, receive one byte and compare.
 *
 * Test send receive beharivor in the following order.
 * Send : TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH bytes
 * Receive : 1 byte
 * Receive : ( TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH - 1 ) bytes
 */
TEST( Full_TransportInterfaceTest, Transport_SendRecvOneByteCompare )
{
    /* Pointer of writable test buffer. */
    uint8_t * pTransportTestBufferStart =
        &( threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;
    bool retValue;

    /* Initialize the test data buffer. */
    prvInitializeTestData( pTransportTestBufferStart, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );

    /* Send the test data to the server. */
    retValue = prvTransportSendData( pTestTransport, pNetworkContext, pTransportTestBufferStart,
                                     TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Send test data failed." );

    /* Reset the buffer. The buffer after received data is verified in prvVerifyTestData. */
    memset( pTransportTestBufferStart, TRANSPORT_TEST_BUFFER_GUARD_PATTERN, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );

    /* Receive one byte test data from server. */
    retValue = prvTransportRecvData( pTestTransport, pNetworkContext, pTransportTestBufferStart, 1U );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Receive test data failed." );

    /* Compare the test data received from server. */
    retValue = prvVerifyTestData( pTransportTestBufferStart, 1U, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Verify test data failed." );

    /* Receive remain test data from server. */
    retValue = prvTransportRecvData( pTestTransport, pNetworkContext, &pTransportTestBufferStart[ 1U ],
                                     ( TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH - 1U ) );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Receive test data failed." );

    /* Compare remain test data received from server. */
    retValue = prvVerifyTestData( pTransportTestBufferStart, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH,
                                  TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Verify test data failed." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface with send, receive and compare on variable length.
 */
TEST( Full_TransportInterfaceTest, Transport_SendRecvCompare )
{
    uint32_t testBufferSize;
    uint8_t * pTransportTestBufferStart =
        &( threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;
    bool retValue;

    for( testBufferSize = 1U; testBufferSize <= TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH; testBufferSize = testBufferSize + 1 )
    {
        /* Initialize the test data buffer. */
        prvInitializeTestData( pTransportTestBufferStart, testBufferSize );

        /* Send the test data to the server. */
        retValue = prvTransportSendData( pTestTransport, pNetworkContext, pTransportTestBufferStart,
                                         testBufferSize );
        TEST_ASSERT_MESSAGE( ( retValue == true ), "Send test data failed." );

        /* Receive the test data from server. */
        retValue = prvTransportRecvData( pTestTransport, pNetworkContext, pTransportTestBufferStart,
                                         testBufferSize );
        TEST_ASSERT_MESSAGE( ( retValue == true ), "Receive test data failed." );

        /* Compare the test data received from server. */
        retValue = prvVerifyTestData( pTransportTestBufferStart, testBufferSize, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
        TEST_ASSERT_MESSAGE( ( retValue == true ), "Verify test data failed." );

        #if ( TRANSPORT_TEST_PRINT_DEBUG_PROGRESS == 1 )
            /* Output information to indicate the test is running. */
            UNITY_OUTPUT_CHAR( '.' );
        #endif
    }
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface with send, receive and compare on variable length in multiple threads.
 */
TEST( Full_TransportInterfaceTest, Transport_SendRecvCompareMultithreaded )
{
    NetworkConnectStatus_t networkConnectResult = NETWORK_CONNECT_SUCCESS;
    int timedWaitResult = 0;
    FRTestThreadHandle_t threadHandle[ TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT ];
    uint32_t threadIndex;

    /* The primary thread parameter already setup in the test setup function. */
    for( threadIndex = 1U; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        memset( threadParameter[ threadIndex ].transportTestBuffer,
                TRANSPORT_TEST_BUFFER_GUARD_PATTERN, TRANSPORT_TEST_BUFFER_TOTAL_LENGTH );
    }

    /* Connect the secondary network context. */
    networkConnectResult = testParam.pNetworkConnect( threadParameter[ TRANSPORT_TEST_SECOND_INDEX ].pNetworkContext,
                                                      &testHostInfo, testParam.pNetworkCredentials );
    TEST_ASSERT_EQUAL_INT32_MESSAGE( NETWORK_CONNECT_SUCCESS, networkConnectResult, "Network connect failed." );
    threadParameter[ TRANSPORT_TEST_SECOND_INDEX ].xNetworkConnected = true;

    /* Create testing threads. */
    for( threadIndex = 0; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        /* threadParameters are initialized in test setup function. */
        threadHandle[ threadIndex ] = FRTest_ThreadCreate( prvSendRecvCompareFunc,
                                                           &threadParameter[ threadIndex ] );
    }

    /* Waiting for all test threads complete. */
    for( threadIndex = 0; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        if( threadHandle[ threadIndex ] != NULL )
        {
            timedWaitResult = FRTest_ThreadTimedJoin( threadHandle[ threadIndex ],
                                                      TRANSPORT_TEST_WAIT_THREAD_TIMEOUT_MS );

            if( timedWaitResult != 0 )
            {
                /* The created test thread runs over TRANSPORT_TEST_WAIT_THREAD_TIMEOUT_MS. */
                threadParameter[ threadIndex ].stopFlag = true;
            }
        }
        else
        {
            /* The thread is not created. */
            threadParameter[ threadIndex ].stopFlag = true;
        }
    }

    /* The primary thread network context will be closed in the test tear down function. */
    for( threadIndex = 1; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        testParam.pNetworkDisconnect( threadParameter[ threadIndex ].pNetworkContext );
        threadParameter[ threadIndex ].xNetworkConnected = false;
    }

    /* Check if every thread finish the test in time. */
    for( threadIndex = 0; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        /* Check the test buffer guard. */
        prvVerifyTestBufferGuard( threadParameter[ threadIndex ].transportTestBuffer );

        /* Check if the test thread timeout or not started. */
        TEST_ASSERT_MESSAGE( ( threadParameter[ threadIndex ].stopFlag != true ), "Test thread timeout or not created." );

        /* Check the test result. */
        TEST_ASSERT_MESSAGE( ( threadParameter[ threadIndex ].xResult == true ), "Test failed in test thread." );
    }
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface send function return value when disconnected.
 */
TEST( Full_TransportInterfaceTest, TransportSend_RemoteDisconnect )
{
    int32_t transportResult = 0;
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;
    uint8_t * pTransportTestBufferStart =
        &( threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );

    /* Send the disconnect command to remote server. */
    transportResult = pTestTransport->send( pNetworkContext,
                                            TRANSPORT_TEST_DISCONNECT_COMMAND,
                                            strlen( TRANSPORT_TEST_DISCONNECT_COMMAND ) );
    TEST_ASSERT_EQUAL_INT32_MESSAGE( strlen( TRANSPORT_TEST_DISCONNECT_COMMAND ), transportResult,
                                     "Transport send should not have any error." );

    /* Delay to wait for the command send to server and server disconnection. */
    FRTest_TimeDelay( TRANSPORT_TEST_NETWORK_DELAY_MS );

    /* Negative value should be returned if a network disconnection has occurred. */
    transportResult = pTestTransport->send( pNetworkContext,
                                            pTransportTestBufferStart,
                                            TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, transportResult,
                                         "Transport send should return negative value when disconnected." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface receive function return value when disconnected.
 */
TEST( Full_TransportInterfaceTest, TransportRecv_RemoteDisconnect )
{
    int32_t transportResult = 0;
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;
    uint8_t * pTransportTestBufferStart =
        &( threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );

    /* Send the disconnect command to remote server. */
    transportResult = pTestTransport->send( pNetworkContext,
                                            TRANSPORT_TEST_DISCONNECT_COMMAND,
                                            strlen( TRANSPORT_TEST_DISCONNECT_COMMAND ) );
    TEST_ASSERT_EQUAL_INT32_MESSAGE( strlen( TRANSPORT_TEST_DISCONNECT_COMMAND ), transportResult,
                                     "Transport send should not have any error." );

    /* Delay to wait for the command send to server. */
    FRTest_TimeDelay( TRANSPORT_TEST_NETWORK_DELAY_MS );

    /* Negative value should be returned if a network disconnection has occurred. */
    transportResult = pTestTransport->recv( pNetworkContext,
                                            pTransportTestBufferStart,
                                            TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, transportResult,
                                         "Transport receive should return negative value when disconnected." );

    /* The buffer should remain unchanged when negative value returned. */
    TEST_ASSERT_EACH_EQUAL_HEX8_MESSAGE( TRANSPORT_TEST_BUFFER_GUARD_PATTERN,
                                         pTransportTestBufferStart,
                                         TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH,
                                         "transportTestBuffer should not be altered." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface receive function return value when no data to receive.
 *
 * Transport interface recv function returns zero due to no data to receive. A test
 * thread is used in this test to prevent the implementation blocked in the receive
 * function when no data to receive.
 */
TEST( Full_TransportInterfaceTest, TransportRecv_NoDataToReceive )
{
    FRTestThreadHandle_t threadHandle;
    int timedWaitResult = 0;

    /* Create testing thread. threadParameters are initialized in test setup function. */
    threadHandle = FRTest_ThreadCreate( prvNoDataToReceiveFunc,
                                        &threadParameter[ TRANSPORT_TEST_INDEX ] );
    TEST_ASSERT_MESSAGE( threadHandle != NULL, "Create thread failed." );

    /* Waiting for the test thread complete. */
    timedWaitResult = FRTest_ThreadTimedJoin( threadHandle,
                                              TRANSPORT_TEST_WAIT_THREAD_RECEIVE_TIMEOUT_MS );

    if( timedWaitResult != 0 )
    {
        threadParameter[ TRANSPORT_TEST_INDEX ].stopFlag = true;
    }

    TEST_ASSERT_MESSAGE( timedWaitResult == 0, "Waiting for test thread receive data failed." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface receive return zero retry.
 *
 * Transport interface recv function returns zero due to no data to receive. The test
 * sends test data to remote server and retry the transport receive operation. Transport
 * receive function should be able to receive data. A test thread is used in this test
 * to prevent the implementation blocked in the receive function when no data to receive.
 */
TEST( Full_TransportInterfaceTest, TransportRecv_ReturnZeroRetry )
{
    FRTestThreadHandle_t threadHandle;
    int timedWaitResult = 0;

    /* Create testing thread. threadParameters are initialized in test setup function. */
    threadHandle = FRTest_ThreadCreate( prvRetunZeroRetryFunc,
                                        &threadParameter[ TRANSPORT_TEST_INDEX ] );
    TEST_ASSERT_MESSAGE( threadHandle != NULL, "Create thread failed." );

    /* Waiting for the test thread complete. */
    timedWaitResult = FRTest_ThreadTimedJoin( threadHandle,
                                              TRANSPORT_TEST_WAIT_THREAD_RECEIVE_TIMEOUT_MS );

    if( timedWaitResult != 0 )
    {
        threadParameter[ TRANSPORT_TEST_INDEX ].stopFlag = true;
    }

    TEST_ASSERT_MESSAGE( timedWaitResult == 0, "Waiting for test thread receive data failed." );
}

/*-----------------------------------------------------------*/
#ifdef TRANSPORT_TEST_EXECUTE_WRITEV_TESTS
/**
 * @brief Test transport interface writev with NULL network context pointer handling.
 */
TEST( Full_TransportInterfaceTest, TransportWritev_NetworkContextNullPtr )
{
    int32_t sendResult = 0;
    TransportOutVector_t transportTestVector = { threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH };

    /* writev with NULL network context pointer should return negative value. */
    sendResult = pTestTransport->writev( NULL,
                                         &( transportTestVector ),
                                         1U );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, sendResult, "Transport interface writev with NULL NetworkContext_t "
                                                        "pointer should return negative value." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface writev with NULL buffer pointer handling.
 */
TEST( Full_TransportInterfaceTest, TransportWritev_BufferNullPtr )
{
    int32_t sendResult = 0;
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;

    /* Writev with NULL buffer pointer should return negative value. */
    sendResult = pTestTransport->writev( pNetworkContext, NULL, 1 );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, sendResult, "Transport interface writev with NULL vector "
                                                        "pointer should return negative value." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface writev with zero vectors to send handling.
 */
TEST( Full_TransportInterfaceTest, TransportWritev_ZeroVectorsToSend )
{
    int32_t sendResult = 0;
    TransportOutVector_t transportTestVector = { threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH };
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;

    /* Send with zero byte to send should return negative value. */
    sendResult = pTestTransport->writev( pNetworkContext,
                                         &transportTestVector,
                                         0 );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, sendResult, "Transport interface writev with zero vectors "
                                                        "to send should return negative value." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface writev when one of the vector array entries has a length
 * of 0.
 *
 * Transport interface writev should return a negative value if any member of the vector array
 * has the length 0.
 */
TEST( Full_TransportInterfaceTest, TransportWritev_OneVectorLengthZero )
{
    uint8_t * pTransportTestBufferStart =
        &( threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;
    TransportOutVector_t pTransportTestVectorArray[ 3U ];
    const size_t ioVecCount = 3U;
    int32_t transportResult;

    /* A pre-requisite for this test requires that the buffer should be at least 3 bytes long. */
    TEST_ASSERT_GREATER_OR_EQUAL_size_t_MESSAGE( 3U,
                                                 TRANSPORT_TEST_BUFFER_TOTAL_LENGTH,
                                                 "The TRANSPORT_TEST_BUFFER_TOTAL_LENGTH must be greater than "
                                                 "or equal to 3 for this test to be run successfully." );

    /* Set the first array pointer. Set the length to 1. */
    pTransportTestVectorArray[ 0U ].iov_base = pTransportTestBufferStart;
    pTransportTestVectorArray[ 0U ].iov_len = 1U;

    /* Set the second array pointer. Set the length to 0. */
    pTransportTestVectorArray[ 1U ].iov_base = &pTransportTestBufferStart[ 1U ];
    pTransportTestVectorArray[ 1U ].iov_len = 0U;

    /* Set the third array pointer. Set the length to 1. */
    pTransportTestVectorArray[ 2U ].iov_base = &pTransportTestBufferStart[ 2U ];
    pTransportTestVectorArray[ 2U ].iov_len = 1U;

    TEST_ASSERT_FALSE_MESSAGE( prvTransportWritevData( pTestTransport, pNetworkContext, pTransportTestVectorArray, ioVecCount ),
                               "Sending of a vector array with zero length member must fail" );

    /* Negative value should be returned if a network disconnection has occurred. */
    transportResult = pTestTransport->recv( pNetworkContext,
                                            pTransportTestBufferStart,
                                            TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_EQUAL_INT32_MESSAGE( 1, transportResult,
                                     "Transport receive must only return one byte. Other bytes should not be sent by writev." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface writev when one of the vector array entries has a the data
 * pointer as NULL.
 *
 * Transport interface writev should return a negative value if any member of the vector array
 * has the data pointer pointing to NULL.
 */
TEST(Full_TransportInterfaceTest, TransportWritev_OneVectorBufferNullPtr )
{
    uint8_t * pTransportTestBufferStart =
        &( threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;
    TransportOutVector_t pTransportTestVectorArray[ 3U ];
    const size_t ioVecCount = 3U;
    int32_t transportResult;

    /* A pre-requisite for this test requires that the buffer should be at least 3 bytes long. */
    TEST_ASSERT_GREATER_OR_EQUAL_size_t_MESSAGE( 3U,
                                                 TRANSPORT_TEST_BUFFER_TOTAL_LENGTH,
                                                 "The TRANSPORT_TEST_BUFFER_TOTAL_LENGTH must be greater than "
                                                 "or equal to 3 for this test to be run successfully." );

    /* Set the first array pointer. Set the length to 1. */
    pTransportTestVectorArray[ 0U ].iov_base = pTransportTestBufferStart;
    pTransportTestVectorArray[ 0U ].iov_len = 1U;

    /* Set the second array pointer to NULL. Set the length to 1. */
    pTransportTestVectorArray[ 1U ].iov_base = NULL;
    pTransportTestVectorArray[ 1U ].iov_len = 0U;

    /* Set the third array pointer. Set the length to 1. */
    pTransportTestVectorArray[ 2U ].iov_base = &pTransportTestBufferStart[ 2U ];
    pTransportTestVectorArray[ 2U ].iov_len = 1U;

    TEST_ASSERT_FALSE_MESSAGE( prvTransportWritevData( pTestTransport, pNetworkContext, pTransportTestVectorArray, ioVecCount ),
                               "Sending of a vector array with a NULL base pointer must fail." );

    /* Negative value should be returned if a network disconnection has occurred. */
    transportResult = pTestTransport->recv( pNetworkContext,
                                            pTransportTestBufferStart,
                                            TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_EQUAL_INT32_MESSAGE( 1, transportResult,
                                     "Transport receive must only return one byte. Other bytes should not be sent by writev." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface with writev one byte, receive and compare
 *
 * Test writev receive beharivor in the following order.
 * Send : 1 byte
 * Send : ( TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH - 1 ) bytes
 * Receive : TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH bytes
 */
TEST( Full_TransportInterfaceTest, Transport_WritevOneByteRecvCompare )
{
    /* Pointer of writable test buffer. */
    uint8_t * pTransportTestBufferStart =
        &( threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;
    bool retValue;
    TransportOutVector_t pTransportVectorArray[ 2U ];

    pTransportVectorArray[ 0U ].iov_base = pTransportTestBufferStart;
    pTransportVectorArray[ 0U ].iov_len = 1U;

    pTransportVectorArray[ 1U ].iov_base = &pTransportTestBufferStart[ 1U ];
    pTransportVectorArray[ 1U ].iov_len = ( TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH - 1U );

    /* Initialize the test data buffer. */
    prvInitializeTestData( pTransportTestBufferStart, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );

    /* Send 1 byte of test data to the server. */
    retValue = prvTransportWritevData( pTestTransport, pNetworkContext, &pTransportVectorArray[ 0U ], 1U );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Send test data failed." );

    /* Send the rest test data to the server. */
    retValue = prvTransportWritevData( pTestTransport, pNetworkContext, &pTransportVectorArray[ 1U ], 1U );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Send test data failed." );

    /* Receive the test data from server. */
    retValue = prvTransportRecvData( pTestTransport, pNetworkContext, pTransportTestBufferStart,
                                     TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Receive test data failed." );

    /* Compare the test data received from server. */
    retValue = prvVerifyTestData( pTransportTestBufferStart, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH,
                                  TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
    TEST_ASSERT_MESSAGE( ( retValue == true ), "Verify test data failed." );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface with writev, receive and compare on variable length.
 */
TEST( Full_TransportInterfaceTest, Transport_WritevRecvCompare )
{
    uint32_t testBufferSize;
    uint8_t * pTransportTestBufferStart =
        &( threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] );
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;
    bool retValue;
    TransportOutVector_t pTransportTestVectorArray[ 5U ];
    size_t ioVecCount;

    for( testBufferSize = 1U; testBufferSize <= TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH; testBufferSize = testBufferSize + 1 )
    {
        if( testBufferSize % 5 == 0 )
        {
            ioVecCount = 5U;
        }
        else if( testBufferSize % 3 == 0 )
        {
            ioVecCount = 3U;
        }
        else if( testBufferSize % 2 == 0 )
        {
            ioVecCount = 2U;
        }
        else
        {
            ioVecCount = 1U;
        }

        for( size_t index = 0U; index < ioVecCount; index ++ )
        {
            pTransportTestVectorArray[ index ].iov_base = &pTransportTestBufferStart[ index * ( testBufferSize / ioVecCount ) ];;
            pTransportTestVectorArray[ index ].iov_len = testBufferSize / ioVecCount;
        }

        /* Initialize the test data buffer. */
        prvInitializeTestData( pTransportTestBufferStart, testBufferSize );

        /* Send the test data to the server. */
        retValue = prvTransportWritevData( pTestTransport, pNetworkContext, pTransportTestVectorArray,
                                           ioVecCount );
        TEST_ASSERT_MESSAGE( ( retValue == true ), "Send test data failed." );

        /* Receive the test data from server. */
        retValue = prvTransportRecvData( pTestTransport, pNetworkContext, pTransportTestBufferStart,
                                         testBufferSize );
        TEST_ASSERT_MESSAGE( ( retValue == true ), "Receive test data failed." );

        /* Compare the test data received from server. */
        retValue = prvVerifyTestData( pTransportTestBufferStart, testBufferSize, TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH );
        TEST_ASSERT_MESSAGE( ( retValue == true ), "Verify test data failed." );

        #if ( TRANSPORT_TEST_PRINT_DEBUG_PROGRESS == 1 )
            /* Output information to indicate the test is running. */
            UNITY_OUTPUT_CHAR( '.' );
        #endif
    }
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface with writev, receive and compare on variable length in multiple threads.
 */
TEST( Full_TransportInterfaceTest, Transport_WritevRecvCompareMultithreaded )
{
    NetworkConnectStatus_t networkConnectResult = NETWORK_CONNECT_SUCCESS;
    int timedWaitResult = 0;
    FRTestThreadHandle_t threadHandle[ TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT ];
    uint32_t threadIndex;

    /* The primary thread parameter already setup in the test setup function. */
    for( threadIndex = 1U; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        memset( threadParameter[ threadIndex ].transportTestBuffer,
                TRANSPORT_TEST_BUFFER_GUARD_PATTERN, TRANSPORT_TEST_BUFFER_TOTAL_LENGTH );
    }

    /* Connect the secondary network context. */
    networkConnectResult = testParam.pNetworkConnect( threadParameter[ TRANSPORT_TEST_SECOND_INDEX ].pNetworkContext,
                                                      &testHostInfo, testParam.pNetworkCredentials );
    TEST_ASSERT_EQUAL_INT32_MESSAGE( NETWORK_CONNECT_SUCCESS, networkConnectResult, "Network connect failed." );
    threadParameter[ TRANSPORT_TEST_SECOND_INDEX ].xNetworkConnected = true;

    /* Create testing threads. */
    for( threadIndex = 0; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        /* threadParameters are initialized in test setup function. */
        threadHandle[ threadIndex ] = FRTest_ThreadCreate( prvWritevRecvCompareFunc,
                                                           &threadParameter[ threadIndex ] );
    }

    /* Waiting for all test threads complete. */
    for( threadIndex = 0; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        if( threadHandle[ threadIndex ] != NULL )
        {
            timedWaitResult = FRTest_ThreadTimedJoin( threadHandle[ threadIndex ],
                                                      TRANSPORT_TEST_WAIT_THREAD_TIMEOUT_MS );

            if( timedWaitResult != 0 )
            {
                /* The created test thread runs over TRANSPORT_TEST_WAIT_THREAD_TIMEOUT_MS. */
                threadParameter[ threadIndex ].stopFlag = true;
            }
        }
        else
        {
            /* The thread is not created. */
            threadParameter[ threadIndex ].stopFlag = true;
        }
    }

    /* The primary thread network context will be closed in the test tear down function. */
    for( threadIndex = 1; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        testParam.pNetworkDisconnect( threadParameter[ threadIndex ].pNetworkContext );
        threadParameter[ threadIndex ].xNetworkConnected = false;
    }

    /* Check if every thread finish the test in time. */
    for( threadIndex = 0; threadIndex < TRANSPORT_TEST_MULTI_THREAD_TASK_COUNT; threadIndex++ )
    {
        /* Check the test buffer guard. */
        prvVerifyTestBufferGuard( threadParameter[ threadIndex ].transportTestBuffer );

        /* Check if the test thread timeout or not started. */
        TEST_ASSERT_MESSAGE( ( threadParameter[ threadIndex ].stopFlag != true ), "Test thread timeout or not created." );

        /* Check the test result. */
        TEST_ASSERT_MESSAGE( ( threadParameter[ threadIndex ].xResult == true ), "Test failed in test thread." );
    }
}

/*-----------------------------------------------------------*/

/**
 * @brief Test transport interface writev function return value when disconnected.
 */
TEST( Full_TransportInterfaceTest, TransportWritev_RemoteDisconnect )
{
    int32_t transportResult = 0;
    NetworkContext_t * pNetworkContext = threadParameter[ TRANSPORT_TEST_INDEX ].pNetworkContext;

    TransportOutVector_t transportTestVectorDisconnect = { TRANSPORT_TEST_DISCONNECT_COMMAND, strlen( TRANSPORT_TEST_DISCONNECT_COMMAND ) };
    TransportOutVector_t transportTestVectorbuffer = { &( threadParameter[ TRANSPORT_TEST_INDEX ].transportTestBuffer[ TRANSPORT_TEST_BUFFER_PREFIX_GUARD_LENGTH ] ), TRANSPORT_TEST_BUFFER_WRITABLE_LENGTH };

    /* Send the disconnect command to remote server. */
    transportResult = pTestTransport->writev( pNetworkContext,
                                              &transportTestVectorDisconnect,
                                              1U );
    TEST_ASSERT_EQUAL_INT32_MESSAGE( strlen( TRANSPORT_TEST_DISCONNECT_COMMAND ), transportResult,
                                     "Transport writev should not have any error." );

    /* Delay to wait for the command send to server and server disconnection. */
    FRTest_TimeDelay( TRANSPORT_TEST_NETWORK_DELAY_MS );

    /* Negative value should be returned if a network disconnection has occurred. */
    transportResult = pTestTransport->writev( pNetworkContext,
                                              &transportTestVectorbuffer,
                                              1U );
    TEST_ASSERT_LESS_THAN_INT32_MESSAGE( 0, transportResult,
                                         "Transport writev should return negative value when disconnected." );
}

#endif
/*-----------------------------------------------------------*/

/**
 * @brief Test group runner for transport interface test against echo server.
 */
TEST_GROUP_RUNNER( Full_TransportInterfaceTest )
{
    /* Invalid parameter test. Disable or replace assert may be required to run these tests. */
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportSend_NetworkContextNullPtr );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportSend_BufferNullPtr );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportSend_ZeroByteToSend );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportRecv_NetworkContextNullPtr );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportRecv_BufferNullPtr );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportRecv_ZeroByteToRecv );

    /* Send and receive correctness test. */
    RUN_TEST_CASE( Full_TransportInterfaceTest, Transport_SendOneByteRecvCompare );
    RUN_TEST_CASE( Full_TransportInterfaceTest, Transport_SendRecvOneByteCompare );
    RUN_TEST_CASE( Full_TransportInterfaceTest, Transport_SendRecvCompare );
    RUN_TEST_CASE( Full_TransportInterfaceTest, Transport_SendRecvCompareMultithreaded );

    /* Disconnect test. */
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportSend_RemoteDisconnect );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportRecv_RemoteDisconnect );

    /* Transport behavior test. */
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportRecv_NoDataToReceive );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportRecv_ReturnZeroRetry );

#ifdef TRANSPORT_TEST_EXECUTE_WRITEV_TESTS
    /* Invalid parameter test. Disable or replace assert may be required to run these tests. */
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportWritev_NetworkContextNullPtr );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportWritev_BufferNullPtr );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportWritev_ZeroVectorsToSend );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportWritev_OneVectorBufferNullPtr );
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportWritev_OneVectorLengthZero );

    /* Send and receive correctness test. */
    RUN_TEST_CASE( Full_TransportInterfaceTest, Transport_WritevOneByteRecvCompare );
    RUN_TEST_CASE( Full_TransportInterfaceTest, Transport_WritevRecvCompare );
    RUN_TEST_CASE( Full_TransportInterfaceTest, Transport_WritevRecvCompareMultithreaded );

    /* Disconnect test. */
    RUN_TEST_CASE( Full_TransportInterfaceTest, TransportWritev_RemoteDisconnect );
#endif
}

/*-----------------------------------------------------------*/

int RunTransportInterfaceTest( void )
{
    int status = -1;

    /* Assign the TransportInterface_t pointer used in test cases. */
    SetupTransportTestParam( &testParam );
    threadParameter[ 0 ].pNetworkContext = testParam.pNetworkContext;
    threadParameter[ 1 ].pNetworkContext = testParam.pSecondNetworkContext;
    testHostInfo.pHostName = ECHO_SERVER_ENDPOINT;
    testHostInfo.port = ECHO_SERVER_PORT;

    /* Initialize unity. */
    UnityFixture.Verbose = 1;
    UnityFixture.GroupFilter = 0;
    UnityFixture.NameFilter = 0;
    UnityFixture.RepeatCount = 1;
    UNITY_BEGIN();

    /* Run the test group. */
    RUN_TEST_GROUP( Full_TransportInterfaceTest );

    status = UNITY_END();

    return status;
}

/*-----------------------------------------------------------*/

#endif /* if ( TRANSPORT_INTERFACE_TEST_ENABLED == 1 ) */
