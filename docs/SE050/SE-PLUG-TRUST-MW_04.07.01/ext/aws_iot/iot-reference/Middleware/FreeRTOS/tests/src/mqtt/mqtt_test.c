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
 * @file mqtt_test.c
 * @brief Implements test functions for MQTT test.
 */

#include "test_execution_config.h"
#if ( MQTT_TEST_ENABLED == 1 )

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include "core_mqtt.h"
#include "core_mqtt_state.h"
#include "unity.h"
#include "unity_fixture.h"

#include "mqtt_test.h"
#include "test_param_config.h"
#include "platform_function.h"

/*-----------------------------------------------------------*/

/**
 * @brief Length of MQTT server host name.
 */
#define BROKER_ENDPOINT_LENGTH                  ( ( uint16_t ) ( sizeof( BROKER_ENDPOINT ) - 1 ) )

/**
 * @brief A valid starting packet ID per MQTT spec. Start from 1.
 */
#define MQTT_FIRST_VALID_PACKET_ID              ( 1 )

/**
 * @brief A PINGREQ packet is always 2 bytes in size, defined by MQTT 3.1.1 spec.
 */
#define MQTT_PACKET_PINGREQ_SIZE                ( 2U )

/**
 * @brief A packet type not handled by MQTT_ProcessLoop.
 */
#define MQTT_PACKET_TYPE_INVALID                ( 0U )

/**
 * @brief Number of milliseconds in a second.
 */
#define MQTT_ONE_SECOND_TO_MS                   ( 1000U )

/**
 * @brief Length of the MQTT network buffer.
 */
#define MQTT_TEST_BUFFER_LENGTH                 ( 128 )

/**
 * @brief Sample length of remaining serialized data.
 */
#define MQTT_SAMPLE_REMAINING_LENGTH            ( 64 )

/**
 * @brief Subtract this value from max value of global entry time
 * for the timer overflow test.
 */
#define MQTT_OVERFLOW_OFFSET                    ( 3 )

/**
 * @brief Sample topic filter to subscribe to.
 */
#define TEST_MQTT_TOPIC                         MQTT_TEST_CLIENT_IDENTIFIER "/iot/integration/test"

/**
 * @brief Sample topic filter 2 to use in tests.
 */
#define TEST_MQTT_TOPIC_2                       MQTT_TEST_CLIENT_IDENTIFIER "/iot/integration/test2"

/**
 * @brief Sample topic filter 3 to use in tests.
 */
#define TEST_MQTT_TOPIC_3                       MQTT_TEST_CLIENT_IDENTIFIER "/iot/integration/testTopic3"

/**
 * @brief Sample topic filter 4 to use in tests.
 */
#define TEST_MQTT_TOPIC_4                       MQTT_TEST_CLIENT_IDENTIFIER "/iot/integration/testFour"

/**
 * @brief Sample topic filter 5 to use in tests.
 */
#define TEST_MQTT_TOPIC_5                       MQTT_TEST_CLIENT_IDENTIFIER "/iot/integration/testTopicName5"

/**
 * @brief Sample topic filter to test MQTT retainted message.
 */
#define TEST_MQTT_RETAIN_TOPIC                  MQTT_TEST_CLIENT_IDENTIFIER "/iot/integration/testretain"

/**
 * @brief Length of sample topic filter.
 */
#define TEST_MQTT_TOPIC_LENGTH                  ( sizeof( TEST_MQTT_TOPIC ) - 1 )

/**
 * @brief Sample topic filter to subscribe to.
 */
#define TEST_MQTT_LWT_TOPIC                     MQTT_TEST_CLIENT_IDENTIFIER "/iot/integration/test/lwt"

/**
 * @brief Length of sample topic filter.
 */
#define TEST_MQTT_LWT_TOPIC_LENGTH              ( sizeof( TEST_MQTT_LWT_TOPIC ) - 1 )

/**
 * @brief Length of the client identifier.
 */
#define TEST_CLIENT_IDENTIFIER_LENGTH           ( sizeof( MQTT_TEST_CLIENT_IDENTIFIER ) - 1u )

/**
 * @brief Client identifier for use in LWT tests.
 */
#define TEST_CLIENT_IDENTIFIER_LWT              MQTT_TEST_CLIENT_IDENTIFIER "-LWT"

/**
 * @brief Length of LWT client identifier.
 */
#define TEST_CLIENT_IDENTIFIER_LWT_LENGTH       ( sizeof( TEST_CLIENT_IDENTIFIER_LWT ) - 1u )

/**
 * @brief The largest random number to use in client identifier.
 *
 * @note Random number is added to MQTT client identifier to avoid client
 * identifier collisions while connecting to MQTT broker.
 */
#define MAX_RAND_NUMBER_FOR_CLIENT_ID           ( 999u )

/**
 * @brief Maximum number of random number digits in Client Identifier.
 * @note The value is derived from the #MAX_RAND_NUM_IN_FOR_CLIENT_ID.
 */
#define MAX_RAND_NUMBER_DIGITS_FOR_CLIENT_ID    ( 3u )


/**
 * @brief Timeout for receiving CONNACK packet in milli seconds.
 */
#define CONNACK_RECV_TIMEOUT_MS             ( 1000U )

/**
 * @brief Time interval in seconds at which an MQTT PINGREQ need to be sent to
 * broker.
 */
#define MQTT_KEEP_ALIVE_INTERVAL_SECONDS    ( 5U )

/**
 * @brief The MQTT message published in this example.
 */
#define MQTT_EXAMPLE_MESSAGE                "Hello World!"

/*-----------------------------------------------------------*/

#if ( MQTT_TEST_ENABLED == 1 )
    #ifndef MQTT_SERVER_ENDPOINT
        #error "Please define MQTT_SERVER_ENDPOINT"
    #endif
    
    #ifndef MQTT_SERVER_PORT
        #error "Please define MQTT_SERVER_PORT"
    #endif
#endif /* if ( MQTT_TEST_ENABLED == 1 ) */

/*-----------------------------------------------------------*/

/**
 * @brief a struct of test parameters filled in by user.
 */
static MqttTestParam_t testParam;

/**
 * @brief info of the server to connect to for tests.
 */
static TestHostInfo_t testHostInfo;

/**
 * @brief Packet Identifier generated when Subscribe request was sent to the broker;
 * it is used to match received Subscribe ACK to the transmitted subscribe.
 */
static uint16_t globalSubscribePacketIdentifier = 0U;

/**
 * @brief Packet Identifier generated when Unsubscribe request was sent to the broker;
 * it is used to match received Unsubscribe ACK to the transmitted unsubscribe
 * request.
 */
static uint16_t globalUnsubscribePacketIdentifier = 0U;

/**
 * @brief Packet Identifier generated when Publish request was sent to the broker;
 * it is used to match acknowledgement responses to the transmitted publish
 * request.
 */
static uint16_t globalPublishPacketIdentifier = 0U;

/**
 * @brief The context representing the MQTT connection with the broker for
 * the test case.
 */
static MQTTContext_t context;

/**
 * @brief Flag that represents whether a persistent session was resumed
 * with the broker for the test.
 */
static bool persistentSession = false;

/**
 * @brief Flag to indicate if LWT is being used when establishing a connection.
 */
static bool useLWTClientIdentifier = false;

/**
 * @brief Flag to represent whether a SUBACK is received from the broker.
 */
static bool receivedSubAck = false;

/**
 * @brief Flag to represent whether an UNSUBACK is received from the broker.
 */
static bool receivedUnsubAck = false;

/**
 * @brief Flag to represent whether a PUBACK is received from the broker.
 */
static bool receivedPubAck = false;

/**
 * @brief Flag to represent whether a PUBREC is received from the broker.
 */
static bool receivedPubRec = false;

/**
 * @brief Flag to represent whether a PUBREL is received from the broker.
 */
static bool receivedPubRel = false;

/**
 * @brief Flag to represent whether a PUBCOMP is received from the broker.
 */
static bool receivedPubComp = false;

/**
 * @brief Flag to represent whether an incoming PUBLISH packet is received
 * with the "retain" flag set.
 */
static bool receivedRetainedMessage = false;

/**
 * @brief Represents incoming PUBLISH information.
 */
static MQTTPublishInfo_t incomingInfo;

/**
 * @brief Disconnect when receiving this packet type. Used for session
 * restoration tests.
 */
static uint8_t packetTypeForDisconnection = MQTT_PACKET_TYPE_INVALID;

/**
 * @brief Random number for the client identifier of the MQTT connection(s) in
 * the test.
 *
 * Random number is used to avoid client identifier collisions while connecting
 * to MQTT broker.
 */
static int clientIdRandNumber;

/*-----------------------------------------------------------*/

/**
 * @brief Sends an MQTT CONNECT packet over the already connected TCP socket.
 *
 * @param[in] pContext MQTT context pointer.
 * @param[in] pNetworkContext Network context for mqtt connection
 * @param[in] createCleanSession Creates a new MQTT session if true.
 * If false, tries to establish the existing session if there was session
 * already present in broker.
 * @param[out] pSessionPresent Session was already present in the broker or not.
 * Session present response is obtained from the CONNACK from broker.
 */
static void establishMqttSession( MQTTContext_t * pContext,
                                  void * pNetworkContext,
                                  bool createCleanSession,
                                  bool * pSessionPresent );

/**
 * @brief Handler for incoming acknowledgement packets from the broker.
 * @param[in] pPacketInfo Info for the incoming acknowledgement packet.
 * @param[in] packetIdentifier The ID of the incoming packet.
 */
static void handleAckEvents( MQTTPacketInfo_t * pPacketInfo,
                             uint16_t packetIdentifier );

/**
 * @brief The application callback function that is expected to be invoked by the
 * MQTT library for incoming publish and incoming acks received over the network.
 *
 * @param[in] pContext MQTT context pointer.
 * @param[in] pPacketInfo Packet Info pointer for the incoming packet.
 * @param[in] pDeserializedInfo Deserialized information from the incoming packet.
 */
static void eventCallback( MQTTContext_t * pContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo );

/**
 * @brief Implementation of TransportSend_t interface that terminates the TLS
 * and TCP connection with the broker and returns failure.
 *
 * @param[in] pNetworkContext The context associated with the network connection
 * to be disconnected.
 * @param[in] pBuffer This parameter is ignored.
 * @param[in] bytesToRecv This parameter is ignored.
 *
 * @return -1 to represent failure.
 */
static int32_t failedRecv( NetworkContext_t * pNetworkContext,
                           void * pBuffer,
                           size_t bytesToRecv );


/**
 * @brief Helper function to start a new persistent session.
 * It terminates the existing "clean session", and creates a new connection
 * with the "clean session" flag set to 0 to create a persistent session
 * with the broker.
 */
static void startPersistentSession();

/**
 * @brief Helper function to resume connection in persistent session
 * with the broker.
 * It resumes the session with the broker by establishing a new connection
 * with the "clean session" flag set to 0.
 */
static void resumePersistentSession();


/**
 * @brief Test group for transport interface test.
 */
TEST_GROUP( MqttTest );
/*-----------------------------------------------------------*/

static void establishMqttSession( MQTTContext_t * pContext,
                                  void * pNetworkContext,
                                  bool createCleanSession,
                                  bool * pSessionPresent )
{
    MQTTConnectInfo_t connectInfo;
    TransportInterface_t transport;
    MQTTFixedBuffer_t networkBuffer;
    MQTTPublishInfo_t lwtInfo;

    assert( pContext != NULL );

    /* The network buffer must remain valid for the lifetime of the MQTT context. */
    static uint8_t buffer[ MQTT_TEST_NETWORK_BUFFER_SIZE ];

    /* Buffer for storing client ID with random integer.
     * Note: Size value is chosen to accommodate both LWT and non-LWT client ID
     * strings along with NULL character.*/
    char clientIdBuffer[ TEST_CLIENT_IDENTIFIER_LWT_LENGTH +
                         MAX_RAND_NUMBER_DIGITS_FOR_CLIENT_ID + 1u ] = { 0 };

    static MQTTPubAckInfo_t pOutgoingPublishRecords[ OUTGOING_PUBLISH_RECORD_COUNT ];
    static MQTTPubAckInfo_t pIncomingPublishRecords[ INCOMING_PUBLISH_RECORD_COUNT ];

    /* Fill the values for network buffer. */
    networkBuffer.pBuffer = buffer;
    networkBuffer.size = MQTT_TEST_NETWORK_BUFFER_SIZE;

    transport.pNetworkContext = pNetworkContext;
    transport.send = testParam.pTransport->send;
    transport.recv = testParam.pTransport->recv;
    transport.writev = testParam.pTransport->writev;

    /* Clear the state of the MQTT context when creating a clean session. */
    if( createCleanSession == true )
    {
        /* Initialize MQTT library. */
        TEST_ASSERT_EQUAL( MQTTSuccess, MQTT_Init( pContext,
                                                   &transport,
                                                   testParam.pGetTimeMs,
                                                   eventCallback,
                                                   &networkBuffer ) );

        TEST_ASSERT_EQUAL( MQTTSuccess, MQTT_InitStatefulQoS( pContext,
                                                              pOutgoingPublishRecords,
                                                              OUTGOING_PUBLISH_RECORD_COUNT,
                                                              pIncomingPublishRecords,
                                                              INCOMING_PUBLISH_RECORD_COUNT ) );
    }

    /* Establish MQTT session with a CONNECT packet. */

    connectInfo.cleanSession = createCleanSession;

    if( useLWTClientIdentifier )
    {
        /* Populate client identifier for connection with LWT topic with random number. */
        connectInfo.clientIdentifierLength =
            snprintf( clientIdBuffer, sizeof( clientIdBuffer ),
                      "%d%s",
                      clientIdRandNumber,
                      TEST_CLIENT_IDENTIFIER_LWT );
        connectInfo.pClientIdentifier = clientIdBuffer;
    }
    else
    {
        /* Populate client identifier with random number. */
        connectInfo.clientIdentifierLength =
            snprintf( clientIdBuffer,
                      sizeof( clientIdBuffer ),
                      "%d%s", clientIdRandNumber,
                      MQTT_TEST_CLIENT_IDENTIFIER );
        connectInfo.pClientIdentifier = clientIdBuffer;
    }

    LogDebug( ( "Created randomized client ID for MQTT connection: ClientID={%.*s}", connectInfo.clientIdentifierLength,
                connectInfo.pClientIdentifier ) );

    /* The interval at which an MQTT PINGREQ needs to be sent out to broker. */
    connectInfo.keepAliveSeconds = MQTT_KEEP_ALIVE_INTERVAL_SECONDS;

    /* Username and password for authentication. Not used in this test. */
    connectInfo.pUserName = NULL;
    connectInfo.userNameLength = 0U;
    connectInfo.pPassword = NULL;
    connectInfo.passwordLength = 0U;

    /* LWT Info. */
    lwtInfo.pTopicName = TEST_MQTT_LWT_TOPIC;
    lwtInfo.topicNameLength = TEST_MQTT_LWT_TOPIC_LENGTH;
    lwtInfo.pPayload = MQTT_EXAMPLE_MESSAGE;
    lwtInfo.payloadLength = strlen( MQTT_EXAMPLE_MESSAGE );
    lwtInfo.qos = MQTTQoS0;
    lwtInfo.dup = false;
    lwtInfo.retain = false;

    /* Send MQTT CONNECT packet to broker. */
    TEST_ASSERT_EQUAL( MQTTSuccess, MQTT_Connect( pContext,
                                                  &connectInfo,
                                                  &lwtInfo,
                                                  CONNACK_RECV_TIMEOUT_MS,
                                                  pSessionPresent ) );
}

/*-----------------------------------------------------------*/

static void eventCallback( MQTTContext_t * pContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo )
{
    MQTTPublishInfo_t * pPublishInfo = NULL;

    assert( pContext != NULL );
    assert( pPacketInfo != NULL );
    assert( pDeserializedInfo != NULL );

    /* Suppress unused parameter warning when asserts are disabled in build. */
    ( void ) pContext;

    TEST_ASSERT_EQUAL( MQTTSuccess, pDeserializedInfo->deserializationResult );
    pPublishInfo = pDeserializedInfo->pPublishInfo;

    if( ( pPacketInfo->type == packetTypeForDisconnection ) ||
        ( ( pPacketInfo->type & 0xF0U ) == packetTypeForDisconnection ) )
    {
        /* Terminate TLS session and TCP connection to test session restoration
         * across network connection. */
        ( *testParam.pNetworkDisconnect )( testParam.pNetworkContext );
    }
    else
    {
        /* Handle incoming publish. The lower 4 bits of the publish packet
         * type is used for the dup, QoS, and retain flags. Hence masking
         * out the lower bits to check if the packet is publish. */
        if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
        {
            assert( pPublishInfo != NULL );
            /* Handle incoming publish. */

            /* Cache information about the incoming PUBLISH message to process
             * in test case. */
            memcpy( &incomingInfo, pPublishInfo, sizeof( MQTTPublishInfo_t ) );
            incomingInfo.pTopicName = NULL;
            incomingInfo.pPayload = NULL;
            /* Allocate buffers and copy information of topic name and payload. */
            incomingInfo.pTopicName = malloc( pPublishInfo->topicNameLength );
            TEST_ASSERT_NOT_NULL( incomingInfo.pTopicName );
            memcpy( ( void * ) incomingInfo.pTopicName, pPublishInfo->pTopicName, pPublishInfo->topicNameLength );
            incomingInfo.pPayload = malloc( pPublishInfo->payloadLength );
            TEST_ASSERT_NOT_NULL( incomingInfo.pPayload );
            memcpy( ( void * ) incomingInfo.pPayload, pPublishInfo->pPayload, pPublishInfo->payloadLength );

            /* Update the global variable if the incoming PUBLISH packet
             * represents a retained message. */
            receivedRetainedMessage = pPublishInfo->retain;
        }
        else
        {
            handleAckEvents( pPacketInfo, pDeserializedInfo->packetIdentifier );
        }
    }
}

/*-----------------------------------------------------------*/

static int32_t failedRecv( NetworkContext_t * pNetworkContext,
                           void * pBuffer,
                           size_t bytesToRecv )
{
    ( void ) pBuffer;
    ( void ) bytesToRecv;

    /* Terminate the TLS+TCP connection with the broker for the test. */
    ( void ) ( *testParam.pNetworkDisconnect )( pNetworkContext );

    return -1;
}

/*-----------------------------------------------------------*/

static void startPersistentSession()
{
    /* Terminate TLS session and TCP network connection to discard the current MQTT session
     * that was created as a "clean session". */
    ( void ) ( *testParam.pNetworkDisconnect )( testParam.pNetworkContext );

    /* Establish a new MQTT connection over TLS with the broker with the "clean session" flag set to 0
     * to start a persistent session with the broker. */

    /* Create the TLS+TCP connection with the broker. */
    TEST_ASSERT_EQUAL( NETWORK_CONNECT_SUCCESS, ( *testParam.pNetworkConnect )( testParam.pNetworkContext,
                                                                                &testHostInfo,
                                                                                testParam.pNetworkCredentials ) );

    /* Establish a new MQTT connection for a persistent session with the broker. */
    establishMqttSession( &context, testParam.pNetworkContext, false, &persistentSession );
    TEST_ASSERT_FALSE( persistentSession );
}

/*-----------------------------------------------------------*/

static void resumePersistentSession()
{
    /* Create a new TLS+TCP network connection with the server. */
    TEST_ASSERT_EQUAL( NETWORK_CONNECT_SUCCESS, ( *testParam.pNetworkConnect )( testParam.pNetworkContext,
                                                                                &testHostInfo,
                                                                                testParam.pNetworkCredentials ) );

    /* Re-establish the persistent session with the broker by connecting with "clean session" flag set to 0. */
    TEST_ASSERT_FALSE( persistentSession );
    establishMqttSession( &context, testParam.pNetworkContext, false, &persistentSession );

    /* Verify that the session was resumed. */
    TEST_ASSERT_TRUE( persistentSession );
}

/*-----------------------------------------------------------*/

static void handleAckEvents( MQTTPacketInfo_t * pPacketInfo,
                             uint16_t packetIdentifier )
{
    /* Handle other packets. */
    switch( pPacketInfo->type )
    {
        case MQTT_PACKET_TYPE_SUBACK:
            /* Set the flag to represent reception of SUBACK. */
            receivedSubAck = true;

            LogDebug( ( "Received SUBACK: PacketID=%u",
                        packetIdentifier ) );
            /* Make sure ACK packet identifier matches with Request packet identifier. */
            TEST_ASSERT_EQUAL( globalSubscribePacketIdentifier, packetIdentifier );
            break;

        case MQTT_PACKET_TYPE_PINGRESP:

            /* Nothing to be done from application as library handles
             * PINGRESP. */
            LogDebug( ( "Received PINGRESP" ) );
            break;

        case MQTT_PACKET_TYPE_UNSUBACK:
            /* Set the flag to represent reception of UNSUBACK. */
            receivedUnsubAck = true;

            LogDebug( ( "Received UNSUBACK: PacketID=%u",
                        packetIdentifier ) );
            /* Make sure ACK packet identifier matches with Request packet identifier. */
            TEST_ASSERT_EQUAL( globalUnsubscribePacketIdentifier, packetIdentifier );
            break;

        case MQTT_PACKET_TYPE_PUBACK:
            /* Set the flag to represent reception of PUBACK. */
            receivedPubAck = true;

            /* Make sure ACK packet identifier matches with Request packet identifier. */
            TEST_ASSERT_EQUAL( globalPublishPacketIdentifier, packetIdentifier );

            LogDebug( ( "Received PUBACK: PacketID=%u",
                        packetIdentifier ) );
            break;

        case MQTT_PACKET_TYPE_PUBREC:
            /* Set the flag to represent reception of PUBREC. */
            receivedPubRec = true;

            /* Make sure ACK packet identifier matches with Request packet identifier. */
            TEST_ASSERT_EQUAL( globalPublishPacketIdentifier, packetIdentifier );

            LogDebug( ( "Received PUBREC: PacketID=%u",
                        packetIdentifier ) );
            break;

        case MQTT_PACKET_TYPE_PUBREL:
            /* Set the flag to represent reception of PUBREL. */
            receivedPubRel = true;

            /* Nothing to be done from application as library handles
             * PUBREL. */
            LogDebug( ( "Received PUBREL: PacketID=%u",
                        packetIdentifier ) );
            break;

        case MQTT_PACKET_TYPE_PUBCOMP:
            /* Set the flag to represent reception of PUBACK. */
            receivedPubComp = true;

            /* Make sure ACK packet identifier matches with Request packet identifier. */
            TEST_ASSERT_EQUAL( globalPublishPacketIdentifier, packetIdentifier );

            /* Nothing to be done from application as library handles
             * PUBCOMP. */
            LogDebug( ( "Received PUBCOMP: PacketID=%u",
                        packetIdentifier ) );
            break;

        /* Any other packet type is invalid. */
        default:
            LogError( ( "Unknown packet type received:(%02x).",
                        pPacketInfo->type ) );
    }
}

/*-----------------------------------------------------------*/

static MQTTStatus_t subscribeToTopic( MQTTContext_t * pContext,
                                      const char * pTopic,
                                      MQTTQoS_t qos )
{
    MQTTSubscribeInfo_t pSubscriptionList[ 1 ];

    assert( pContext != NULL );

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pSubscriptionList, 0x00, sizeof( pSubscriptionList ) );

    pSubscriptionList[ 0 ].qos = qos;
    pSubscriptionList[ 0 ].pTopicFilter = pTopic;
    pSubscriptionList[ 0 ].topicFilterLength = strlen( pTopic );

    /* Generate packet identifier for the SUBSCRIBE packet. */
    globalSubscribePacketIdentifier = MQTT_GetPacketId( pContext );

    /* Send SUBSCRIBE packet. */
    return MQTT_Subscribe( pContext,
                           pSubscriptionList,
                           sizeof( pSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                           globalSubscribePacketIdentifier );
}

/*-----------------------------------------------------------*/

static MQTTStatus_t unsubscribeFromTopic( MQTTContext_t * pContext,
                                          const char * pTopic,
                                          MQTTQoS_t qos )
{
    MQTTSubscribeInfo_t pSubscriptionList[ 1 ];

    assert( pContext != NULL );

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pSubscriptionList, 0x00, sizeof( pSubscriptionList ) );

    pSubscriptionList[ 0 ].qos = qos;
    pSubscriptionList[ 0 ].pTopicFilter = pTopic;
    pSubscriptionList[ 0 ].topicFilterLength = strlen( pTopic );

    /* Generate packet identifier for the UNSUBSCRIBE packet. */
    globalUnsubscribePacketIdentifier = MQTT_GetPacketId( pContext );

    /* Send UNSUBSCRIBE packet. */
    return MQTT_Unsubscribe( pContext,
                             pSubscriptionList,
                             sizeof( pSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                             globalUnsubscribePacketIdentifier );
}

/*-----------------------------------------------------------*/

static MQTTStatus_t publishToTopic( MQTTContext_t * pContext,
                                    const char * pTopic,
                                    bool setRetainFlag,
                                    bool isDuplicate,
                                    MQTTQoS_t qos,
                                    uint16_t packetId )
{
    assert( pContext != NULL );
    MQTTPublishInfo_t publishInfo;

    publishInfo.retain = setRetainFlag;

    publishInfo.qos = qos;
    publishInfo.dup = isDuplicate;
    publishInfo.pTopicName = pTopic;
    publishInfo.topicNameLength = strlen( pTopic );
    publishInfo.pPayload = MQTT_EXAMPLE_MESSAGE;
    publishInfo.payloadLength = strlen( MQTT_EXAMPLE_MESSAGE );

    /* Get a new packet id. */
    globalPublishPacketIdentifier = packetId;

    /* Send PUBLISH packet. */
    return MQTT_Publish( pContext,
                         &publishInfo,
                         packetId );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test setup function for MQTT tests.
 */
TEST_SETUP( MqttTest )
{
    /* Reset file-scoped global variables. */
    receivedSubAck = false;
    receivedUnsubAck = false;
    receivedPubAck = false;
    receivedPubRec = false;
    receivedPubRel = false;
    receivedPubComp = false;
    receivedRetainedMessage = false;
    persistentSession = false;
    useLWTClientIdentifier = false;
    packetTypeForDisconnection = MQTT_PACKET_TYPE_INVALID;
    memset( &incomingInfo, 0u, sizeof( MQTTPublishInfo_t ) );

    /* Generate a random number to use in the client identifier. */
    clientIdRandNumber = ( FRTest_GenerateRandInt() % ( MAX_RAND_NUMBER_FOR_CLIENT_ID + 1u ) );

    /* Establish a TCP connection with the server endpoint, then
     * establish TLS session on top of TCP connection. */
    TEST_ASSERT_EQUAL( NETWORK_CONNECT_SUCCESS, ( *testParam.pNetworkConnect )( testParam.pNetworkContext,
                                                                                &testHostInfo,
                                                                                testParam.pNetworkCredentials ) );

    /* Establish MQTT session on top of the TCP+TLS connection. */
    establishMqttSession( &context, testParam.pNetworkContext, true, &persistentSession );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test tear down function for MQTT tests.
 */
TEST_TEAR_DOWN( MqttTest )
{
    MQTTStatus_t mqttStatus;

    /* Free memory, if allocated during test case execution. */
    if( incomingInfo.pTopicName != NULL )
    {
        free( ( void * ) incomingInfo.pTopicName );
    }

    if( incomingInfo.pPayload != NULL )
    {
        free( ( void * ) incomingInfo.pPayload );
    }

    /* Terminate MQTT connection. */
    mqttStatus = MQTT_Disconnect( &context );

    ( *testParam.pNetworkDisconnect )( testParam.pNetworkContext );

    /* Make any assertions at the end so that all memory is deallocated before
     * the end of this function. */
    TEST_ASSERT_EQUAL( MQTTSuccess, mqttStatus );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests Subscribe and Publish operations with the MQTT broken using QoS 0.
 * The test subscribes to a topic, and then publishes to the same topic. The
 * broker is expected to route the publish message back to the test.
 */
TEST( MqttTest, MQTT_Subscribe_Publish_With_Qos_0 )
{
    MQTTStatus_t xMQTTStatus;
    uint32_t entryTime;

    /* Subscribe to a topic with Qos 0. */
    TEST_ASSERT_EQUAL( MQTTSuccess, subscribeToTopic(
                           &context, TEST_MQTT_TOPIC, MQTTQoS0 ) );

    /* Assert that this flag is not set before MQTT_ProcessLoop is called.
     * It will be set when a SUBACK is received. */
    TEST_ASSERT_FALSE( receivedSubAck );

    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
            
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    TEST_ASSERT_TRUE( receivedSubAck );

    /* Publish to the same topic, that we subscribed to, with Qos 0. */
    TEST_ASSERT_EQUAL( MQTTSuccess, publishToTopic(
                           &context,
                           TEST_MQTT_TOPIC,
                           false, /* setRetainFlag */
                           false, /* isDuplicate */
                           MQTTQoS0,
                           MQTT_GetPacketId( &context ) ) );

    /* Call the MQTT library for the expectation to read an incoming PUBLISH for
     * the same message that we published (as we have subscribed to the same topic). */
    TEST_ASSERT_FALSE( receivedPubAck );
    
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
            
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    /* We do not expect a PUBACK from the broker for the QoS 0 PUBLISH. */
    TEST_ASSERT_FALSE( receivedPubAck );

    /* Make sure that we have received the same message from the server,
     * that was published (as we have subscribed to the same topic). */
    TEST_ASSERT_EQUAL( MQTTQoS0, incomingInfo.qos );
    TEST_ASSERT_EQUAL( TEST_MQTT_TOPIC_LENGTH, incomingInfo.topicNameLength );
    TEST_ASSERT_EQUAL_MEMORY( TEST_MQTT_TOPIC,
                              incomingInfo.pTopicName,
                              TEST_MQTT_TOPIC_LENGTH );
    TEST_ASSERT_EQUAL( strlen( MQTT_EXAMPLE_MESSAGE ), incomingInfo.payloadLength );
    TEST_ASSERT_EQUAL_MEMORY( MQTT_EXAMPLE_MESSAGE,
                              incomingInfo.pPayload,
                              incomingInfo.payloadLength );

    /* Un-subscribe from a topic with Qos 0. */
    TEST_ASSERT_EQUAL( MQTTSuccess, unsubscribeFromTopic(
                           &context, TEST_MQTT_TOPIC, MQTTQoS0 ) );

    /* We expect an UNSUBACK from the broker for the unsubscribe operation. */
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
            
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    TEST_ASSERT_TRUE( receivedUnsubAck );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests Subscribe and Publish operations with the MQTT broken using QoS 1.
 * The test subscribes to a topic, and then publishes to the same topic. The
 * broker is expected to route the publish message back to the test.
 */
TEST( MqttTest, MQTT_Subscribe_Publish_With_Qos_1 )
{
    MQTTStatus_t xMQTTStatus;
    uint32_t entryTime;

    /* Subscribe to a topic with Qos 1. */
    TEST_ASSERT_EQUAL( MQTTSuccess, subscribeToTopic(
                           &context, TEST_MQTT_TOPIC, MQTTQoS1 ) );

    /* Assert that this flag is not set before MQTT_ProcessLoop is called or
     * else the test will return a flase positive. This flag should be set when
     * a SUBACK is received. */
    TEST_ASSERT_FALSE( receivedSubAck );

    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedSubAck != 0 )
        {
            /* Received the SUBACK. No need to call process loop anymore. */
            break;
        }
        else
        {
            /* Nothing to do. */
        }
    } while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    TEST_ASSERT_TRUE( receivedSubAck );

    /* Publish to the same topic, that we subscribed to, with Qos 1. */
    TEST_ASSERT_EQUAL( MQTTSuccess, publishToTopic(
                           &context,
                           TEST_MQTT_TOPIC,
                           false, /* setRetainFlag */
                           false, /* isDuplicate */
                           MQTTQoS1,
                           MQTT_GetPacketId( &context ) ) );

    /* Make sure that the MQTT context state was updated after the PUBLISH request. */
    TEST_ASSERT_EQUAL( MQTTQoS1, context.outgoingPublishRecords[ 0 ].qos );
    TEST_ASSERT_EQUAL( globalPublishPacketIdentifier, context.outgoingPublishRecords[ 0 ].packetId );
    TEST_ASSERT_EQUAL( MQTTPubAckPending, context.outgoingPublishRecords[ 0 ].publishState );

    /* Expect a PUBACK response for the PUBLISH and an incoming PUBLISH for the
     * same message that we published (as we have subscribed to the same topic). */
    TEST_ASSERT_FALSE( receivedPubAck );
    
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
        else if( ( receivedPubAck != 0 ) && ( incomingInfo.topicNameLength > 0 ) && ( strncmp( TEST_MQTT_TOPIC, incomingInfo.pTopicName, TEST_MQTT_TOPIC_LENGTH ) == 0 ) )
        {
            /* Both the PUBACK and the incoming publish have been received. */
            /* "incomingInfo.topicNameLength > 0" means we got a publish message from MQTT broker.
             * We compare message's content/length after breaking loop. */
            break;
        }
        else
        {
            /* Nothing to do. */
        }
    } while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    /* Make sure we have received PUBACK response. */
    TEST_ASSERT_TRUE( receivedPubAck );

    /* Make sure that we have received the same message from the server,
     * that was published (as we have subscribed to the same topic). */
    TEST_ASSERT_EQUAL( MQTTQoS1, incomingInfo.qos );
    TEST_ASSERT_EQUAL( TEST_MQTT_TOPIC_LENGTH, incomingInfo.topicNameLength );
    TEST_ASSERT_EQUAL_MEMORY( TEST_MQTT_TOPIC,
                              incomingInfo.pTopicName,
                              TEST_MQTT_TOPIC_LENGTH );
    TEST_ASSERT_EQUAL( strlen( MQTT_EXAMPLE_MESSAGE ), incomingInfo.payloadLength );
    TEST_ASSERT_EQUAL_MEMORY( MQTT_EXAMPLE_MESSAGE,
                              incomingInfo.pPayload,
                              incomingInfo.payloadLength );

    /* Un-subscribe from a topic with Qos 1. */
    TEST_ASSERT_EQUAL( MQTTSuccess, unsubscribeFromTopic(
                           &context, TEST_MQTT_TOPIC, MQTTQoS1 ) );

    /* Expect an UNSUBACK from the broker for the unsubscribe operation. */
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedUnsubAck != 0 )
        {
            /* Received the SUBACK. No need to call process loop anymore. */
            break;
        }
        else
        {
            /* Nothing to do. */
        }
            
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    TEST_ASSERT_TRUE( receivedUnsubAck );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests Subscribe and Publish operations with the MQTT broken using QoS 1.
 * The test subscribes to a topic, and then publishes to the same topic. The
 * broker is expected to route the publish message back to the test.
 */
TEST( MqttTest, MQTT_Connect_LWT )
{
    bool sessionPresent;
    MQTTContext_t secondMqttContext;
    MQTTStatus_t xMQTTStatus;
    uint32_t entryTime;

    /* Establish a second TCP connection with the server endpoint, then
     * a TLS session. The server info and credentials can be reused. */
    TEST_ASSERT_EQUAL( NETWORK_CONNECT_SUCCESS, ( *testParam.pNetworkConnect )( testParam.pSecondNetworkContext,
                                                                                &testHostInfo,
                                                                                testParam.pNetworkCredentials ) );

    /* Establish MQTT session on top of the TCP+TLS connection. */
    useLWTClientIdentifier = true;
    establishMqttSession( &secondMqttContext, testParam.pSecondNetworkContext, true, &sessionPresent );

    /* Subscribe to LWT Topic. */
    TEST_ASSERT_EQUAL( MQTTSuccess, subscribeToTopic(
                           &context, TEST_MQTT_LWT_TOPIC, MQTTQoS0 ) );

    /* Wait for the SUBACK response from the broker for the subscribe request. */
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedSubAck != 0 )
        {
            /* No need to wait any longer as we have received the subscribe
             * acknowledgement. */
            break;
        }
        else
        {
            /* Do nothing. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    TEST_ASSERT_TRUE( receivedSubAck );

    /* Abruptly terminate TCP connection. */
    ( void ) ( *testParam.pNetworkDisconnect )( testParam.pSecondNetworkContext );

    /* Run the process loop to receive the LWT. Allow some more time for the
     * server to realize the connection is closed. */
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + ( MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS * 2 ) ) )
        {
            /* Timeout. */
            break;
        }
        else if( ( incomingInfo.topicNameLength > 0 ) && ( strncmp( TEST_MQTT_LWT_TOPIC, incomingInfo.pTopicName, TEST_MQTT_LWT_TOPIC_LENGTH ) == 0 ) )
        {
            /* Some data was received on the LWT topic. */
            /* "incomingInfo.topicNameLength > 0" means we got a publish message from MQTT broker.
             * We compare message's content/length after breaking loop. */
            break;
        }
        else
        {
            /* Do nothing. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    /* Test if we have received the LWT. */
    TEST_ASSERT_EQUAL( MQTTQoS0, incomingInfo.qos );
    TEST_ASSERT_EQUAL( TEST_MQTT_LWT_TOPIC_LENGTH, incomingInfo.topicNameLength );
    TEST_ASSERT_EQUAL_MEMORY( TEST_MQTT_LWT_TOPIC,
                              incomingInfo.pTopicName,
                              TEST_MQTT_LWT_TOPIC_LENGTH );
    TEST_ASSERT_EQUAL( strlen( MQTT_EXAMPLE_MESSAGE ), incomingInfo.payloadLength );
    TEST_ASSERT_EQUAL_MEMORY( MQTT_EXAMPLE_MESSAGE,
                              incomingInfo.pPayload,
                              incomingInfo.payloadLength );

    /* Un-subscribe from a topic with Qos 0. */
    TEST_ASSERT_EQUAL( MQTTSuccess, unsubscribeFromTopic(
                           &context, TEST_MQTT_TOPIC, MQTTQoS0 ) );

    /* We expect an UNSUBACK from the broker for the unsubscribe operation. */
    TEST_ASSERT_FALSE( receivedUnsubAck );
    
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedUnsubAck != 0 )
        {
            /* No need to call processloop anymore as unsub ACK has been received. */
            break;
        }
        else
        {
            /* Do nothing. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    TEST_ASSERT_TRUE( receivedUnsubAck );
}

/*-----------------------------------------------------------*/

/**
 * @brief Verifies that the MQTT library sends a Ping Request packet if the connection is
 * idle for more than the keep-alive period.
 */
TEST( MqttTest, MQTT_ProcessLoop_KeepAlive )
{
    uint32_t connectPacketTime = context.lastPacketTxTime;
    uint32_t elapsedTime = 0;
    MQTTStatus_t xMQTTStatus;
    uint32_t entryTime;

    TEST_ASSERT_EQUAL( 0, context.pingReqSendTimeMs );

    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        /* Check whether it has been more than twice the keep alive timeout. */
        if( FRTest_GetTimeMs() > ( entryTime + ( MQTT_KEEP_ALIVE_INTERVAL_SECONDS * 2000 ) ) )
        {
            /* Timeout after waiting for twice the keep alive interval. */
            break;
        }
        else if( context.pingReqSendTimeMs != 0 )
        {
            /* Ping is sent! */
            break;
        }
        else
        {
            /* Nothing to be done for now. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_NOT_EQUAL( 0, context.pingReqSendTimeMs );
    TEST_ASSERT_NOT_EQUAL( connectPacketTime, context.lastPacketTxTime);
    /* Test that the ping was sent within 1.5 times the keep alive interval. */
    elapsedTime = context.lastPacketTxTime - connectPacketTime;
    TEST_ASSERT_LESS_OR_EQUAL( MQTT_KEEP_ALIVE_INTERVAL_SECONDS * 1500, elapsedTime );
}

/*-----------------------------------------------------------*/

/**
 * @brief Verifies that the MQTT library supports resending a PUBLISH QoS 1 packet which is
 * un-acknowledged in its first attempt.
 * Tests that the library is able to support resending the PUBLISH packet with the DUP flag.
 */
TEST( MqttTest, MQTT_Resend_Unacked_Publish_QoS1 )
{
    MQTTStatus_t xMQTTStatus;
    uint32_t entryTime;

    /* Start a persistent session with the broker. */
    startPersistentSession();

    /* Initiate the PUBLISH operation at QoS 1. The library should add an
     * outgoing PUBLISH record in the context. */
    TEST_ASSERT_EQUAL( MQTTSuccess, publishToTopic(
                           &context,
                           TEST_MQTT_TOPIC,
                           false, /* setRetainFlag */
                           false, /* isDuplicate */
                           MQTTQoS1,
                           MQTT_GetPacketId( &context ) ) );

    /* Setup the MQTT connection to terminate to simulate incomplete PUBLISH operation. */
    context.transportInterface.recv = failedRecv;

    /* Attempt to complete the PUBLISH operation at QoS1 which should fail due
     * to terminated network connection.
     * The abrupt network disconnection should cause the PUBLISH packet to be left
     * in an un-acknowledged state in the MQTT context. */
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + ( MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS * 2 ) ) )
        {
            /* Timeout. */
            break;
        }
            
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_EQUAL( MQTTRecvFailed, xMQTTStatus );

    /* Verify that the library has stored the PUBLISH as an incomplete operation. */
    TEST_ASSERT_NOT_EQUAL( MQTT_PACKET_ID_INVALID, context.outgoingPublishRecords[ 0 ].packetId );

    /* Reset the transport receive function in the context. */
    context.transportInterface.recv = testParam.pTransport->recv;

    /* We will re-establish an MQTT over TLS connection with the broker to restore
     * the persistent session. */
    resumePersistentSession();

    /* Obtain the packet ID of the PUBLISH packet that didn't complete in the previous connection. */
    MQTTStateCursor_t cursor = MQTT_STATE_CURSOR_INITIALIZER;
    uint16_t publishPackedId = MQTT_PublishToResend( &context, &cursor );

    TEST_ASSERT_NOT_EQUAL( MQTT_PACKET_ID_INVALID, publishPackedId );

    /* Make sure that the packet ID is maintained in the outgoing publish state records. */
    TEST_ASSERT_EQUAL( context.outgoingPublishRecords[ 0 ].packetId, publishPackedId );

    /* Resend the PUBLISH packet that didn't complete in the previous connection. */
    TEST_ASSERT_EQUAL( MQTTSuccess, publishToTopic(
                           &context,
                           TEST_MQTT_TOPIC,
                           false, /* setRetainFlag */
                           true,  /* isDuplicate */
                           MQTTQoS1,
                           publishPackedId ) );

    /* Complete the QoS 1 PUBLISH resend operation. */
    TEST_ASSERT_FALSE( receivedPubAck );
    
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + ( MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS * 2 ) ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedPubAck != 0 )
        {
            /* Received the PUBACK, no need to wait anymore. */
            break;
        }
        else
        {
            /* Nothing to be done for now. */
        }
            
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    /* Make sure that the PUBLISH resend was complete. */
    TEST_ASSERT_TRUE( receivedPubAck );

    /* Make sure that the library has removed the record for the outgoing PUBLISH packet. */
    TEST_ASSERT_EQUAL( MQTT_PACKET_ID_INVALID, context.outgoingPublishRecords[ 0 ].packetId );
}

/*-----------------------------------------------------------*/

/**
 * @brief Verifies the behavior of the MQTT library on receiving a duplicate
 * QoS 1 PUBLISH packet from the broker in a restored session connection.
 * Tests that the library responds with a PUBACK to the duplicate incoming QoS 1 PUBLISH
 * packet that was un-acknowledged in a previous connection of the same session.
 */
TEST( MqttTest, MQTT_Restore_Session_Duplicate_Incoming_Publish_Qos1 )
{
    MQTTStatus_t xMQTTStatus;
    uint32_t entryTime;

    /* Start a persistent session with the broker. */
    startPersistentSession();

    /* Subscribe to a topic from which we will be receiving an incomplete incoming
     * QoS 2 PUBLISH transaction in this connection. */
    TEST_ASSERT_EQUAL( MQTTSuccess, subscribeToTopic(
                           &context, TEST_MQTT_TOPIC, MQTTQoS1 ) );
    TEST_ASSERT_FALSE( receivedSubAck );
    
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedSubAck != 0 )
        {
            /* No need to call process loop anymore, we have received a sub ack. */
            break;
        }
        else
        {
            /* Do nothing. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( receivedSubAck );

    /* Publish to the same topic with Qos 1 (so that the broker can re-publish it back to us). */
    TEST_ASSERT_EQUAL( MQTTSuccess, publishToTopic(
                           &context,
                           TEST_MQTT_TOPIC,
                           false, /* setRetainFlag */
                           false, /* isDuplicate */
                           MQTTQoS1,
                           MQTT_GetPacketId( &context ) ) );

    /* Disconnect on receiving the incoming PUBLISH packet from the broker so that
     * an acknowledgement cannot be sent to the broker. */
    packetTypeForDisconnection = MQTT_PACKET_TYPE_PUBLISH;
    
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + ( MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS * 2 ) ) )
        {
            /* Timeout. */
            break;
        }
            
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_EQUAL( MQTTSendFailed, xMQTTStatus );

    /* Make sure that a record was created for the incoming PUBLISH packet. */
    TEST_ASSERT_NOT_EQUAL( MQTT_PACKET_ID_INVALID, context.incomingPublishRecords[ 0 ].packetId );

    FRTest_TimeDelay( 30000 );

    /* We will re-establish an MQTT over TLS connection with the broker to restore
     * the persistent session. */
    resumePersistentSession();

    /* Clear the global variable for not disconnecting on the duplicate PUBLISH
     * packet that we receive from the broker on the session restoration. */
    packetTypeForDisconnection = MQTT_PACKET_TYPE_INVALID;

    /* Process the duplicate incoming QoS 1 PUBLISH that will be sent by the broker
     * to re-attempt the PUBLISH operation. */
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + ( MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS * 2 ) ) )
        {
            /* Timeout. */
            break;
        }
            
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    /* Make sure that the library cleared the record for the incoming QoS 1 PUBLISH packet. */
    TEST_ASSERT_EQUAL( MQTT_PACKET_ID_INVALID, context.incomingPublishRecords[ 0 ].packetId );
}

/*-----------------------------------------------------------*/

/**
 * @brief Verifies that the library supports notifying the broker to retain a PUBLISH message
 * for a topic using the retain flag.
 */
TEST( MqttTest, MQTT_Publish_With_Retain_Flag )
{
    MQTTStatus_t xMQTTStatus;
    uint32_t entryTime;

    /* Publish to a topic with the "retain" flag set. */
    TEST_ASSERT_EQUAL( MQTTSuccess, publishToTopic( &context,
                                                    TEST_MQTT_RETAIN_TOPIC,
                                                    true,  /* setRetainFlag */
                                                    false, /* isDuplicate */
                                                    MQTTQoS1,
                                                    MQTT_GetPacketId( &context ) ) );
    /* Complete the QoS 1 PUBLISH operation. */
    TEST_ASSERT_FALSE( receivedPubAck );

    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + ( MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS * 2 ) ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedPubAck != 0 )
        {
            /* No need to loop anymore since we received the PUBACK. */
            break;
        }
        else
        {
            /* Do nothing. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( receivedPubAck );

    /* Subscribe to the same topic that we published the message to.
     * The broker should send the "retained" message with the "retain" flag set. */
    TEST_ASSERT_EQUAL( MQTTSuccess, subscribeToTopic(
                           &context, TEST_MQTT_RETAIN_TOPIC, MQTTQoS1 ) );
    TEST_ASSERT_FALSE( receivedSubAck );

    TEST_ASSERT_FALSE( receivedRetainedMessage );

    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + ( MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS * 2 ) ) )
        {
            /* Timeout. */
            break;
        }
        else if( ( receivedSubAck != 0 ) && ( receivedRetainedMessage != 0 ) )
        {
            /* No need to loop anymore since we received both the messages we were supposed to. */
            break;
        }
        else
        {
            /* Do nothing. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( receivedSubAck );

    /* Make sure that the library invoked the event callback with the incoming PUBLISH from
     * the broker containing the "retained" flag set. */
    TEST_ASSERT_TRUE( receivedRetainedMessage );

    /* Reset the global variables for the remainder of the test. */
    receivedPubAck = false;
    receivedSubAck = false;
    receivedUnsubAck = false;
    receivedRetainedMessage = false;

    /* Publish to another topic with the "retain" flag set to 0. */
    TEST_ASSERT_EQUAL( MQTTSuccess, publishToTopic( &context,
                                                    TEST_MQTT_TOPIC,
                                                    false, /* setRetainFlag */
                                                    false, /* isDuplicate */
                                                    MQTTQoS1,
                                                    MQTT_GetPacketId( &context ) ) );

    /* Complete the QoS 1 PUBLISH operation. */
    TEST_ASSERT_FALSE( receivedPubAck );
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + ( MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS * 2 ) ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedPubAck != 0 )
        {
            /* No need to loop anymore since we received the PUBACK. */
            break;
        }
        else
        {
            /* Do nothing. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    TEST_ASSERT_TRUE( receivedPubAck );

    /* Again, subscribe to the same topic that we just published to.
     * We don't expect the broker to send the message to us (as we
     * PUBLISHed without a retain flag set). */
    TEST_ASSERT_EQUAL( MQTTSuccess, subscribeToTopic(
                           &context, TEST_MQTT_TOPIC, MQTTQoS1 ) );
    TEST_ASSERT_FALSE( receivedSubAck );

    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + ( MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS * 2 ) ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedSubAck != 0 )
        {
            /* No need to loop anymore since we received the SUBACK. */
            break;
        }
        else
        {
            /* Do nothing. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    TEST_ASSERT_TRUE( receivedSubAck );

    /* Make sure that the library did not receive an incoming PUBLISH from the broker. */
    TEST_ASSERT_FALSE( receivedRetainedMessage );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests Subscribe and Unsubscribe operations to multiple topic filters
 * in a single API call.
 * The test subscribes to 5 topics, and then publishes to the same topics one
 * at a time. The broker is expected to route the publish message back to the
 * test for all topics.
 * The test then unsubscribes from the 5 topics which should also succeed.
 */
TEST( MqttTest, MQTT_SubUnsub_Multiple_Topics )

{
    MQTTSubscribeInfo_t subscribeParams[ 5 ];
    char * topicList[ 5 ];
    size_t i;
    const size_t topicCount = 5U;
    MQTTQoS_t qos;
    MQTTStatus_t xMQTTStatus;
    uint32_t entryTime;

    topicList[ 0 ] = TEST_MQTT_TOPIC;
    topicList[ 1 ] = TEST_MQTT_TOPIC_2;
    topicList[ 2 ] = TEST_MQTT_TOPIC_3;
    topicList[ 3 ] = TEST_MQTT_TOPIC_4;
    topicList[ 4 ] = TEST_MQTT_TOPIC_5;

    for( i = 0; i < topicCount; i++ )
    {
        subscribeParams[ i ].pTopicFilter = topicList[ i ];
        subscribeParams[ i ].topicFilterLength = strlen( topicList[ i ] );
        subscribeParams[ i ].qos = ( i % 2 );
    }

    globalSubscribePacketIdentifier = MQTT_GetPacketId( &context );
    /* Check that the packet ID is valid according to the MQTT spec. */
    TEST_ASSERT_NOT_EQUAL( MQTT_PACKET_ID_INVALID, globalSubscribePacketIdentifier );
    TEST_ASSERT_NOT_EQUAL( 0U, globalSubscribePacketIdentifier );

    /* Subscribe to all topics. */
    TEST_ASSERT_EQUAL( MQTTSuccess, MQTT_Subscribe( &context,
                                                    subscribeParams,
                                                    topicCount,
                                                    globalSubscribePacketIdentifier ) );

    /* Expect a SUBACK from the broker for the subscribe operation. */
    TEST_ASSERT_FALSE( receivedSubAck );
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedSubAck != 0 )
        {
            /* No need to loop anymore since we received the SUBACK. */
            break;
        }
        else
        {
            /* Do nothing. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    TEST_ASSERT_TRUE( receivedSubAck );

    /* Publish to the same topic, that we subscribed to. */
    for( i = 0; i < topicCount; i++ )
    {
        /* Set Qos to be either 1 or 0. */
        qos = ( i % 2 );

        TEST_ASSERT_EQUAL( MQTTSuccess, publishToTopic(
                                            &context,
                                            topicList[ i ],
                                            false, /* setRetainFlag */
                                            false, /* isDuplicate */
                                            qos,   /* QoS */
                                            MQTT_GetPacketId( &context ) ) );

        /* Reset the PUBACK flag. */
        receivedPubAck = false;

        entryTime = FRTest_GetTimeMs();
        do
        {
            xMQTTStatus = MQTT_ProcessLoop( &context );

            if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
            {
                /* Timeout. */
                break;
            }
            else
            {
                /* Do nothing. */
            }
        }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

		TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

        /* Only wait for PUBACK if QoS is not QoS0. */
        if( qos != MQTTQoS0 )
        {
            /* Make sure we have received PUBACK response. */
            TEST_ASSERT_TRUE( receivedPubAck );
        }

        /* Make sure that we have received the same message from the server,
         * that was published (as we have subscribed to the same topic). */
        TEST_ASSERT_EQUAL( qos, incomingInfo.qos );
        TEST_ASSERT_EQUAL( strlen( topicList[ i ] ), incomingInfo.topicNameLength );
        TEST_ASSERT_EQUAL_MEMORY( topicList[ i ],
                                  incomingInfo.pTopicName,
                                  strlen( topicList[ i ] ) );
        TEST_ASSERT_EQUAL( strlen( MQTT_EXAMPLE_MESSAGE ), incomingInfo.payloadLength );
        TEST_ASSERT_EQUAL_MEMORY( MQTT_EXAMPLE_MESSAGE,
                                  incomingInfo.pPayload,
                                  incomingInfo.payloadLength );
    }

    globalUnsubscribePacketIdentifier = MQTT_GetPacketId( &context );
    /* Check that the packet ID is valid according to the MQTT spec. */
    TEST_ASSERT_NOT_EQUAL( MQTT_PACKET_ID_INVALID, globalUnsubscribePacketIdentifier );
    TEST_ASSERT_NOT_EQUAL( 0U, globalUnsubscribePacketIdentifier );

    /* Un-subscribe from all the topics. */
    TEST_ASSERT_EQUAL( MQTTSuccess, MQTT_Unsubscribe(
                           &context, subscribeParams, topicCount, globalUnsubscribePacketIdentifier ) );

    receivedUnsubAck = false;

    /* Expect an UNSUBACK from the broker for the unsubscribe operation. */
    entryTime = FRTest_GetTimeMs();
    do
    {
        xMQTTStatus = MQTT_ProcessLoop( &context );

        if( FRTest_GetTimeMs() > ( entryTime + MQTT_TEST_PROCESS_LOOP_TIMEOUT_MS ) )
        {
            /* Timeout. */
            break;
        }
        else if( receivedUnsubAck != 0 )
        {
            break;
        }
        else
        {
            /* Do nothing. */
        }
    }while( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );

    TEST_ASSERT_TRUE( ( xMQTTStatus == MQTTSuccess ) || ( xMQTTStatus == MQTTNeedMoreBytes ) );
    TEST_ASSERT_TRUE( receivedUnsubAck );
}

/*-----------------------------------------------------------*/

/**
 * @brief Test group runner for MQTT test against MQTT broker.
 */
TEST_GROUP_RUNNER( MqttTest )
{
    RUN_TEST_CASE( MqttTest, MQTT_Subscribe_Publish_With_Qos_0 );
    RUN_TEST_CASE( MqttTest, MQTT_Subscribe_Publish_With_Qos_1 );
    RUN_TEST_CASE( MqttTest, MQTT_Connect_LWT );
    RUN_TEST_CASE( MqttTest, MQTT_ProcessLoop_KeepAlive );
    RUN_TEST_CASE( MqttTest, MQTT_Resend_Unacked_Publish_QoS1 );
    RUN_TEST_CASE( MqttTest, MQTT_Restore_Session_Duplicate_Incoming_Publish_Qos1 );
    RUN_TEST_CASE( MqttTest, MQTT_Publish_With_Retain_Flag );
    RUN_TEST_CASE( MqttTest, MQTT_SubUnsub_Multiple_Topics );
}

/*-----------------------------------------------------------*/

int RunMqttTest( void )
{
    int status = -1;

    /* Calls user-implemented SetupMqttTestParam to fill in testParam */
    SetupMqttTestParam( &testParam );
    testHostInfo.pHostName = MQTT_SERVER_ENDPOINT;
    testHostInfo.port = MQTT_SERVER_PORT;

    /* Initialize unity. */
    UnityFixture.Verbose = 1;
    UnityFixture.GroupFilter = 0;
    UnityFixture.NameFilter = 0;
    UnityFixture.RepeatCount = 1;

    UNITY_BEGIN();

    RUN_TEST_GROUP( MqttTest );

    status = UNITY_END();
    return status;
}

#endif /* if ( MQTT_TEST_ENABLED == 1 ) */
