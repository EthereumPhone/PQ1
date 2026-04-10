/*
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

/*
 * This example demonstrates a task which collects and publishes metrics periodically
 * to AWS IoT Device Defender service.
 *
 * This demo task uses coreMQTT agent task to connect to AWS IoT broker and
 * subscribes to the device defender topics. It then collects metrics for open
 * TCP/UDP ports, TCP connections and network stats from LWIP and generates a device defender report
 * in CBOR format. The report is then published, and the demo waits for a response from the device
 * defender service.
 */

/* Standard includes. */
#include <string.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"

/* Task Handle. */
#include "task.h"

/* Demo config. */
#include "demo_config.h"

/* Device Defender Client Library. */
#include "defender.h"

/* Contains definitions for all metrics collected. */
#include "defender_metrics.h"

/* Report builder API implementation using CBOR. */
#include "defender_report_builder.h"

/* API to collect metrics. */
#include "defender_metrics_collector.h"

/* API to fetch thingname */
#include "kvstore.h"

/* MQTT library includes. */
#include "core_mqtt_agent.h"

/* MQTT Agent task APIs. */
#include "mqtt_agent_task.h"

#if ( !defined( democonfigMETRICS_PUBLISH_INTERVAL_SECONDS ) || ( democonfigMETRICS_PUBLISH_INTERVAL_SECONDS < 300 ) )
#error "Defender metrics publish interval should be greater than or equal to 300 seconds"
#endif

/**
 * @brief The maximum length of thing name supported by AWS IoT.
 * This is used to pre-allocate the buffer for device defender topics.
 */
#define MAX_THING_NAME_LENGTH             ( 256 )

/**
 * @brief Maximum length of the topics used by the device defender service.
 */
#define DEFENDER_MAX_TOPIC_LENGTH         DEFENDER_API_MAX_LENGTH( MAX_THING_NAME_LENGTH )

/**
 * @brief Number of milliseconds to wait for the response from AWS IoT Device
 * Defender service.
 */
#define DEFENDER_RESPONSE_WAIT_MS         ( 2000U )

/**
 * @brief Number of milliseconds to wait for the response from coreMQTT agent for a command sent.
 */
#define MAX_COMMAND_SEND_BLOCK_TIME_MS    ( 200U )


#define DEFENDER_REPORT_ACCEPTED_EVENT    ( 1UL << 0 )
#define DEFENDER_REPORT_REJECTED_EVENT    ( 1UL << 1 )

/*-----------------------------------------------------------*/

/**
 * @brief Defines the structure to use as the command callback context in this
 * demo.
 */
struct MQTTAgentCommandContext
{
    TaskHandle_t xDefenderTaskHandle;
    bool xReturnStatus;
};

/*-----------------------------------------------------------*/

extern MQTTAgentContext_t xGlobalMqttAgentContext;

/**
 * @brief Open TCP ports array.
 */
static uint16_t usOpenTCPPorts[ democonfigOPEN_TCP_PORTS_ARRAY_SIZE ];

/**
 * @brief Open UDP ports array.
 */
static uint16_t usOpenUDPPorts[ democonfigOPEN_UDP_PORTS_ARRAY_SIZE ];

/**
 * @brief Established TCP connections array.
 */
static TCPConnection_t xEstablishedTCPConnections[ democonfigESTABLISHED_CONNECTIONS_ARRAY_SIZE ];

/**
 * @brief Topic used to receive report accepted notifications from device defender.
 */
static char cReportAcceptedTopic[ DEFENDER_MAX_TOPIC_LENGTH ] = { 0 };
uint16_t usReportAcceptedTopicLength = 0U;

/**
 * @brief Topic used to receive report rejected notifications from device defender.
 */
static char cReportRejectedTopic[ DEFENDER_MAX_TOPIC_LENGTH ] = { 0 };
uint16_t usReportRejectedTopicLength = 0U;

/**
 * @brief Topic used to publish a report to the device defender service.
 */
static char cReportPublishTopic[ DEFENDER_MAX_TOPIC_LENGTH ] = { 0 };
uint16_t usReportPublishTopicLength = 0U;

static char cThingName[ MAX_THING_NAME_LENGTH + 1 ] = { 0 };
size_t xThingNameLength = 0U;

/*-----------------------------------------------------------*/

/**
 * @brief The callback to execute when there is an incoming publish on the
 * topic for accepted reports. The callback sends an event to the device defender
 * task to indicate a successful acceptance of the report.
 *
 * @param[in] pxSubscriptionContext Context of the initial command.
 * @param[in] pxPublishInfo Deserialized publish.
 */
static void prvReportAcceptedCallback( void * pxSubscriptionContext,
                                       MQTTPublishInfo_t * pxPublishInfo );


/**
 * @brief The callback to execute when there is an incoming publish on the
 * topic for rejected report. The callback sends an event to the device defender
 * task to indicate a rejection of the report.
 *
 * @param[in] pxSubscriptionContext Context of the initial command.
 * @param[in] pxPublishInfo Deserialized publish.
 */
static void prvReportRejectedCallback( void * pxSubscriptionContext,
                                       MQTTPublishInfo_t * pxPublishInfo );

/**
 * @brief Subscribe to the device defender topics.
 *
 * @return true if the subscribe is successful;
 * false otherwise.
 */
static bool prvSubscribeToDeviceDefenderTopics( void );

/**
 * @brief Passed into MQTTAgent_Subscribe() as the callback to execute when the
 * broker ACKs the SUBSCRIBE message. Its implementation sends a notification
 * to the task that called MQTTAgent_Subscribe() to let the task know the
 * SUBSCRIBE operation completed. It also sets the xReturnStatus of the
 * structure passed in as the command's context to the value of the
 * xReturnStatus parameter - which enables the task to check the status of the
 * operation.
 *
 * See https://freertos.org/mqtt/mqtt-agent-demo.html#example_mqtt_api_call
 *
 * @param[in] pxCommandContext Context of the initial command.
 * @param[in] pxReturnInfo The result of the command.
 */
static void prvSubscribeCommandCallback( MQTTAgentCommandContext_t * pxCommandContext,
                                         MQTTAgentReturnInfo_t * pxReturnInfo );


/**
 * @brief Creates the required defender topics for the example, given thing name as the parameter.
 *
 * @param[in] pcThingName Pointer to the thing name
 * @param[in] xThingNameLength Length of the thing name.
 * @return true if the defender topics are created successfully, false otherwise.
 */
static bool prvCreateDefenderTopics( const char * pcThingName,
                                     size_t xThingNameLength );


/**
 * @brief Publishes a new metrics report to the device defender service topic.
 * Waits for a report accepted or rejected response from the defender.
 *
 * @param[in] pvMetricsReport Pointer to the metrics report payload.
 * @param[in] xMetricsReportLength Length of the metrics report payload.
 * @return true if the Publish report was accepted by defender.
 *         false if the report was rejected or request/response timedout.
 */
static bool prvPublishMetricsReport( void * pvMetricsReport,
                                     size_t xMetricsReportLength );


/*-----------------------------------------------------------*/

static void prvReportAcceptedCallback( void * pxSubscriptionContext,
                                       MQTTPublishInfo_t * pxPublishInfo )
{
    TaskHandle_t xTaskToNotify = NULL;

    configASSERT( pxSubscriptionContext != NULL );
    configASSERT( pxPublishInfo != NULL );

    xTaskToNotify = ( TaskHandle_t ) ( pxSubscriptionContext );

    ( void ) xTaskNotify( xTaskToNotify, DEFENDER_REPORT_ACCEPTED_EVENT, eSetBits );
}

/*-----------------------------------------------------------*/

static void prvReportRejectedCallback( void * pxSubscriptionContext,
                                       MQTTPublishInfo_t * pxPublishInfo )
{
    TaskHandle_t xTaskToNotify = NULL;

    configASSERT( pxSubscriptionContext != NULL );
    configASSERT( pxPublishInfo != NULL );

    xTaskToNotify = ( TaskHandle_t ) ( pxSubscriptionContext );

    ( void ) xTaskNotify( xTaskToNotify, DEFENDER_REPORT_REJECTED_EVENT, eSetBits );
}

static void prvSubscribeCommandCallback( MQTTAgentCommandContext_t * pxCommandContext,
                                         MQTTAgentReturnInfo_t * pxReturnInfo )
{
    BaseType_t xSubscriptionAdded = pdFALSE;

    /* Check if the subscribe operation is a success. */
    if( pxReturnInfo->returnCode == MQTTSuccess )
    {
        /* Add subscriptions so that incoming publishes are routed to the application
         * callback. */
        xSubscriptionAdded = xAddMQTTTopicFilterCallback( cReportAcceptedTopic,
                                                          usReportAcceptedTopicLength,
                                                          prvReportAcceptedCallback,
                                                          ( void * ) pxCommandContext->xDefenderTaskHandle,
                                                          pdTRUE );
        configASSERT( xSubscriptionAdded == pdTRUE );

        xSubscriptionAdded = xAddMQTTTopicFilterCallback( cReportRejectedTopic,
                                                          usReportRejectedTopicLength,
                                                          prvReportRejectedCallback,
                                                          ( void * ) pxCommandContext->xDefenderTaskHandle,
                                                          pdTRUE );
        configASSERT( xSubscriptionAdded == pdTRUE );
    }

    /* Store the result in the application defined context so the calling task
     * can check it. */
    pxCommandContext->xReturnStatus = xSubscriptionAdded;

    xTaskNotifyGive( pxCommandContext->xDefenderTaskHandle );
}
/*-----------------------------------------------------------*/

static bool prvSubscribeToDeviceDefenderTopics( void )
{
    bool xReturnStatus = false;
    MQTTStatus_t xStatus;
    uint32_t ulNotificationValue = 0U;
    MQTTAgentCommandInfo_t xCommandParams = { 0 };

    /* These must persist until the command is processed. */
    MQTTAgentSubscribeArgs_t xSubscribeArgs = { 0 };
    MQTTSubscribeInfo_t xSubscribeInfo[ 2 ];
    MQTTAgentCommandContext_t xCommandContext = { 0 };

    /* Subscribe to defender topic for responses for incoming delta updates. */
    xSubscribeInfo[ 0 ].pTopicFilter = cReportAcceptedTopic;
    xSubscribeInfo[ 0 ].topicFilterLength = usReportAcceptedTopicLength;
    xSubscribeInfo[ 0 ].qos = MQTTQoS1;

    /* Subscribe to defender topic for responses for incoming delta updates. */
    xSubscribeInfo[ 1 ].pTopicFilter = cReportRejectedTopic;
    xSubscribeInfo[ 1 ].topicFilterLength = usReportRejectedTopicLength;
    xSubscribeInfo[ 1 ].qos = MQTTQoS1;

    /* Complete the subscribe information. The topic string must persist for
     * duration of subscription - although in this case it is a static const so
     * will persist for the lifetime of the application. */
    xSubscribeArgs.pSubscribeInfo = xSubscribeInfo;
    xSubscribeArgs.numSubscriptions = 2;

    /* Loop in case the queue used to communicate with the MQTT agent is full and
     * attempts to post to it time out.  The queue will not become full if the
     * priority of the MQTT agent task is higher than the priority of the task
     * calling this function. */
    xTaskNotifyStateClear( NULL );

    xCommandContext.xReturnStatus = false;
    xCommandContext.xDefenderTaskHandle = xTaskGetCurrentTaskHandle();

    xCommandParams.blockTimeMs = MAX_COMMAND_SEND_BLOCK_TIME_MS;
    xCommandParams.cmdCompleteCallback = prvSubscribeCommandCallback;
    xCommandParams.pCmdCompleteCallbackContext = &xCommandContext;
    LogInfo( ( "Sending subscribe request to agent for defender topics." ) );

    do
    {
        /* If this fails, the agent's queue is full, so we retry until the agent
         * has more space in the queue. */
        xStatus = MQTTAgent_Subscribe( &xGlobalMqttAgentContext,
                                       &( xSubscribeArgs ),
                                       &xCommandParams );
    } while( xStatus != MQTTSuccess );

    /* Wait for acks from subscribe messages - this is optional.  If the
     * returned value is zero then the wait timed out. */
    ulNotificationValue = ulTaskNotifyTake( pdTRUE, pdMS_TO_TICKS( DEFENDER_RESPONSE_WAIT_MS ) );

    if( ulNotificationValue != 0U )
    {
        /* The callback sets the xReturnStatus member of the context. */
        if( xCommandContext.xReturnStatus != true )
        {
            LogError( ( "Failed to subscribe to defender update topics." ) );
            xReturnStatus = false;
        }
        else
        {
            LogInfo( ( "Successfully subscribed to defender update topics." ) );
            xReturnStatus = true;
        }
    }
    else
    {
        LogError( ( "Timed out to subscribe to defender update topics." ) );
        xReturnStatus = false;
    }

    return xReturnStatus;
}
/*-----------------------------------------------------------*/

static bool prvCreateDefenderTopics( const char * pcThingName,
                                     size_t xThingNameLength )
{
    bool xStatus = true;
    DefenderStatus_t xDefenderStatus = DefenderError;


    if( xStatus == true )
    {
        xDefenderStatus = Defender_GetTopic( cReportPublishTopic,
                                             DEFENDER_MAX_TOPIC_LENGTH,
                                             pcThingName,
                                             xThingNameLength,
                                             DefenderCborReportPublish,
                                             &usReportPublishTopicLength );

        if( xDefenderStatus != DefenderSuccess )
        {
            LogError( ( "Fail to construct defender report publish  topic, error = %u.", xDefenderStatus ) );
            xStatus = false;
        }
    }

    if( xStatus == true )
    {
        xDefenderStatus = Defender_GetTopic( cReportAcceptedTopic,
                                             DEFENDER_MAX_TOPIC_LENGTH,
                                             pcThingName,
                                             xThingNameLength,
                                             DefenderCborReportAccepted,
                                             &usReportAcceptedTopicLength );

        if( xDefenderStatus != DefenderSuccess )
        {
            LogError( ( "Fail to construct defender report accepted  topic, error = %u.", xDefenderStatus ) );
            xStatus = false;
        }
    }

    if( xStatus == true )
    {
        xDefenderStatus = Defender_GetTopic( cReportRejectedTopic,
                                             DEFENDER_MAX_TOPIC_LENGTH,
                                             pcThingName,
                                             xThingNameLength,
                                             DefenderCborReportRejected,
                                             &usReportRejectedTopicLength );

        if( xDefenderStatus != DefenderSuccess )
        {
            LogError( ( "Fail to construct defender report rejected topic, error = %u.", xDefenderStatus ) );
            xStatus = false;
        }
    }

    return xStatus;
}

/*-----------------------------------------------------------*/

static MetricsCollectorStatus_t prvCollectMetrics( DefenderMetrics_t * pxMetrics )
{
    MetricsCollectorStatus_t xStatus;
    size_t usNumOpenPorts = 0;
    size_t usNumConnections = 0;

    xStatus = GetNetworkStats( &pxMetrics->xNetworkStats );

    if( xStatus == MetricsCollectorSuccess )
    {
        xStatus = GetOpenTcpPorts( usOpenTCPPorts, democonfigOPEN_TCP_PORTS_ARRAY_SIZE, &usNumOpenPorts );

        if( xStatus == MetricsCollectorSuccess )
        {
            pxMetrics->pusOpenTCPPortsList = usOpenTCPPorts;
            pxMetrics->ulNumOpenTCPPorts = usNumOpenPorts;
        }
    }

    if( xStatus == MetricsCollectorSuccess )
    {
        xStatus = GetOpenUdpPorts( usOpenUDPPorts, democonfigOPEN_UDP_PORTS_ARRAY_SIZE, &usNumOpenPorts );

        if( xStatus == MetricsCollectorSuccess )
        {
            pxMetrics->pusOpenUDPPortsList = usOpenUDPPorts;
            pxMetrics->ulNumOpenUDPPorts = usNumOpenPorts;
        }
    }

    if( xStatus == MetricsCollectorSuccess )
    {
        xStatus = GetEstablishedConnections( xEstablishedTCPConnections, democonfigESTABLISHED_CONNECTIONS_ARRAY_SIZE, &usNumConnections );

        if( xStatus == MetricsCollectorSuccess )
        {
            pxMetrics->pxEstablishedConnectionsList = xEstablishedTCPConnections;
            pxMetrics->ulEstablishedConnectionsListLength = usNumConnections;
        }
    }

    return xStatus;
}

/*-----------------------------------------------------------*/

static bool prvPublishMetricsReport( void * pvMetricsReport,
                                     size_t xMetricsReportLength )
{
    static MQTTPublishInfo_t xPublishInfo = { 0 };
    MQTTAgentCommandInfo_t xCommandParams = { 0 };
    MQTTStatus_t xCommandStatus = MQTTSendFailed;
    bool xReturnStatus = false;
    uint32_t ulNotifiedValue = 0U;
    BaseType_t xNotifyStatus = pdFALSE;

    /* Set up MQTTPublishInfo_t for the Report message. */
    xPublishInfo.qos = MQTTQoS1;
    xPublishInfo.pTopicName = cReportPublishTopic;
    xPublishInfo.topicNameLength = usReportPublishTopicLength;
    xPublishInfo.pPayload = pvMetricsReport;
    xPublishInfo.payloadLength = xMetricsReportLength;

    /*
     * We do not need a completion callback here since for publishes, we expect to get a
     * response on the appropriate topics for accepted or rejected reports. */
    xCommandParams.blockTimeMs = MAX_COMMAND_SEND_BLOCK_TIME_MS;
    xCommandParams.cmdCompleteCallback = NULL;

    /* Send update. */
    LogInfo( ( "Publishing new metrics report to device defender topic." ) );

    xCommandStatus = MQTTAgent_Publish( &xGlobalMqttAgentContext,
                                        &xPublishInfo,
                                        &xCommandParams );

    if( xCommandStatus == MQTTSuccess )
    {
        LogInfo( ( "Successfully sent a publish message to device defender topic." ) );
        xReturnStatus = true;
    }
    else
    {
        xReturnStatus = false;
    }

    if( xReturnStatus == true )
    {
        xNotifyStatus = xTaskNotifyWait( 0x00,
                                         ( DEFENDER_REPORT_ACCEPTED_EVENT | DEFENDER_REPORT_REJECTED_EVENT ),
                                         &ulNotifiedValue,
                                         pdMS_TO_TICKS( DEFENDER_RESPONSE_WAIT_MS ) );

        if( xNotifyStatus == pdTRUE )
        {
            if( ( ulNotifiedValue & DEFENDER_REPORT_ACCEPTED_EVENT ) != 0 )
            {
                LogInfo( ( "Received a report accepted message from defender. " ) );
            }
            else if( ( ulNotifiedValue & DEFENDER_REPORT_REJECTED_EVENT ) != 0 )
            {
                LogError( ( "Received a report rejected message from defender." ) );
                xReturnStatus = false;
            }
            else
            {
                LogError( ( "Timedout waiting for a response for publish report from defender." ) );
                xReturnStatus = false;
            }
        }
        else
        {
            LogError( ( "Timedout waiting for a response for publish report from defender." ) );
            xReturnStatus = false;
        }
    }

    return xReturnStatus;
}

/*-----------------------------------------------------------*/


void vDeviceDefenderTask( void * pvParameters )
{
    bool xStatus = false;
    void * pvMetricsReport = NULL;
    size_t xMetricsReportLength = 0;
    ReportBuilderStatus_t xReportStatus;
    MetricsCollectorStatus_t xCollectStatus;
    uint32_t ulReportID = 0;
    DefenderMetrics_t xMetrics = { 0 };
    TickType_t xDelayIntervalTicks = 0U;

    /* Remove compiler warnings about unused parameters. */
    ( void ) pvParameters;

    xThingNameLength = KVStore_getValueLength( KVS_CORE_THING_NAME );

    if( ( xThingNameLength > 0 ) && ( xThingNameLength <= MAX_THING_NAME_LENGTH ) )
    {
        memset( cThingName, 0x00, sizeof( cThingName ) );
        ( void ) KVStore_getString( KVS_CORE_THING_NAME, cThingName, sizeof( cThingName ) );
        xStatus = true;
    }
    else
    {
        LogError( ( "Failed to get thing name from KV store, thing name length received = %u, "
                    "max thing name length supported = %u", xThingNameLength, MAX_THING_NAME_LENGTH ) );
        xStatus = false;
    }

    if( xStatus == true )
    {
        if( xGetMQTTAgentState() != MQTT_AGENT_STATE_CONNECTED )
        {
            ( void ) xWaitForMQTTAgentState( MQTT_AGENT_STATE_CONNECTED, portMAX_DELAY );
        }

        LogInfo( ( "MQTT Agent is connected. Initializing device defender task." ) );
    }

    if( xStatus == true )
    {
        xStatus = prvCreateDefenderTopics( cThingName, xThingNameLength );
    }

    if( xStatus == true )
    {
        /* Subscribe to Defender topics. */
        xStatus = prvSubscribeToDeviceDefenderTopics();
    }

    if( xStatus == true )
    {
        for( ; ; )
        {
            xCollectStatus = prvCollectMetrics( &xMetrics );

            if( xCollectStatus == MetricsCollectorSuccess )
            {
                xStatus = true;
            }
            else
            {
                LogError( ( "Failed to collect metrics for defender report, collector error = %d.", xCollectStatus ) );
                xStatus = false;
            }

            if( xStatus == true )
            {
                ulReportID = xTaskGetTickCount();
                xReportStatus = xBuildDefenderMetricsReport( ulReportID,
                                                             democonfigDEVICE_METRICS_REPORT_VERSION,
                                                             &xMetrics,
                                                             pvMetricsReport,
                                                             xMetricsReportLength,
                                                             &xMetricsReportLength );

                if( ( xReportStatus == REPORT_BUILDER_BUFFER_TOO_SMALL ) && ( xMetricsReportLength > 0 ) )
                {
                    pvMetricsReport = pvPortMalloc( xMetricsReportLength );

                    if( pvMetricsReport == NULL )
                    {
                        LogError( ( "Failed to allocate memory for defender metrics report of size %u.", xMetricsReportLength ) );
                        xStatus = false;
                    }
                    else
                    {
                        xReportStatus = xBuildDefenderMetricsReport( ulReportID,
                                                                     democonfigDEVICE_METRICS_REPORT_VERSION,
                                                                     &xMetrics,
                                                                     pvMetricsReport,
                                                                     xMetricsReportLength,
                                                                     &xMetricsReportLength );
                    }
                }

                if( xReportStatus != REPORT_BUILDER_SUCCESS )
                {
                    LogError( ( "Failed to create defender metrics report, report build error = %d.", xReportStatus ) );
                    xStatus = false;
                }
            }

            if( xStatus == true )
            {
                ( void ) prvPublishMetricsReport( pvMetricsReport, xMetricsReportLength );
            }

            if( pvMetricsReport != NULL )
            {
                vPortFree( pvMetricsReport );
                pvMetricsReport = NULL;
                xMetricsReportLength = 0;
            }

            LogInfo( ( "Waiting for %u seconds before publishing next metrics report.", democonfigMETRICS_PUBLISH_INTERVAL_SECONDS ) );

            xDelayIntervalTicks = pdMS_TO_TICKS( democonfigMETRICS_PUBLISH_INTERVAL_SECONDS * 1000 );

            if( xWaitForMQTTAgentState( MQTT_AGENT_STATE_DISCONNECTED, xDelayIntervalTicks ) == pdTRUE )
            {
                ( void ) xWaitForMQTTAgentState( MQTT_AGENT_STATE_CONNECTED, portMAX_DELAY );
            }
        }
    }

    vTaskDelete( NULL );
}
