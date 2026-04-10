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

/*
 * This file demonstrates task which use the MQTT agent API
 * to send unique MQTT payloads to unique topics over the same MQTT connection
 * to the same MQTT agent.  Some tasks use QoS0 and others QoS1.
 *
 * vSimpleSubscribePublishTask() subscribes to a topic then periodically publishes a message to the same
 * topic to which it has subscribed.  The command context sent to
 * MQTTAgent_Publish() contains a unique number that is sent back to the task
 * as a task notification from the callback function that executes when the
 * PUBLISH operation is acknowledged (or just sent in the case of QoS 0).  The
 * task checks the number it receives from the callback equals the number it
 * previously set in the command context before printing out either a success
 * or failure message.
 */


/* Standard includes. */
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

/* Demo Specific configs. */
#include "demo_config.h"

/* MQTT library includes. */
#include "core_mqtt.h"

/* MQTT agent include. */
#include "core_mqtt_agent.h"

/* MQTT agent task API. */
#include "mqtt_agent_task.h"

/* Fetches thing name from the key store */
#include "kvstore.h"

/**
 * @brief Delay for the synchronous publisher task between publishes.
 */
#define mqttexampleDELAY_BETWEEN_PUBLISH_OPERATIONS_MS    ( 2000U )

/**
 * @brief Number of publishes done by each task in this demo.
 */
#define mqttexamplePUBLISH_COUNT                          UINT32_MAX

/**
 * @brief Number of times a publish has to be retried if agent cannot send a QoS0 packet
 * or an ACK is not received for a QoS1 packet.
 */
#define mqttexampleNUM_PUBLISH_RETRIES                    ( 3 )

/**
 * @brief The maximum amount of time in milliseconds to wait for the commands
 * to be posted to the MQTT agent should the MQTT agent's command queue be full.
 * Tasks wait in the Blocked state, so don't use any CPU time.
 */
#define mqttexampleMAX_COMMAND_SEND_BLOCK_TIME_MS         ( 1000 )

/**
 * @brief Maximum length of the thing name as set by AWS IoT.
 * This is used to set the maximum size of topic buffer that needs to be allocated.
 */
#define mqttexampleTHING_NAME_MAX_LENGTH                  ( 128 )

/**
 * @brief Size of statically allocated buffers for holding payloads.
 */
#define mqttexampleSTRING_BUFFER_LENGTH                   ( 100 )

/**
 * @brief Format of the loop-back topic.
 * Demo task subscribes to the loop-back topic and then publishes to the same topic so as to echo back
 * the message published onto the serial console. This tests the full publish-subscribe path of the message
 * without an external application sending messages to the device.
 *
 * Topic format follows a hierarchy as follows: domain_name/device_identifier/publisher_identifier.
 * domain_name refers to domain under which all devices publishes and subscribes message with the MQTT broker.
 * device_identifier is a unique identifier for a device sending message within the domain. The domain name and
 * device_identifier together can be used a topic filter to subscribe to all messages from device.
 * publisher_identifier is a unique identifier for an entity within a device which is publishing the message. In
 * this demo this can be a task number, when more than one tasks are publishing within a device.
 *
 */
#define mqttexampleLOOPBACK_TOPIC_FORMAT                  "pubsub_demo/%s/task_%lu"

/**
 * @brief Format for the topic to which demo task sends PUBLISH messages to broker.
 * The topic is set by default as the loopback topic, so that device will receive the same message which is sent to the
 * broker.
 */
#define mqttexampleOUTPUT_TOPIC_FORMAT                    mqttexampleLOOPBACK_TOPIC_FORMAT

/**
 * @brief Size of the static buffer to hold the output topic name.
 * The buffer should accommodate the topic format string, thing name and the task number which is a 32bit integer.
 */
#define mqttexampleOUTPUT_TOPIC_BUFFER_LENGTH             ( sizeof( mqttexampleOUTPUT_TOPIC_FORMAT ) + mqttexampleTHING_NAME_MAX_LENGTH + 10U )

/**
 * @brief Format for the topic to receive incoming messages from the MQTT broker.
 * Topic is set by default as the loopback topic so that the device will receive the same message which is published to the
 * broker.
 */
#define mqttexampleINPUT_TOPIC_FORMAT                     mqttexampleLOOPBACK_TOPIC_FORMAT

/**
 * @brief Size of the static buffer to hold the topic name.
 * The buffer should accommodate the topic format string, thing name and the task number which is a 32bit integer.
 */
#define mqttexampleINPUT_TOPIC_BUFFER_LENGTH              ( sizeof( mqttexampleINPUT_TOPIC_FORMAT ) + mqttexampleTHING_NAME_MAX_LENGTH + 10U )

/*-----------------------------------------------------------*/

/**
 * @brief Defines the structure to use as the command callback context in this
 * demo.
 */
struct MQTTAgentCommandContext
{
    TaskHandle_t xTaskToNotify;
    void * pArgs;
};

/*-----------------------------------------------------------*/

/**
 * @brief Passed into MQTTAgent_Subscribe() as the callback to execute when the
 * broker ACKs the SUBSCRIBE message.  Its implementation sends a notification
 * to the task that called MQTTAgent_Subscribe() to let the task know the
 * SUBSCRIBE operation completed.  It also sets the xReturnStatus of the
 * structure passed in as the command's context to the value of the
 * xReturnStatus parameter - which enables the task to check the status of the
 * operation.
 *
 * See https://freertos.org/mqtt/mqtt-agent-demo.html#example_mqtt_api_call
 *
 * @param[in] pxCommandContext Context of the initial command.
 * @param[in].xReturnStatus The result of the command.
 */
static void prvSubscribeCommandCallback( MQTTAgentCommandContext_t * pxCommandContext,
                                         MQTTAgentReturnInfo_t * pxReturnInfo );

/**
 * @brief Passed into MQTTAgent_Publish() as the callback to execute when the
 * broker ACKs the PUBLISH message.  Its implementation sends a notification
 * to the task that called MQTTAgent_Publish() to let the task know the
 * PUBLISH operation completed.  It also sets the xReturnStatus of the
 * structure passed in as the command's context to the value of the
 * xReturnStatus parameter - which enables the task to check the status of the
 * operation.
 *
 * See https://freertos.org/mqtt/mqtt-agent-demo.html#example_mqtt_api_call
 *
 * @param[in] pxCommandContext Context of the initial command.
 * @param[in].xReturnStatus The result of the command.
 */
static void prvPublishCommandCallback( MQTTAgentCommandContext_t * pxCommandContext,
                                       MQTTAgentReturnInfo_t * pxReturnInfo );

/**
 * @brief Passed into MQTTAgent_Subscribe() as the callback to execute when
 * there is an incoming publish on the topic being subscribed to.  Its
 * implementation just logs information about the incoming publish including
 * the publish messages source topic and payload.
 *
 * See https://freertos.org/mqtt/mqtt-agent-demo.html#example_mqtt_api_call
 *
 * @param[in] pvIncomingPublishCallbackContext Context of the initial command.
 * @param[in] pxPublishInfo Deserialized publish.
 */
static void prvIncomingPublishCallback( void * pvIncomingPublishCallbackContext,
                                        MQTTPublishInfo_t * pxPublishInfo );

/**
 * @brief Subscribe to the topic the demo task will also publish to - that
 * results in all outgoing publishes being published back to the task
 * (effectively echoed back).
 *
 * @param[in] xQoS The quality of service (QoS) to use.  Can be zero or one
 * for all MQTT brokers.  Can also be QoS2 if supported by the broker.  AWS IoT
 * does not support QoS2.
 * @param[in] pcTopicFilter Pointer to the topic filter string to subscribe for.
 * @param[in] xTopicFilterLength Length of the topic filter string.
 */
static MQTTStatus_t prvSubscribeToTopic( MQTTQoS_t xQoS,
                                         char * pcTopicFilter,
                                         size_t xTopicFilterLength );


/**
 * @brief Publishes the given payload using the given qos to the topic provided.
 *
 * Function queues a publish command with the MQTT agent and waits for response. For
 * Qos0 publishes command is successful when the message is sent out of network. For Qos1
 * publishes, the command succeeds once a puback is received. If publish is unsuccessful, the function
 * retries the publish for a configure number of tries.
 *
 * @param[in] xQoS The quality of service (QoS) to use.  Can be zero or one
 * for all MQTT brokers.  Can also be QoS2 if supported by the broker.  AWS IoT
 * does not support QoS2.
 * @param[in] pcTopic NULL terminated topic string to which message is published.
 * @param[in] xTopicLength Length of the topic string.
 * @param[in] pucPayload The payload blob to be published.
 * @param[in] xPayloadLength Length of the payload blob to be published.
 * @param[in] lNumTries Number of retries if the QoS1 publish is not acknowledged.
 */
static MQTTStatus_t prvPublishToTopic( MQTTQoS_t xQoS,
                                       char * pcTopic,
                                       size_t xTopicLength,
                                       uint8_t * pucPayload,
                                       size_t xPayloadLength,
                                       int32_t lNumTries );

/**
 * @brief Retrieves the thing name from key store to use in demo.
 *
 * @return Pointer to null terminated string containing the thing name.
 *         NULL if thing name not found.
 */
static char * prvGetThingNameFromKeyStore( void );

/**
 * @brief The function that implements the task demonstrated by this file.
 *
 * @param pvParameters The parameters to the task.
 */
void vSimpleSubscribePublishTask( void * pvParameters );


/**
 * @brief Starts a group of publish subscribe tasks as requested by the user.
 * All tasks share the same code, task stack size and task priority, but publishes
 * messages to different topics.
 *
 * @param ulNumPubsubTasks Number of publish subscribe tasks to start.
 * @param uxStackSize Stack size for each publish subscribe task.
 * @param uxPriority Priority for each publish subscribe task.
 */
BaseType_t xStartSimplePubSubTasks( uint32_t ulNumPubsubTasks,
                                    configSTACK_DEPTH_TYPE uxStackSize,
                                    UBaseType_t uxPriority );

/*-----------------------------------------------------------*/

/**
 * @brief The MQTT agent manages the MQTT contexts.  This set the handle to the
 * context used by this demo.
 */
extern MQTTAgentContext_t xGlobalMqttAgentContext;

/*-----------------------------------------------------------*/

static void prvPublishCommandCallback( MQTTAgentCommandContext_t * pxCommandContext,
                                       MQTTAgentReturnInfo_t * pxReturnInfo )
{
    if( pxCommandContext->xTaskToNotify != NULL )
    {
        ( void ) xTaskNotify( pxCommandContext->xTaskToNotify,
                              pxReturnInfo->returnCode,
                              eSetValueWithOverwrite );
    }
}

/*-----------------------------------------------------------*/

static void prvSubscribeCommandCallback( MQTTAgentCommandContext_t * pxCommandContext,
                                         MQTTAgentReturnInfo_t * pxReturnInfo )
{
    BaseType_t xSubscriptionAdded = pdFALSE;
    MQTTAgentSubscribeArgs_t * pxSubscribeArgs = ( MQTTAgentSubscribeArgs_t * ) pxCommandContext->pArgs;

    /* Check if the subscribe operation is a success. Only one topic is
     * subscribed by this demo. */
    if( pxReturnInfo->returnCode == MQTTSuccess )
    {
        /* Add subscription so that incoming publishes are routed to the application
         * callback. */
        xSubscriptionAdded = xAddMQTTTopicFilterCallback( pxSubscribeArgs->pSubscribeInfo->pTopicFilter,
                                                          pxSubscribeArgs->pSubscribeInfo->topicFilterLength,
                                                          prvIncomingPublishCallback,
                                                          NULL,
                                                          pdTRUE );
        configASSERT( xSubscriptionAdded == pdTRUE );
    }

    xTaskNotify( pxCommandContext->xTaskToNotify,
                 ( uint32_t ) ( pxReturnInfo->returnCode ),
                 eSetValueWithOverwrite );
}

/*-----------------------------------------------------------*/

static void prvIncomingPublishCallback( void * pvIncomingPublishCallbackContext,
                                        MQTTPublishInfo_t * pxPublishInfo )
{
    static char cTerminatedString[ mqttexampleSTRING_BUFFER_LENGTH ];

    ( void ) pvIncomingPublishCallbackContext;

    /* Create a message that contains the incoming MQTT payload to the logger,
     * terminating the string first. */
    if( pxPublishInfo->payloadLength < mqttexampleSTRING_BUFFER_LENGTH )
    {
        memcpy( ( void * ) cTerminatedString, pxPublishInfo->pPayload, pxPublishInfo->payloadLength );
        cTerminatedString[ pxPublishInfo->payloadLength ] = 0x00;
    }
    else
    {
        memcpy( ( void * ) cTerminatedString, pxPublishInfo->pPayload, mqttexampleSTRING_BUFFER_LENGTH );
        cTerminatedString[ mqttexampleSTRING_BUFFER_LENGTH - 1 ] = 0x00;
    }

    LogInfo( ( "Received incoming publish message %s", cTerminatedString ) );
}

/*-----------------------------------------------------------*/

static MQTTStatus_t prvSubscribeToTopic( MQTTQoS_t xQoS,
                                         char * pcTopicFilter,
                                         size_t xTopicFilterLength )
{
    MQTTStatus_t xCommandStatus;
    MQTTAgentSubscribeArgs_t xSubscribeArgs = { 0 };
    MQTTSubscribeInfo_t xSubscribeInfo = { 0 };
    MQTTAgentCommandContext_t xCommandContext = { 0UL };
    MQTTAgentCommandInfo_t xCommandParams = { 0UL };
    uint32_t ulNotifiedValue = 0U;

    /* Complete the subscribe information.  The topic string must persist for
     * duration of subscription! */
    xSubscribeInfo.pTopicFilter = pcTopicFilter;
    xSubscribeInfo.topicFilterLength = ( uint16_t ) xTopicFilterLength;
    xSubscribeInfo.qos = xQoS;
    xSubscribeArgs.pSubscribeInfo = &xSubscribeInfo;
    xSubscribeArgs.numSubscriptions = 1;

    /* Complete an application defined context associated with this subscribe message.
     * This gets updated in the callback function so the variable must persist until
     * the callback executes. */
    xCommandContext.xTaskToNotify = xTaskGetCurrentTaskHandle();
    xCommandContext.pArgs = ( void * ) &xSubscribeArgs;

    xCommandParams.blockTimeMs = mqttexampleMAX_COMMAND_SEND_BLOCK_TIME_MS;
    xCommandParams.cmdCompleteCallback = prvSubscribeCommandCallback;
    xCommandParams.pCmdCompleteCallbackContext = ( void * ) &xCommandContext;

    xTaskNotifyStateClear( NULL );

    /* Loop in case the queue used to communicate with the MQTT agent is full and
     * attempts to post to it time out.  The queue will not become full if the
     * priority of the MQTT agent task is higher than the priority of the task
     * calling this function. */
    do
    {
        xCommandStatus = MQTTAgent_Subscribe( &xGlobalMqttAgentContext,
                                              &xSubscribeArgs,
                                              &xCommandParams );

        if( xCommandStatus == MQTTSuccess )
        {
            /*
             * If command was enqueued successfully, then agent will either process the packet successfully, or if
             * there is a disconnect, then it either retries the subscribe message while reconnecting and resuming
             * persistent sessions or cancel the operation and invokes the callback for failed response.
             * Hence the caller task wait indefinitely for a success or failure response from agent.
             */
            ( void ) xTaskNotifyWait( 0UL,
                                      UINT32_MAX,
                                      &ulNotifiedValue,
                                      portMAX_DELAY );
            xCommandStatus = ( MQTTStatus_t ) ( ulNotifiedValue );
        }

        if( xCommandStatus != MQTTSuccess )
        {
            if( xGetMQTTAgentState() == MQTT_AGENT_STATE_DISCONNECTED )
            {
                ( void ) xWaitForMQTTAgentState( MQTT_AGENT_STATE_CONNECTED, portMAX_DELAY );
            }
        }
    } while( xCommandStatus != MQTTSuccess );

    return xCommandStatus;
}
/*-----------------------------------------------------------*/

static MQTTStatus_t prvPublishToTopic( MQTTQoS_t xQoS,
                                       char * pcTopic,
                                       size_t xTopicLength,
                                       uint8_t * pucPayload,
                                       size_t xPayloadLength,
                                       int32_t lNumRetries )
{
    MQTTPublishInfo_t xPublishInfo = { 0UL };
    MQTTAgentCommandContext_t xCommandContext = { 0 };
    MQTTStatus_t xCommandStatus;
    MQTTAgentCommandInfo_t xCommandParams = { 0UL };
    uint32_t ulNotifiedValue = 0U;

    xTaskNotifyStateClear( NULL );

    /* Configure the publish operation. */
    xPublishInfo.qos = xQoS;
    xPublishInfo.pTopicName = pcTopic;
    xPublishInfo.topicNameLength = ( uint16_t ) xTopicLength;
    xPublishInfo.pPayload = pucPayload;
    xPublishInfo.payloadLength = xPayloadLength;

    xCommandContext.xTaskToNotify = xTaskGetCurrentTaskHandle();

    xCommandParams.blockTimeMs = mqttexampleMAX_COMMAND_SEND_BLOCK_TIME_MS;
    xCommandParams.cmdCompleteCallback = prvPublishCommandCallback;
    xCommandParams.pCmdCompleteCallbackContext = &xCommandContext;

    do
    {
        xCommandStatus = MQTTAgent_Publish( &xGlobalMqttAgentContext,
                                            &xPublishInfo,
                                            &xCommandParams );

        if( xCommandStatus == MQTTSuccess )
        {
            /*
             * If command was enqueued successfully, then agent will either process the packet successfully, or if
             * there is a disconnect, then it either retries the publish after reconnecting and resuming session
             * (only for persistent sessions) or cancel the operation and invokes the callback for failed response.
             * Hence the caller task wait indefinitely for a success or failure response from agent.
             */
            ( void ) xTaskNotifyWait( 0UL,
                                      UINT32_MAX,
                                      &ulNotifiedValue,
                                      portMAX_DELAY );
            xCommandStatus = ( MQTTStatus_t ) ( ulNotifiedValue );
        }

        if( ( xCommandStatus != MQTTSuccess ) && ( lNumRetries > 0 ) )
        {
            if( xGetMQTTAgentState() == MQTT_AGENT_STATE_DISCONNECTED )
            {
                ( void ) xWaitForMQTTAgentState( MQTT_AGENT_STATE_CONNECTED, portMAX_DELAY );
            }

            if( xQoS == MQTTQoS1 )
            {
                xPublishInfo.dup = true;
            }
        }
    } while( ( xCommandStatus != MQTTSuccess ) && ( lNumRetries-- > 0 ) );

    return xCommandStatus;
}
/*-----------------------------------------------------------*/

static char * prvGetThingNameFromKeyStore( void )
{
    size_t xValueLength = 0U;
    char * pcValue = NULL;

    /* Load broker endpoint and thing name for client connection, from the key store. */
    xValueLength = KVStore_getValueLength( KVS_CORE_THING_NAME );

    if( xValueLength > 0 )
    {
        pcValue = pvPortMalloc( xValueLength + 1 );

        if( pcValue != NULL )
        {
            ( void ) KVStore_getString( KVS_CORE_THING_NAME, pcValue, ( xValueLength + 1 ) );
        }
    }

    return pcValue;
}

/*-----------------------------------------------------------*/


void vSimpleSubscribePublishTask( void * pvParameters )
{
    uint32_t ulTaskNumber = ( uint32_t ) pvParameters;
    MQTTQoS_t xQoS;
    TickType_t xTicksToDelay;
    char cPayloadBuf[ mqttexampleSTRING_BUFFER_LENGTH ];
    char cInTopicBuf[ mqttexampleINPUT_TOPIC_BUFFER_LENGTH ];
    char cOutTopicBuf[ mqttexampleOUTPUT_TOPIC_BUFFER_LENGTH ];
    size_t xInTopicLength = 0UL, xOutTopicLength = 0UL, xPayloadLength = 0UL;
    char * pcThingName = NULL;
    uint32_t ulPublishCount = 0U, ulSuccessCount = 0U, ulFailCount = 0U;
    BaseType_t xStatus = pdPASS;
    MQTTStatus_t xMQTTStatus;

    /* Have different tasks use different QoS.  0 and 1.  2 can also be used
     * if supported by the broker. */
    xQoS = ( MQTTQoS_t ) ( ulTaskNumber % 2UL );

    /*
     * Get the thing name to be used in topic filter.
     */
    pcThingName = prvGetThingNameFromKeyStore();

    if( pcThingName == NULL )
    {
        xStatus = pdFAIL;
    }

    if( xStatus == pdPASS )
    {
        if( xGetMQTTAgentState() != MQTT_AGENT_STATE_CONNECTED )
        {
            ( void ) xWaitForMQTTAgentState( MQTT_AGENT_STATE_CONNECTED, portMAX_DELAY );
        }
    }

    if( xStatus == pdPASS )
    {
        /* Create a topic name for this task to publish to. */
        xInTopicLength = snprintf( cInTopicBuf,
                                   mqttexampleINPUT_TOPIC_BUFFER_LENGTH,
                                   mqttexampleINPUT_TOPIC_FORMAT,
                                   pcThingName,
                                   ulTaskNumber );

        /*  Assert if the topic buffer is enough to hold the required topic. */
        configASSERT( xInTopicLength <= mqttexampleINPUT_TOPIC_BUFFER_LENGTH );

        /* Subscribe to the same topic to which this task will publish.  That will
         * result in each published message being published from the server back to
         * the target. */

        LogInfo( ( "Sending subscribe request to agent for topic filter: %.*s", xInTopicLength, cInTopicBuf ) );

        xMQTTStatus = prvSubscribeToTopic( xQoS, cInTopicBuf, xInTopicLength );

        if( xMQTTStatus != MQTTSuccess )
        {
            LogError( ( "Failed to subscribe to topic: %.*s",
                        xInTopicLength,
                        cInTopicBuf ) );
            xStatus = pdFALSE;
        }
        else
        {
            LogError( ( "Successfully subscribed to topic: %.*s",
                        xInTopicLength,
                        cInTopicBuf ) );
        }
    }

    if( xStatus == pdTRUE )
    {
        /* Create a topic name for this task to publish to. */
        xOutTopicLength = snprintf( cOutTopicBuf,
                                    mqttexampleOUTPUT_TOPIC_BUFFER_LENGTH,
                                    mqttexampleOUTPUT_TOPIC_FORMAT,
                                    pcThingName,
                                    ulTaskNumber );

        /*  Assert if the topic buffer is enough to hold the required topic. */
        configASSERT( xOutTopicLength <= mqttexampleOUTPUT_TOPIC_BUFFER_LENGTH );

        /* For a finite number of publishes... */
        for( ulPublishCount = 0UL; ulPublishCount < mqttexamplePUBLISH_COUNT; ulPublishCount++ )
        {
            /* Create a payload to send with the publish message.  This contains
             * the task name and an incrementing number. */
            xPayloadLength = snprintf( cPayloadBuf,
                                       mqttexampleSTRING_BUFFER_LENGTH,
                                       "Task %lu publishing message %d",
                                       ulTaskNumber,
                                       ( int ) ulPublishCount );

            /* Assert if the buffer length is not enough to hold the message.*/
            configASSERT( xPayloadLength <= mqttexampleSTRING_BUFFER_LENGTH );

            LogInfo( ( "Sending publish request on topic \"%.*s\"", xOutTopicLength, cOutTopicBuf ) );

            xMQTTStatus = prvPublishToTopic( xQoS,
                                             cOutTopicBuf,
                                             xOutTopicLength,
                                             ( uint8_t * ) cPayloadBuf,
                                             xPayloadLength,
                                             mqttexampleNUM_PUBLISH_RETRIES );

            if( xMQTTStatus == MQTTSuccess )
            {
                ulSuccessCount++;
                LogInfo( ( "Successfully sent QoS %u publish to topic: %s (PassCount:%d, FailCount:%d).",
                           xQoS,
                           cOutTopicBuf,
                           ulSuccessCount,
                           ulFailCount ) );
            }
            else
            {
                ulFailCount++;
                LogError( ( "Timed out while sending QoS %u publish to topic: %s (PassCount:%d, FailCount: %d)",
                            xQoS,
                            cOutTopicBuf,
                            ulSuccessCount,
                            ulFailCount ) );
            }

            /* Add a little randomness into the delay so the tasks don't remain
             * in lockstep. */
            xTicksToDelay = pdMS_TO_TICKS( mqttexampleDELAY_BETWEEN_PUBLISH_OPERATIONS_MS ) +
                            ( xTaskGetTickCount() % 0xff );

            if( xWaitForMQTTAgentState( MQTT_AGENT_STATE_DISCONNECTED, xTicksToDelay ) == pdTRUE )
            {
                ( void ) xWaitForMQTTAgentState( MQTT_AGENT_STATE_CONNECTED, portMAX_DELAY );
            }
        }

        /* Delete the task if it is complete. */
        LogInfo( ( "Task %u completed.", ulTaskNumber ) );
    }

    if( pcThingName != NULL )
    {
        vPortFree( pcThingName );
        pcThingName = NULL;
    }

    vTaskDelete( NULL );
}

BaseType_t xStartSimplePubSubTasks( uint32_t ulNumPubsubTasks,
                                    configSTACK_DEPTH_TYPE uxStackSize,
                                    UBaseType_t uxPriority )
{
    BaseType_t xResult = pdFAIL;
    uint32_t ulTaskNum;

    for( ulTaskNum = 0; ulTaskNum < ulNumPubsubTasks; ulTaskNum++ )
    {
        xResult = xTaskCreate( vSimpleSubscribePublishTask,
                               "PUBSUB",
                               uxStackSize,
                               ( void * ) ulTaskNum,
                               uxPriority,
                               NULL );

        if( xResult == pdFAIL )
        {
            break;
        }
    }

    return xResult;
}
