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
#include "FreeRTOS.h"
#include "task.h"

#include "defender.h"
#include "defender_report_builder.h"
#include "cbor.h"

#define DEFENDER_REPORT_NUM_PARAMS               ( 2 )

#define DEFENDER_METRICS_STRUCT_NUM_PARAMS       ( 4 )

#define DEFENDER_PORTS_STRUCT_NUM_PARAMS         ( 1 )

#define DEFENDER_CONNECTION_STRUCT_NUM_PARAMS    ( 2 )

#define DEFENDER_NETWORK_STATS_NUM_PARAMS        ( 4 )

#define IPV4_ADDRESS_MAX_LENGTH                  ( 15 )

#define PORT_MAX_LENGTH                          ( 5 )

#define REPORT_IP_ADDR_MAX_LENGTH                ( IPV4_ADDRESS_MAX_LENGTH + PORT_MAX_LENGTH + 1 )

#define REPORT_IP_ADDR_FORMAT                    "%u.%u.%u.%u:%u"

#define CBOR_CONTINUE( xError ) \
    ( ( xError == CborNoError ) || ( xError == CborErrorOutOfMemory ) )


CborError prvWriteReportHeader( CborEncoder * pxMetricsReport,
                                uint32_t ulReportID,
                                const char * pcReportVersion )
{
    CborEncoder xReportHeader = { 0 };
    CborError xCborError = CborUnknownError;

    xCborError = cbor_encoder_create_map( pxMetricsReport, &xReportHeader, DEFENDER_REPORT_NUM_PARAMS );

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xReportHeader, DEFENDER_REPORT_ID_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_uint( &xReportHeader, ulReportID );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xReportHeader, DEFENDER_REPORT_VERSION_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xReportHeader, pcReportVersion );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encoder_close_container( pxMetricsReport, &xReportHeader );
    }

    return xCborError;
}

CborError prvWriteTCPEstablishedConnections( CborEncoder * pxTCPConnections,
                                             TCPConnection_t * pxConnectionList,
                                             uint32_t ulNumConnections )
{
    CborEncoder xEstablishedConns = { 0 }, xConnectionsArray = { 0 }, xConnection = { 0 };
    CborError xCborError = CborUnknownError;
    uint32_t ulIndex = 0;
    char cRemoteIPAddr[ REPORT_IP_ADDR_MAX_LENGTH + 1 ] = { 0 };
    size_t xRemoteIPAddrLength = 0;
    uint8_t * pucIPAddr = NULL;

    xCborError = cbor_encoder_create_map( pxTCPConnections, &xEstablishedConns, 2 );

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xEstablishedConns, DEFENDER_REPORT_CONNECTIONS_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encoder_create_array( &xEstablishedConns, &xConnectionsArray, ulNumConnections );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        for( ulIndex = 0; ulIndex < ulNumConnections; ulIndex++ )
        {
            xCborError = cbor_encoder_create_map( &xConnectionsArray, &xConnection, DEFENDER_CONNECTION_STRUCT_NUM_PARAMS );

            if( CBOR_CONTINUE( xCborError ) == pdTRUE )
            {
                xCborError = cbor_encode_text_stringz( &xConnection, DEFENDER_REPORT_LOCAL_PORT_KEY );
            }

            if( CBOR_CONTINUE( xCborError ) == pdTRUE )
            {
                xCborError = cbor_encode_uint( &xConnection, pxConnectionList[ ulIndex ].usLocalPort );
            }

            if( CBOR_CONTINUE( xCborError ) == pdTRUE )
            {
                xCborError = cbor_encode_text_stringz( &xConnection, DEFENDER_REPORT_REMOTE_ADDR_KEY );
            }

            if( CBOR_CONTINUE( xCborError ) == pdTRUE )
            {
                pucIPAddr = ( uint8_t * ) ( &pxConnectionList[ ulIndex ].ulRemoteIPAddr );
                xRemoteIPAddrLength = snprintf( cRemoteIPAddr,
                                                REPORT_IP_ADDR_MAX_LENGTH,
                                                REPORT_IP_ADDR_FORMAT,
                                                pucIPAddr[ 0 ],
                                                pucIPAddr[ 1 ],
                                                pucIPAddr[ 2 ],
                                                pucIPAddr[ 3 ],
                                                pxConnectionList[ ulIndex ].usRemotePort );

                configASSERT( ( xRemoteIPAddrLength > 0 ) &&
                              ( xRemoteIPAddrLength <= REPORT_IP_ADDR_MAX_LENGTH ) );


                xCborError = cbor_encode_text_stringz( &xConnection, cRemoteIPAddr );
            }

            if( CBOR_CONTINUE( xCborError ) == pdTRUE )
            {
                xCborError = cbor_encoder_close_container( &xConnectionsArray, &xConnection );
            }

            if( xCborError != CborNoError )
            {
                break;
            }
        }
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encoder_close_container( &xEstablishedConns, &xConnectionsArray );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xEstablishedConns, DEFENDER_REPORT_TOTAL_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_uint( &xEstablishedConns, ulNumConnections );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encoder_close_container( pxTCPConnections, &xEstablishedConns );
    }

    return xCborError;
}

CborError prvWriteTCPConnections( CborEncoder * pxMetrics,
                                  TCPConnection_t * pxConnectionList,
                                  uint32_t ulNumConnections )
{
    CborEncoder xTCPConnections = { 0 };
    CborError xCborError = CborUnknownError;

    xCborError = cbor_encoder_create_map( pxMetrics, &xTCPConnections, 1 );

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xTCPConnections, DEFENDER_REPORT_ESTABLISHED_CONNECTIONS_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = prvWriteTCPEstablishedConnections( &xTCPConnections, pxConnectionList, ulNumConnections );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encoder_close_container( pxMetrics, &xTCPConnections );
    }

    return xCborError;
}

CborError prvWriteNetworkStats( CborEncoder * pxMetrics,
                                NetworkStats_t * pxNetworkStats )
{
    CborEncoder xNetworkStatsMap = { 0 };
    CborError xCborError = CborUnknownError;

    xCborError = cbor_encoder_create_map( pxMetrics, &xNetworkStatsMap, DEFENDER_NETWORK_STATS_NUM_PARAMS );

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xNetworkStatsMap, DEFENDER_REPORT_BYTES_IN_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_uint( &xNetworkStatsMap, pxNetworkStats->ulBytesReceived );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xNetworkStatsMap, DEFENDER_REPORT_BYTES_OUT_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_uint( &xNetworkStatsMap, pxNetworkStats->ulBytesSent );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xNetworkStatsMap, DEFENDER_REPORT_PKTS_IN_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_uint( &xNetworkStatsMap, pxNetworkStats->ulPacketsReceived );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xNetworkStatsMap, DEFENDER_REPORT_PKTS_OUT_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_uint( &xNetworkStatsMap, pxNetworkStats->ulPacketsSent );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encoder_close_container( pxMetrics, &xNetworkStatsMap );
    }

    return xCborError;
}


CborError prvWritePorts( CborEncoder * pxMetrics,
                         uint16_t * pusPortsList,
                         uint32_t ulNumPorts )
{
    CborEncoder xPortsContainer = { 0 }, xPortsArray = { 0 }, xPort = { 0 };
    CborError xCborError = CborUnknownError;
    uint32_t ulIndex = 0;

    xCborError = cbor_encoder_create_map( pxMetrics, &xPortsContainer, 2 );

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xPortsContainer, DEFENDER_REPORT_PORTS_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        cbor_encoder_create_array( &xPortsContainer, &xPortsArray, ulNumPorts );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        for( ulIndex = 0; ulIndex < ulNumPorts; ulIndex++ )
        {
            xCborError = cbor_encoder_create_map( &xPortsArray, &xPort, DEFENDER_PORTS_STRUCT_NUM_PARAMS );

            if( CBOR_CONTINUE( xCborError ) == pdTRUE )
            {
                xCborError = cbor_encode_text_stringz( &xPort, DEFENDER_REPORT_PORT_KEY );
            }

            if( CBOR_CONTINUE( xCborError ) == pdTRUE )
            {
                xCborError = cbor_encode_uint( &xPort, pusPortsList[ ulIndex ] );
            }

            if( CBOR_CONTINUE( xCborError ) == pdTRUE )
            {
                xCborError = cbor_encoder_close_container( &xPortsArray, &xPort );
            }

            if( xCborError != CborNoError )
            {
                break;
            }
        }
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encoder_close_container( &xPortsContainer, &xPortsArray );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xPortsContainer, DEFENDER_REPORT_TOTAL_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_uint( &xPortsContainer, ulNumPorts );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encoder_close_container( pxMetrics, &xPortsContainer );
    }

    return xCborError;
}

CborError prvWriteMetrics( CborEncoder * pxReport,
                           DefenderMetrics_t * pxMetrics )
{
    CborEncoder xMetricsMap = { 0 };
    CborError xCborError = CborUnknownError;

    xCborError = cbor_encoder_create_map( pxReport, &xMetricsMap, DEFENDER_METRICS_STRUCT_NUM_PARAMS );

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xMetricsMap, DEFENDER_REPORT_TCP_LISTENING_PORTS_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = prvWritePorts( &xMetricsMap, pxMetrics->pusOpenTCPPortsList, pxMetrics->ulNumOpenTCPPorts );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xMetricsMap, DEFENDER_REPORT_UDP_LISTENING_PORTS_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = prvWritePorts( &xMetricsMap, pxMetrics->pusOpenUDPPortsList, pxMetrics->ulNumOpenUDPPorts );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xMetricsMap, DEFENDER_REPORT_TCP_CONNECTIONS_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = prvWriteTCPConnections( &xMetricsMap, pxMetrics->pxEstablishedConnectionsList, pxMetrics->ulEstablishedConnectionsListLength );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xMetricsMap, DEFENDER_REPORT_NETWORK_STATS_KEY );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = prvWriteNetworkStats( &xMetricsMap, &pxMetrics->xNetworkStats );
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encoder_close_container( pxReport, &xMetricsMap );
    }

    return xCborError;
}

ReportBuilderStatus_t xBuildDefenderMetricsReport( uint32_t ulReportID,
                                                   const char * pcReportVersion,
                                                   DefenderMetrics_t * pxMetrics,
                                                   uint8_t * pBuffer,
                                                   size_t xBufferLength,
                                                   size_t * pxOutBufferLength )
{
    CborError xCborError = CborUnknownError;
    CborEncoder xEncoder = { 0 }, xMetricsReport = { 0 };
    ReportBuilderStatus_t xStatus = REPORT_BUILDER_INTERNAL_ERROR;


    cbor_encoder_init( &xEncoder, pBuffer, xBufferLength, 0 );

    xCborError = cbor_encoder_create_map( &xEncoder, &xMetricsReport, DEFENDER_REPORT_NUM_PARAMS );

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xMetricsReport, DEFENDER_REPORT_HEADER_KEY );

        if( CBOR_CONTINUE( xCborError ) == pdTRUE )
        {
            xCborError = prvWriteReportHeader( &xMetricsReport, ulReportID, pcReportVersion );
        }
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encode_text_stringz( &xMetricsReport, DEFENDER_REPORT_METRICS_KEY );

        if( CBOR_CONTINUE( xCborError ) == pdTRUE )
        {
            xCborError = prvWriteMetrics( &xMetricsReport, pxMetrics );
        }
    }

    if( CBOR_CONTINUE( xCborError ) == pdTRUE )
    {
        xCborError = cbor_encoder_close_container( &xEncoder, &xMetricsReport );
    }

    if( xCborError == CborNoError )
    {
        ( *pxOutBufferLength ) = cbor_encoder_get_buffer_size( &xEncoder, pBuffer );
        xStatus = REPORT_BUILDER_SUCCESS;
    }
    else if( xCborError == CborErrorOutOfMemory )
    {
        ( *pxOutBufferLength ) = cbor_encoder_get_extra_bytes_needed( &xEncoder );
        xStatus = REPORT_BUILDER_BUFFER_TOO_SMALL;
    }
    else
    {
        LogError( ( "Failed to serialize defender metrics report, cbor error = %d.", xCborError ) );
    }

    return xStatus;
}
