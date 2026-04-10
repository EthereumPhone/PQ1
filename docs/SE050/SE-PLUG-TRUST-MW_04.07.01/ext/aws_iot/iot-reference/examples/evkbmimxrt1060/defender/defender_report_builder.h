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

#ifndef _DEFENDER_REPORT_BUILDER_H
#define _DEFENDER_REPORT_BUILDER_H

#include "defender_metrics.h"

/**
 * @brief Enums for error codes returned from defender report builder.
 */
typedef enum ReportBuilderStatus
{
    REPORT_BUILDER_SUCCESS = 0,
    REPORT_BUILDER_BUFFER_TOO_SMALL = 1,
    REPORT_BUILDER_INVALID_PARAM = 2,
    REPORT_BUILDER_INTERNAL_ERROR = 3
} ReportBuilderStatus_t;


ReportBuilderStatus_t xBuildDefenderMetricsReport( uint32_t ulReportID,
                                                   const char * pcReportVersion,
                                                   DefenderMetrics_t * pxMetrics,
                                                   uint8_t * pBuffer,
                                                   size_t xBufferLength,
                                                   size_t * pxOutBufferLength );


#endif /* ifndef _DEFENDER_REPORT_BUILDER_H */
