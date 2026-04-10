/**
 * @file tst_sm_time.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par LICENSE
 *
 * Copyright 2016,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * (APDU) Execution time measurement utility library
 * @par HISTORY
 * 1.0   03-apr-2015 : Initial version
 *
 *****************************************************************************/

/*******************************************************************
* standard include files
*******************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

/*******************************************************************
* project specific include files
*******************************************************************/
#include "tst_sm_util.h"
#include "tst_sm_time.h"

/*******************************************************************
* global variables and struct definitions
*******************************************************************/

/*
 * API
 */

#ifdef SM_TIME_USE_TIMEVAL
#define CLOCK_MONOTONIC 0

int clock_gettime(int X, struct timeval *tv)
{
#ifdef MSC_VER
    ULONGLONG msSinceBoot = GetTickCount64();
#else
    ULONGLONG msSinceBoot = GetTickCount();
#endif
    tv->tv_sec = (long) (msSinceBoot / 1000);
    tv->tv_usec = (msSinceBoot % 1000) * 1000;
    return (0);
}
#endif // SM_TIME_USE_TIMEVAL

#if 0 //artf993613 - semaphore timeout issue

#ifdef SM_TIME_USE_TIMESPEC
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 0
#endif // CLOCK_MONOTONIC

int clock_gettime(int X, struct timespec *tv)
{
    return 0;
}
#endif // SM_TIME_USE_TIMESPEC

#endif //artf993613 - semaphore timeout issue

/**
 * Initiate measurement of execution time
 *
 * @param[in,out] mPair In: Pointer to an allocated axTimeMeasurement_t structure
 */
void initMeasurement(axTimeMeasurement_t *mPair)
{
    mPair->tStart.tv_sec = 0;
#ifdef SM_TIME_USE_TIMEVAL
    mPair->tStart.tv_usec = 0;
#endif
#ifdef SM_TIME_USE_TIMESPEC
    mPair->tStart.tv_nsec = 0;
#endif
    mPair->tEnd.tv_sec = 0;
#ifdef SM_TIME_USE_TIMEVAL
    mPair->tEnd.tv_usec = 0;
#endif
#ifdef SM_TIME_USE_TIMESPEC
    mPair->tEnd.tv_nsec = 0;
#endif

    clock_gettime(CLOCK_MONOTONIC, &(mPair->tStart));
}

/**
 * Conclude measurement of execution time. Matches a call to ::initMeasurement
 *
 * @param[in,out] mPair In: Pointer to an allocated axTimeMeasurement_t structure
 */
void concludeMeasurement(axTimeMeasurement_t *mPair)
{
    clock_gettime(CLOCK_MONOTONIC, &(mPair->tEnd));
}

/**
 * Calculates (and returns) execution time in ms (milli seconds).
 * \pre Call to ::initMeasurement
 * \pre Call to ::concludeMeasurement
 *
 * @param[in,out] mPair In: Pointer to an allocated axTimeMeasurement_t structure
 * @returns Execution time in ms (milli seconds)
 */
long getMeasurement(axTimeMeasurement_t *mPair)
{
    long startMillis;
    long endMillis;
    long deltaMillis;
    // printf("Start: Sec: 0x%08x - nSec: 0x%08x\n", mPair->tStart.tv_sec, mPair->tStart.tv_nsec);
    // printf("End  : Sec: 0x%08x - nSec: 0x%08x\n", mPair->tEnd.tv_sec, mPair->tEnd.tv_nsec);
#ifdef SM_TIME_USE_TIMEVAL
    startMillis = (mPair->tStart.tv_sec * 1000) + (mPair->tStart.tv_usec / 1000);
    endMillis = (mPair->tEnd.tv_sec * 1000) + (mPair->tEnd.tv_usec / 1000);
#endif
#ifdef SM_TIME_USE_TIMESPEC
    startMillis = (mPair->tStart.tv_sec * 1000) + (mPair->tStart.tv_nsec / 1000000);
    endMillis = (mPair->tEnd.tv_sec * 1000) + (mPair->tEnd.tv_nsec / 1000000);
#endif
    deltaMillis = endMillis - startMillis;

    // printf("Delta:  %" PRIi32 " ms\n", deltaMillis);
    return deltaMillis;
}

/**
 * Create a report fragment based on measurements contained in \p msArray
 *
 * @param[in] fHandle Valid file handle to contain report fragment
 * @param[in] szMessage Label to use in report fragment
 * @param[in] msArray Array containing (execution time) measurements (in ms)
 * @param[in] nMeasurement Amount of measurements contained in \p msArray
 * @param[in] reportMode Defines style of report (construct bitpattern with e.g. ::AX_MEASURE_REPORT_VERBOSE or ::AX_MEASURE_ECHO_STDOUT)
 */
void axSummarizeMeasurement(FILE *fHandle, char *szMessage, long *msArray, int nMeasurement, int reportMode)
{
    int i;
    long averaged = 0;
    long minValue = 0;
    long maxValue = 0;
    int fEchoStdout = 0;
    int fReportVerbose = 0;
    FILE *fHandleArray[2];
    int nHandle = 2;
    int nOut;

    fEchoStdout = ((reportMode & AX_MEASURE_ECHO_MASK) == AX_MEASURE_ECHO_STDOUT);
    fReportVerbose = ((reportMode & AX_MEASURE_REPORT_MASK) == AX_MEASURE_REPORT_VERBOSE);

    if (fEchoStdout)
    {
        fHandleArray[0] = fHandle;
        fHandleArray[1] = stdout;
        nHandle = 2;
    }
    else
    {
        fHandleArray[0] = fHandle;
        nHandle = 1;
    }

    if (nMeasurement > 0)
    {
        minValue = msArray[0];
        maxValue = msArray[0];
    }
    else
    {
        for (nOut=0; nOut<nHandle; nOut++)
        {
            fprintf(fHandleArray[nOut], "%s: No valid amount of measurements ( %" PRIi32 ")\n", szMessage, (int32_t)nMeasurement);
        }
        return;
    }

    for (i=0; i<nMeasurement; i++)
    {
        if (fReportVerbose)
        {
            for (nOut=0; nOut<nHandle; nOut++)
            {
                fprintf(fHandleArray[nOut], "%s: %" PRIu32 " ms\n", szMessage, (uint32_t)msArray[i]);
            }
        }
        averaged += msArray[i];
        minValue = (msArray[i] < minValue) ? msArray[i] : minValue;
        maxValue = (msArray[i] > maxValue) ? msArray[i] : maxValue;
    }
    averaged /= nMeasurement;

    for (nOut=0; nOut<nHandle; nOut++)
    {
        fprintf(fHandleArray[nOut], "Exec Time: %s:\n\tAverage ( %" PRIu32 " measurements):  %" PRIu32 " ms\n",
            szMessage, (uint32_t)nMeasurement, (uint32_t)averaged);
        fprintf(fHandleArray[nOut], "\tMinimum: %" PRIu32 " ms\n", (uint32_t)minValue);
        fprintf(fHandleArray[nOut], "\tMaximum: %" PRIu32 " ms\n", (uint32_t)maxValue);
    }
}

#if !defined(TGT_A71CH) && !defined(TGT_A71CL)
/**
 * @param szMessage
 * @param measured
 * @param lowerBound    measured must be higher than lowerBound in case lowerBound is different from 0
 * @param higherBound   measured must be lower than higherBound in case higherBound is different from 0
 * @param severity
 * @return
 */
int evalMeasurement(char *szMessage, long measured, long lowerBound, long higherBound, axExecTimeEval_t severity) {
    int status = 1;
    printf("%s:  %" PRIu32 " ms\n", szMessage, (uint32_t)measured);
    switch (severity) {
        case AX_TIME_EVAL_IGNORE:
            break;
        case AX_TIME_EVAL_WARNING:
        case AX_TIME_EVAL_FATAL:
            if ( (lowerBound != 0) && (measured < lowerBound) ) {
                printf("*** Execution speed faster than specified: %" PRIu32 " < %" PRIu32 "\n", (uint32_t)measured, (uint32_t)lowerBound);
                status = (severity == AX_TIME_EVAL_FATAL ? 0 : 1);
            }
            if ( (higherBound != 0)  && (measured > higherBound)) {
                printf("*** Execution speed slower than specified: %" PRIu32 " > %" PRIu32 "\n", (uint32_t)measured, (uint32_t)higherBound);
                status = (severity == AX_TIME_EVAL_FATAL ? 0 : 1);
            }
            break;
        default:
            printf("Severity level not defined.\n");
            status = 0;
    }
    return status;
}
#endif //!defined(TGT_A71CH) && !defined(TGT_A71CL)
