/*
 * Copyright 2018, 2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <time.h>
#include "sm_printf.h"
#include "stdio.h"
#include "string.h"
#include "tst_sm_time.h"
#include "unity_fixture.h"
#include "unity_internals.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

#if !AX_EMBEDDED
static const char *szPASS = "PASS";
static const char *szIGNORED = "IGNORED";
static const char *szFAILED = "FAILED";
#endif

static const char *gUnity_LastFailureMessage;
static UNITY_LINE_TYPE gUnity_LastFailureFine;
static axTimeMeasurement_t exec_time;


/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */


/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */
void UnityAddin_ConcludeFixture(const char *printableName,
    const char *group,
    const char *name,
    const char *file,
    unsigned int line)
{
    long timetaken = 0;
    concludeMeasurement(&exec_time);
    timetaken = getMeasurement(&exec_time);
    AX_UNUSED_ARG(timetaken);

#if AX_EMBEDDED
    PRINTF("Exec time for :%s:%s = %ldms\r\n", group, name, timetaken);
#else
    FILE *fp = fopen("unity_log.csv", "a+");
    const char *test_status = szPASS;
    const char *msg = "";

    if (gUnity_LastFailureMessage != NULL) {
        msg = gUnity_LastFailureMessage;
    }
    if (gUnity_LastFailureFine != 0) {
        line = gUnity_LastFailureFine;
    }
    if (NULL == fp) {
        return;
    }

    if (Unity.CurrentTestFailed)
        test_status = szFAILED;
    else if (Unity.CurrentTestIgnored)
        test_status = szIGNORED;

    fprintf(fp,
        "%s,%d,%s,%s,\"%s\",%s,%ld,%ld,\"%s\"\n",
        file,
        line,
        group,
        name,
        printableName,
        test_status,
        (long)exec_time.tStart.tv_sec,
        (long)exec_time.tEnd.tv_sec,
        msg
        );
    fclose(fp);
#endif
}

void UnityAddin_SetMessage(const char *msg, const UNITY_LINE_TYPE line)
{
    if ( msg == NULL && line == 0) {
        initMeasurement(&exec_time);
    }
    gUnity_LastFailureMessage = msg;
    gUnity_LastFailureFine = line;
}

void UnityAddin_AnnounceFilters() {
    if (UnityFixture.NameFilter && UnityFixture.Verbose)
    {
        printf("############################################################\n");
        printf("Unity NameFiler = '%s'\n", UnityFixture.NameFilter);
        printf("############################################################\n");
    }

    if (UnityFixture.GroupFilter && UnityFixture.Verbose)
    {
        printf("############################################################\n");
        printf("Unity NameFiler = '%s'\n", UnityFixture.GroupFilter);
        printf("############################################################\n");
    }
}

