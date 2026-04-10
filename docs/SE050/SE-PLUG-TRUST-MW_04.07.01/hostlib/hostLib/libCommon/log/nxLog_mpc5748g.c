/*
*
* Copyright 2018,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CPU_MPC5748G)

#include <nxLog.h>
#include <stdarg.h>
#include <stdio.h>
#include <inttypes.h>

#include "sm_printf.h"

#include "pin_mux.h"
#include "i2c1.h"
#include "linflexd_uart1.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(USE_RTOS) && (USE_RTOS == 1)
#include "FreeRTOS.h"
#include "semphr.h"
#endif

#if (__GNUC__ && !AX_EMBEDDED) || (USE_RTOS)
#define USE_LOCK 1
#else
#define USE_LOCK 0
#endif

#define szCRLF "\r\n"
#define szLF "\n"

static void ansi_setColor(int level);
static void setColor(int level);
static void reSetColor();

#if defined(_MSC_VER)
static HANDLE sStdOutConsoleHandle = INVALID_HANDLE_VALUE;
static void msvc_setColor(int level);
static void msvc_reSetColor(void);
#define szEOL szLF
#endif

#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_BLUE "\033[0;34m"
#define COLOR_RESET "\033[0m"

#if defined(__GNUC__) && !defined(__ARMCC_VERSION)
#if defined(CPU_MPC5748G)
#else
#include <unistd.h>
#endif

#if AX_EMBEDDED
#define szEOL szCRLF
#else
#define szEOL szLF
#endif
#endif /* __GNUC__ && !defined(__ARMCC_VERSION) */

#ifndef szEOL
#define szEOL szCRLF
#endif

uint32_t bytesRemaining;

#define PRINTF(text) LINFLEXD_UART_DRV_SendData(INST_LINFLEXD_UART1, (uint8_t *)text, strlen(text));\
                     while(LINFLEXD_UART_DRV_GetTransmitStatus(INST_LINFLEXD_UART1, &bytesRemaining) != STATUS_SUCCESS);

/* Set this to do not widen the logs.
 *
 * When set to 0, and logging is verbose, it looks like this
 *
 *    APDU:DEBUG:ReadECCurveList []
 *   smCom:DEBUG:Tx> (Len=4)
 *    80 02 0B 25
 *   smCom:DEBUG:<Rx (Len=23)
 *    41 82 00 11    01 01 02 01    01 01 01 01    01 01 01 01
 *    01 01 01 01    01 90 00
 *
 * When set to 1, same log looks like this
 *
 *       APDU:DEBUG:ReadECCurveList []
 *      smCom:DEBUG:Tx> (Len=4)
 * =>   80 02 0B 25
 *      smCom:DEBUG:<Rx (Len=23)
 * =>   41 82 00 11 01 01 02 01 01 01 01 01 01 01 01 01
 *    01 01 01 01 01 90 00
 *
 */
#define COMPRESSED_LOGGING_STYLE 0

/* Set this to 1 if you want colored logs with GCC based compilers */
#define USE_COLORED_LOGS 1

static const char *szLevel[] = {"ERROR", "WARN ", "INFO ", "DEBUG"};

#if AX_EMBEDDED
#define TAB_SEPRATOR "\t"
#else
#define TAB_SEPRATOR "   "
#endif

#if defined(SMCOM_JRCP_V2)
#include "smCom.h"
#endif

#if USE_LOCK
static uint8_t lockInitialised = false;
#endif

uint8_t nLog_Init(void)
{
	LINFLEXD_UART_DRV_Init(INST_LINFLEXD_UART1, &linflexd_uart1_State, &linflexd_uart1_InitConfig0);
    return 0;
}


void nLog_DeInit(void)
{
	LINFLEXD_UART_DRV_Deinit(INST_LINFLEXD_UART1);
}


void nLog(const char *comp, int level, const char *format, ...)
{
    if (level > (int)(sizeof(szLevel) / sizeof(char*))) {
        return;
    }
	setColor(level);
    if (level >= 1) {
		char buf[10];
		sprintf(buf, "%-6s:%s:", comp, szLevel[level-1]);
        PRINTF(buf);
    }
    else {
        reSetColor();
        return;
    }
	if (format == NULL) {
        /* Nothing */
#ifdef SMCOM_JRCP_V2
        smCom_Echo(NULL, comp, szLevel[level-1], "");
#endif // SMCOM_JRCP_V2
    }
    else if (format[0] == '\0') {
        /* Nothing */
#ifdef SMCOM_JRCP_V2
        smCom_Echo(NULL, comp, szLevel[level-1], "");
#endif // SMCOM_JRCP_V2
    }
    else {
        char buffer[256];
        size_t size_buff = sizeof(buffer) / sizeof(buffer[0]) - 1;
        va_list vArgs;
        va_start(vArgs, format);
        if ((vsnprintf(buffer, size_buff, format, vArgs)) < 0) {
            PRINTF("vsnprintf Error");
            reSetColor();
            return;
        }
        va_end(vArgs);
        PRINTF(buffer);
#ifdef SMCOM_JRCP_V2
        smCom_Echo(NULL, comp, szLevel[level-1], buffer);
#endif // SMCOM_JRCP_V2
    }
    reSetColor();
    PRINTF(szEOL);
}

void nLog_au8(const char *comp, int level, const char *message, const unsigned char *array, size_t array_len)
{
    size_t i;
    if (level > (int)(sizeof(szLevel) / sizeof(char*))) {
        return;
    }
    if (array_len > 0) {
        if (array == NULL) {
            return;
        }
    }
	setColor(level);
	if (level >= 1) {
		char buf[256];
        if (array_len > INT32_MAX) {
            reSetColor();
            return;
        }
		sprintf(buf, "%-6s:%s:%s (Len=%d)", comp, szLevel[level-1], message, (int)array_len);
        PRINTF(buf);
    }
    else {
        reSetColor();
        return;
    }
	for (i = 0; i < array_len; i++) {
		char buf[8];
        if (0 == (i % 16)) {
            PRINTF(szEOL);
            if (0 == i) {
#if COMPRESSED_LOGGING_STYLE
                PRINTF("=>");
#endif
                PRINTF(TAB_SEPRATOR);
            }
            else {
                PRINTF(TAB_SEPRATOR);
            }
        }
#if !COMPRESSED_LOGGING_STYLE
        if (0 == (i % 4)) {
            PRINTF(TAB_SEPRATOR);
        }
#endif
		sprintf(buf, "%02X ", array[i]);
        PRINTF(buf);
    }
    reSetColor();
    PRINTF(szEOL);
}

static void setColor(int level)
{
#if defined(__GNUC__) && !defined(__ARMCC_VERSION)
    ansi_setColor(level);
#endif
}

static void reSetColor()
{
#if USE_COLORED_LOGS
    PRINTF(COLOR_RESET);
#endif // USE_COLORED_LOGS
}

static void ansi_setColor(int level)
{
#if USE_COLORED_LOGS
    switch (level) {
    case NX_LEVEL_ERROR:
        PRINTF(COLOR_RED);
        break;
    case NX_LEVEL_WARN:
        PRINTF(COLOR_YELLOW);
        break;
    case NX_LEVEL_INFO:
        PRINTF(COLOR_BLUE);
        break;
    case NX_LEVEL_DEBUG:
        PRINTF(COLOR_GREEN);
        break;
    default:
        PRINTF(COLOR_RESET);
    }
#endif // USE_COLORED_LOGS
}

#endif

#ifdef __cplusplus
}
#endif
