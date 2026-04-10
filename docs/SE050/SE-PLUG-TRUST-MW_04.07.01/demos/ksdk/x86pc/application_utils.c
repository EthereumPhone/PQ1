/*
 * Amazon FreeRTOS V1.4.0
 * Copyright (C) 2017 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 * Copyright 2021 NXP
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
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/*
 * Setup information:
 *
 * See the following URL for information on using FreeRTOS and FreeRTOS+TCP in
 * a Windows environment.  **NOTE**  The project described on the link is not
 * the project that is implemented in this file, but the setup is the same.  It
 * may also be necessary to have WinPCap installed (https://www.winpcap.org/):
 * http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/examples_FreeRTOS_simulator.html.
 *
 * It is necessary to use a wired Ethernet port.  Wireless ports are unlikely
 * to work.
 */

#include <stdio.h>
#include <time.h>
#include <conio.h>

/* FreeRTOS includes. */
#include <FreeRTOS.h>
#include "task.h"

/* Notes if the trace is running or not. */
static BaseType_t xTraceRunning = pdTRUE;

/*
 * Writes trace data to a disk file when the trace recording is stopped.
 * This function will simply overwrite any trace files that already exist.
 */
static void prvSaveTraceFile(void);

/*
 * Miscellaneous initialization including preparing the logging and seeding the
 * random number generator.
 */
void prvMiscInitialisation(void);

/*-----------------------------------------------------------*/
void vAssertCalled(const char *pcFile, uint32_t ulLine)
{
    const uint32_t ulLongSleep = 1000UL;
    volatile uint32_t ulBlockVariable = 0UL;
    volatile char *pcFileName = (volatile char *)pcFile;
    volatile uint32_t ulLineNumber = ulLine;

    (void)pcFileName;
    (void)ulLineNumber;

    printf("vAssertCalled %s, %ld\n", pcFile, (long)ulLine);
    fflush(stdout);

    /* Setting ulBlockVariable to a non-zero value in the debugger will allow
     * this function to be exited. */
    taskDISABLE_INTERRUPTS();
    {
        while (ulBlockVariable == 0UL) {
            Sleep(ulLongSleep);
        }
    }
    taskENABLE_INTERRUPTS();
}
/*-----------------------------------------------------------*/

void vApplicationIdleHook(void)
{
    const uint32_t ulMSToSleep = 1;
    const TickType_t xKitHitCheckPeriod = pdMS_TO_TICKS(1000UL);
    static TickType_t xTimeNow, xLastTimeCheck = 0;

    /* vApplicationIdleHook() will only be called if configUSE_IDLE_HOOK is set
     * to 1 in FreeRTOSConfig.h.  It will be called on each iteration of the idle
     * task.  It is essential that code added to this hook function never attempts
     * to block in any way (for example, call xQueueReceive() with a block time
     * specified, or call vTaskDelay()).  If application tasks make use of the
     * vTaskDelete() API function to delete themselves then it is also important
     * that vApplicationIdleHook() is permitted to return to its calling function,
     * because it is the responsibility of the idle task to clean up memory
     * allocated by the kernel to any task that has since deleted itself. */

    /* _kbhit() is a Windows system function, and system functions can cause
     * crashes if they somehow block the FreeRTOS thread.  The call to _kbhit()
     * can be removed if it causes problems.  Limiting the frequency of calls to
     * _kbhit() should minimize the potential for issues. */
    xTimeNow = xTaskGetTickCount();

    if ((xTimeNow - xLastTimeCheck) > xKitHitCheckPeriod) {
        if (_kbhit() != pdFALSE) {
            if (xTraceRunning == pdTRUE) {
                xTraceRunning = pdFALSE;
#if configUSE_TRACE_FACILITY
                vTraceStop();
#endif // configUSE_TRACE_FACILITY
                prvSaveTraceFile();
            }
        }

        xLastTimeCheck = xTimeNow;
    }

    /* This is just a trivial example of an idle hook.  It is called on each
     * cycle of the idle task if configUSE_IDLE_HOOK is set to 1 in
     * FreeRTOSConfig.h.  It must *NOT* attempt to block.  In this case the
     * idle task just sleeps to lower the CPU usage. */
    Sleep(ulMSToSleep);
}
/*-----------------------------------------------------------*/

/**
 * @brief Warn user if pvPortMalloc fails.
 *
 * Called if a call to pvPortMalloc() fails because there is insufficient
 * free memory available in the FreeRTOS heap.  pvPortMalloc() is called
 * internally by FreeRTOS API functions that create tasks, queues, software
 * timers, and semaphores.  The size of the FreeRTOS heap is set by the
 * configTOTAL_HEAP_SIZE configuration constant in FreeRTOSConfig.h.
 *
 */
void vApplicationMallocFailedHook()
{
    taskDISABLE_INTERRUPTS();
    for (;;)
        ;
}
/*-----------------------------------------------------------*/

static void prvSaveTraceFile(void)
{
#if configUSE_TRACE_FACILITY
    FILE *pxOutputFile;

    fopen_s(&pxOutputFile, "Trace.dump", "wb");

    if (pxOutputFile != NULL) {
        fwrite(RecorderDataPtr, sizeof(RecorderDataType), 1, pxOutputFile);
        fclose(pxOutputFile);
        printf("\r\nTrace output saved to Trace.dump\r\n");
    }
    else {
        printf("\r\nFailed to create trace dump file\r\n");
    }
#endif // configUSE_TRACE_FACILITY
}
/*-----------------------------------------------------------*/

void prvMiscInitialisation(void)
{
    /* Initialise the trace recorder and create the label used to post user
     * events to the trace recording on each tick interrupt. */
#if configUSE_TRACE_FACILITY
    vTraceEnable(TRC_START);
#endif // configUSE_TRACE_FACILITY
}

#if defined(configFRTOS_MEMORY_SCHEME) && (configFRTOS_MEMORY_SCHEME == 4)
void *pvPortCalloc(size_t num, size_t size)
{
    void *ptr;

    ptr = pvPortMalloc(num * size);
    if (!ptr)
    {
        extern void vApplicationMallocFailedHook(void);
        vApplicationMallocFailedHook();
    }
    else
    {
        memset(ptr, 0, num * size);
    }
    return ptr;
}
#else // HEAP_3
void *pvPortCalloc(size_t num, size_t size)
{
    void *pvReturn;

    vTaskSuspendAll();
    {
        pvReturn = calloc(num, size);
        traceMALLOC(pvReturn, xWantedSize);
    }
    (void)xTaskResumeAll();

#if (configUSE_MALLOC_FAILED_HOOK == 1)
    {
        if (pvReturn == NULL)
        {
            extern void vApplicationMallocFailedHook(void);
            vApplicationMallocFailedHook();
        }
    }
#endif

    return pvReturn;
}
#endif // configFRTOS_MEMORY_SCHEME


/*-----------------------------------------------------------*/