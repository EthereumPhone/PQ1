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
 * @file plaform_function.h
 * @brief Declaration of platform functions that users need to implement.
 */
#ifndef PLATFORM_FUNCTION_H
#define PLATFORM_FUNCTION_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Thread handle data structure definition.
 */
typedef void * FRTestThreadHandle_t;

/**
 * @brief Thread function to be executed in ThreadCreate_t function.
 *
 * @param[in] pParam The pParam parameter passed in ThreadCreate_t function.
 */
typedef void ( * FRTestThreadFunction_t )( void * pParam );

/**
 * @brief Delay function to wait for at least specified amount of time.
 *
 * @param[in] delayMs Delay in milliseconds.
 */
void FRTest_TimeDelay( uint32_t delayMs );

/**
 * @brief Function to get time elapsed in milliseconds since a given epoch.
 * 
 * @note The timer should be a monotonic timer. It just needs to provide an
 * incrementing count of milliseconds elapsed since a given epoch.
 * 
 * @return Time elapsed since the given epoch in milliseconds.
 */
uint32_t FRTest_GetTimeMs( void );

/**
 * @brief Thread create function for test application.
 *
 * @param[in] threadFunc The thread function to be executed in the created thread.
 * @param[in] pParam The pParam parameter passed to the thread function pParam parameter.
 *
 * @return NULL if create thread failed. Otherwise, return the handle of the created thread.
 */
FRTestThreadHandle_t FRTest_ThreadCreate( FRTestThreadFunction_t threadFunc,
                                          void * pParam );

/**
 * @brief Timed thread join function to wait for the created thread exit.
 *
 * @param[in] threadHandle The handle of the created thread to be waited.
 * @param[in] timeoutMs The timeout value of to wait for the created thread exit.
 *
 * @return 0 if the thread exits within timeoutMs. Other value will be regarded as error.
 */
int FRTest_ThreadTimedJoin( FRTestThreadHandle_t threadHandle,
                            uint32_t timeoutMs );

/**
 * @brief Malloc function to allocate memory for test.
 *
 * @param[in] size Size in bytes.
 */
void * FRTest_MemoryAlloc( size_t size );

/**
 * @brief Free function to free memory allocated by FRTest_MemoryAlloc function.
 *
 * @param[in] size Size in bytes.
 */
void FRTest_MemoryFree( void * ptr );

/**
 * @brief To generate random number in INT format.
 *
 * @return A random number.
 */
int FRTest_GenerateRandInt();

#endif /* PLATFORM_FUNCTION_H */
