/*
 * Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_BLOB_TEST_H__
#define __EL2GO_BLOB_TEST_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ZEPHYR__
#include <stdio.h>
#include <stdint.h>
#define LOG printf
#else
#include "fsl_debug_console.h"
#define LOG PRINTF
uint32_t get_uptime_ms(void);
#endif

enum serial_color_t
{
    DEFAULT = 0,
    RED     = 31,
    GREEN   = 32,
    YELLOW  = 33,
    BLUE    = 34,
    MAGENTA = 35,
    CYAN    = 36
};

#define LOG_SET_COLOR(color) LOG("\33" "[%dm", color)

enum indentation_t
{
    SUITE     = 0,
    TEST      = 2,
    VARIATION = 4
};

enum test_status_t
{
    TEST_PASSED  = 0,
    TEST_FAILED  = 1,
    TEST_SKIPPED = 2,
};

struct test_result_t
{
    enum test_status_t status;
    const char *message;
    const char *function;
    uint32_t line;
};

#define TEST_FAIL(msg)               \
    result->status   = TEST_FAILED;  \
    result->message  = msg;          \
    result->function = __FUNCTION__; \
    result->line     = __LINE__;

#define TEST_SKIP(msg)              \
    result->status  = TEST_SKIPPED; \
    result->message = msg;

typedef void TESTCASE(struct test_result_t *result);
struct test_t
{
    TESTCASE *const testcase;
    const char *name;
    const char *description;
    const uint8_t *data;
    uint32_t data_length;
};

struct test_suite_t;
typedef void TESTSUITE(struct test_suite_t *test_suite);
struct test_suite_t
{
    TESTSUITE *const suite;
    struct test_t *test_list;
    uint32_t test_list_size;
    const char *name;
    enum test_status_t status;
    uint32_t elapsed_time;
};

void testsuite_blob_generic(struct test_suite_t *test_suite);

#ifdef __cplusplus
}
#endif

#endif /* __EL2GO_BLOB_TEST_H__ */
