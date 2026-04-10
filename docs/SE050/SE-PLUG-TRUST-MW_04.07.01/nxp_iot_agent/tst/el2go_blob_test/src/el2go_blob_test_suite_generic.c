/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_blob_test_suite_generic.h"

/* TEST SUITE */

void testsuite_blob_generic(struct test_suite_t *test_suite)
{
    test_suite->name           = "GENERIC (EL2GO_BLOB_TEST_GENERIC_XXXX)";
    test_suite->test_list      = blob_generic_tests;
    test_suite->test_list_size = (sizeof(blob_generic_tests) / sizeof(blob_generic_tests[0]));
}
