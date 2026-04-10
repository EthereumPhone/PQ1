/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_BLOB_TEST_SUITE_GENERIC_H__
#define __EL2GO_BLOB_TEST_SUITE_GENERIC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "el2go_blob_test.h"

// These are placeholder blobs
// Refer to el2go_blob_test.readme for how to generate device specific ones

static const uint8_t PLACEHOLDER_BLOB[] = {0};

static struct test_t blob_generic_tests[] = {
    {NULL, "EL2GO_BLOB_TEST_GENERIC_0001", "PLACEHOLDER_BLOB", PLACEHOLDER_BLOB, sizeof(PLACEHOLDER_BLOB)}};

#ifdef __cplusplus
}
#endif

#endif /* __EL2GO_BLOB_TEST_SUITE_GENERIC_H__ */
