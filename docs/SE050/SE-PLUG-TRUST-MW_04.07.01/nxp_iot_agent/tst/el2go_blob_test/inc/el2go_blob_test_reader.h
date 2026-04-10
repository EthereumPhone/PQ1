/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_BLOB_TEST_READER_H__
#define __EL2GO_BLOB_TEST_READER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "el2go_blob_test.h"

#define TEST_FAIL_READER(msg)                \
    LOG_SET_COLOR(RED);                      \
    LOG("Failed to read blob: %s\r\n", msg); \
    TEST_FAIL(NULL)

/**
 * \brief Gets raw EL2GO blob data from location information data
 *
 * \param[in]  data         Data which is or points to a location of an EL2GO blob
 * \param[in]  data_length  Size of the data which is or points to a location of an EL2GO blob
 * \param[out] blob         The data of a raw EL2GO blob
 * \param[out] blob_length  Size of the data of a raw EL2GO blob
 * \param[out] result       Test result
 *
 */
void read_blob_data(
    const uint8_t *data, size_t data_length, uint8_t **blob, size_t *blob_length, struct test_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* __EL2GO_BLOB_TEST_READER_H__ */
