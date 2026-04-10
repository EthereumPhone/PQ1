/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_BLOB_TEST_PARSER_H__
#define __EL2GO_BLOB_TEST_PARSER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "el2go_blob_test.h"

/**
 * \brief Parse and run corresponding test of a blob
 *
 * \param[in]  blob         The data of a raw EL2GO blob
 * \param[in]  blob_length  Size of the data of a raw EL2GO blob
 * \param[out] result       Test result
 *
 */
void parse_and_run_test(const uint8_t *blob, size_t blob_length, struct test_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* __EL2GO_BLOB_TEST_PARSER_H__ */
