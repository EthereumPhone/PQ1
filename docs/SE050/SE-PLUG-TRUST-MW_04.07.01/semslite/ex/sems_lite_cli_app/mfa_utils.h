/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#ifndef MFA_UTILS_H_INCLUDED
#define MFA_UTILS_H_INCLUDED

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <sems_lite_agent_context.h>

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

extern ex_sss_boot_ctx_t gfeature_app_sems_lite_boot_ctx;
extern sems_lite_agent_ctx_t g_sems_lite_agent_load_ctx;

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Function declarations                                                      */
/* ************************************************************************** */

void printSEMSLiteStatusCode(sems_lite_status_t sems_lite_status);
void print_SSS_StatusCode(sss_status_t sss_stat);
void print_hex_contents(
    const char *contentsName, uint8_t *contents, size_t contentsLen);
uint8_t *hexstr_to_bytes(const char *str, size_t *len);
void tst_asymm_alloc_and_set_key(sss_object_t *keyObject,
    sss_key_store_t *ks,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    uint32_t keyId,
    const uint8_t *key,
    size_t keyByteLen,
    size_t keyBitLen,
    uint32_t options);
void initialise_allocate_key_object(sss_object_t *Key,
    sss_key_store_t *ks,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options);

#endif /* MFA_UTILS_H_INCLUDED */
