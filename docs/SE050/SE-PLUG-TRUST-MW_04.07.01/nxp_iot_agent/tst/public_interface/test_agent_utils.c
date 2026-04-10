/*
 * Copyright 2018-2019,2021-2022,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

 /* ************************************************************************** */
 /* Includes                                                                   */
 /* ************************************************************************** */
 //#include "test_public_interface.h"
#include "test_agent_utils.h"
#include <nxp_iot_agent.h>
#include <nxp_iot_agent_utils.h>
#include <nxp_iot_agent_utils_internal.h>
#include <nxp_iot_agent_datastore_fs.h>
#include <nxp_iot_agent_keystore_sss_se05x.h>
#include <nxp_iot_agent_session.h>
#include <nxp_iot_agent_macros.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#define TEST_ROOT_FOLDER "."
#define NUMBER_OF_PROTOCOL_SERVICES 7 //7 Protocol Services are available
#define NUMBER_OF_SERVICES 6          //7 Service Services are available

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

#if NXP_IOT_AGENT_HAVE_SSS
static ex_sss_boot_ctx_t gex_sss_boot_ctx;
#endif

//static void runAllTests(void);

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

//TEST_GROUP(AgentService);

TEST_SETUP(AgentUtils)
{
}

TEST_TEAR_DOWN(AgentUtils)
{
}


TEST(AgentUtils, WriteCertificatePem)
{
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    const char* filename = "certificatePem.bin";
    uint8_t buffer_content = 12;
    uint8_t *buffer = &buffer_content;
    size_t len = sizeof(buffer);
    iot_agent_status_t agent_status = iot_agent_utils_write_certificate_pem(
        buffer, len, filename);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

#endif
}

TEST(AgentUtils, KeyFileExistence)
{
#if !(AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1)
    const char *filename = "Keystore.bin";
    bool forceCreation = true;
    iot_agent_status_t agent_status = IOT_AGENT_FAILURE;

	agent_status = iot_agent_keystore_file_existence(filename, forceCreation);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
#endif
}

TEST(AgentUtils, ConvertService2KeyId)
{
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    uint64_t serviceId = 1;
    uint32_t keyId = 1;
	iot_agent_status_t agent_status = iot_agent_utils_convert_service2key_id( serviceId,  &keyId);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
#endif
}


static bool encode_expect_field(pb_ostream_t *ostream, const pb_field_t *field, void *const *arg)
{
	AX_UNUSED_ARG(arg);
	pb_encode_tag_for_field(ostream, field);
	pb_encode_varint(ostream, 1);

	pb_encode_tag_for_field(ostream, field);
	pb_encode_varint(ostream, 2);

	pb_encode_tag_for_field(ostream, field);
	pb_encode_varint(ostream, 3);
	return true;
}


TEST(AgentUtils, DecodeExpectField)
{
	uint8_t buffer[128] = { 0 };
	uint16_t expectations_memory[2] = { 0 };

	nxp_iot_ApduRequest encode_request = nxp_iot_ApduRequest_init_default;
	encode_request.expectation.arg = NULL;
	encode_request.expectation.funcs.encode = &encode_expect_field;

	// This callback creates a message with three expectations, we only have space for two.
	// So we expect the first two to be decoded correctly, but the final decoding result to
	// be false (since there is more which is skipped).
	pb_ostream_t ostream = pb_ostream_from_buffer(buffer, sizeof(buffer));
	pb_encode(&ostream, nxp_iot_ApduRequest_fields, &encode_request);

	nxp_iot_ApduRequest request = nxp_iot_ApduRequest_init_default;
	expectation_t expectations = { 0 };
	expectations.buf = (uint8_t*)expectations_memory;
	expectations.len = sizeof(expectations_memory);
	expectations.offset = 0;

	request.expectation.funcs.decode = &decode_expect_field;
	request.expectation.arg = &expectations;

	pb_istream_t istream = pb_istream_from_buffer(buffer, sizeof(buffer));
	bool decode_result = pb_decode(&istream, nxp_iot_ApduRequest_fields, &request);

	TEST_ASSERT_EQUAL_HEX16(1u, expectations_memory[0]);
	TEST_ASSERT_EQUAL_HEX16(2u, expectations_memory[1]);
	TEST_ASSERT_FALSE(decode_result);
}


TEST(AgentUtils, VerifyReturnValue)
{
	uint16_t expectations_memory[2] = { 1, 2 };
	expectation_t expectations = { 0 };
	expectations.buf = (uint8_t*)expectations_memory;
	expectations.len = sizeof(expectations_memory);
	expectations.offset = sizeof(expectations_memory);

	bool result = verify_return_value(1, &expectations);
	TEST_ASSERT_TRUE(result);

	result = verify_return_value(7, NULL);
	TEST_ASSERT_FALSE(result);

	result = verify_return_value(7, &expectations);
	TEST_ASSERT_FALSE(result);
}


TEST_GROUP_RUNNER(AgentUtils)
{
	RUN_TEST_CASE(AgentUtils, KeyFileExistence);
	RUN_TEST_CASE(AgentUtils, WriteCertificatePem);
	RUN_TEST_CASE(AgentUtils, ConvertService2KeyId);
	RUN_TEST_CASE(AgentUtils, DecodeExpectField);
	RUN_TEST_CASE(AgentUtils, VerifyReturnValue);
}
