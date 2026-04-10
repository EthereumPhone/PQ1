/*
 * Copyright 2020-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <test_agent_dispatcher.h>
#include <nxp_iot_agent_macros.h>
#include <nxp_iot_agent_dispatcher.h>
#include <pb_encode.h>
#include <pb_decode.h>
#include <Agent.pb.h>


/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static iot_agent_dispatcher_context_t dispatcher_context = { 0 };
static uint8_t response_buffer_memory[128];
static iot_agent_response_buffer_t response_buffer = { 0 };
static handle_request_payload_args_t handle_request_args = { 0 };
static nxp_iot_EndpointRequest endpoint_request = { 0 };

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

static void encode_hello_request(uint8_t* buffer, size_t sz, nxp_iot_AgentHelloRequest* request)
{
	nxp_iot_RequestPayload request_payload = nxp_iot_RequestPayload_init_default;
	request_payload.which_payload = nxp_iot_RequestPayload_hello_tag;
	request_payload.payload.hello = *request;

	pb_ostream_t ostream = pb_ostream_from_buffer(buffer, sz);
	pb_encode(&ostream, nxp_iot_RequestPayload_fields, &request_payload);
}


static void encode_apdu_request(uint8_t* buffer, size_t sz, nxp_iot_ApduRequest* request)
{
	nxp_iot_RequestPayload request_payload = nxp_iot_RequestPayload_init_default;
	request_payload.which_payload = nxp_iot_RequestPayload_apdu_tag;
	request_payload.payload.apdu = *request;

	pb_ostream_t ostream = pb_ostream_from_buffer(buffer, sz);
	pb_encode(&ostream, nxp_iot_RequestPayload_fields, &request_payload);
}


static bool get_no_endpoint_info(void *context, void* endpoint_information)
{
	AX_UNUSED_ARG(context);
	AX_UNUSED_ARG(endpoint_information);
	return false;
}

static bool fail_handle_request(pb_istream_t *istream,
	pb_ostream_t *ostream, const pb_field_t* message_type, void *context) {
	AX_UNUSED_ARG(istream);
	AX_UNUSED_ARG(ostream);
	AX_UNUSED_ARG(message_type);
	AX_UNUSED_ARG(context);
	return false;
}


static bool encode_broken_endpoint_request(pb_ostream_t *ostream, const pb_field_t *field, void* const* arg)
{
	AX_UNUSED_ARG(field);
	AX_UNUSED_ARG(arg);
	pb_encode_tag(ostream, PB_WT_STRING, nxp_iot_Requests_payload_tag);
	pb_encode_varint(ostream, INT_MAX);
	return true;
}



/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

TEST_SETUP(AgentDispatcher)
{
	memset(&dispatcher_context, 0, sizeof(dispatcher_context));
	memset(&response_buffer, 0, sizeof(response_buffer));
	memset(&endpoint_request, 0, sizeof(endpoint_request));

	response_buffer.start = response_buffer_memory;
	response_buffer.pos = response_buffer.start;
	response_buffer.remaining = sizeof(response_buffer_memory);

	endpoint_request.has_type = true;
	endpoint_request.type = nxp_iot_EndpointType_AGENT;
	endpoint_request.has_endpointId = true;
	endpoint_request.endpointId = 0;

	handle_request_args.dispatcher_context = &dispatcher_context;
	handle_request_args.response_buffer = &response_buffer;

	dispatcher_context.stream_type = STREAM_TYPE_NETWORK;
	dispatcher_context.successful_crl_verification_done = true;
	dispatcher_context.current_request = &endpoint_request;
}

TEST_TEAR_DOWN(AgentDispatcher)
{
}


TEST(AgentDispatcher, InvalidMessageBeforeCrlVerification)
{
#if NXP_IOT_AGENT_REQUEST_CRL_FROM_EDGELOCK_2GO

	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_ApduRequest request = nxp_iot_ApduRequest_init_default;
	encode_apdu_request(buffer, sz, &request);

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	void* addr_handle_request_args = &handle_request_args;

	dispatcher_context.successful_crl_verification_done = false;
	bool result = handle_request_payload(&istream, NULL, &addr_handle_request_args);

	TEST_ASSERT_FALSE(result);
#endif
}


TEST(AgentDispatcher, InvalidHelloMessage)
{
	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_AgentHelloRequest hello_request = nxp_iot_AgentHelloRequest_init_default;
	hello_request.has_version = true;
	hello_request.version = 0x7F;
	encode_hello_request(buffer, sz, &hello_request);

	// corrupt the message so we can not decode it (but keep the message type intact)
	// make the version field be interpreted as string, this will cause decoding issues
	// together with the value of the version from above, this will read out of the buffer
	buffer[2] = 0x40 | PB_WT_STRING;

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	void* addr_handle_request_args = &handle_request_args;
	bool result = handle_request_payload(&istream, NULL, &addr_handle_request_args);

	TEST_ASSERT_FALSE(result);
}


TEST(AgentDispatcher, EmptyHelloResponse)
{
	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_AgentHelloRequest hello_request = nxp_iot_AgentHelloRequest_init_default;
	encode_hello_request(buffer, sz, &hello_request);

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	void* addr_handle_request_args = &handle_request_args;
	bool result = handle_request_payload(&istream, NULL, &addr_handle_request_args);

	TEST_ASSERT_TRUE(result);
}


TEST(AgentDispatcher, InvalidEndpointTypeInResponse)
{
	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_AgentHelloRequest hello_request = nxp_iot_AgentHelloRequest_init_default;
	encode_hello_request(buffer, sz, &hello_request);

	dispatcher_context.endpoints[0].id = 0;
	dispatcher_context.endpoints[0].type = nxp_iot_EndpointType_AGENT;
	dispatcher_context.endpoints[0].endpoint_interface.get_endpoint_information = &get_no_endpoint_info;

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	void* addr_handle_request_args = &handle_request_args;
	bool result = handle_request_payload(&istream, NULL, &addr_handle_request_args);

	TEST_ASSERT_FALSE(result);
}


TEST(AgentDispatcher, EncodingResponsesFails)
{
	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_AgentHelloRequest hello_request = nxp_iot_AgentHelloRequest_init_default;
	encode_hello_request(buffer, sz, &hello_request);

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	void* addr_handle_request_args = &handle_request_args;

	response_buffer.remaining = 0;
	bool result = handle_request_payload(&istream, NULL, &addr_handle_request_args);

	TEST_ASSERT_FALSE(result);
}


TEST(AgentDispatcher, MissingEndpointType)
{
	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_ApduRequest request = nxp_iot_ApduRequest_init_default;
	encode_apdu_request(buffer, sz, &request);

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	void* addr_handle_request_args = &handle_request_args;

	dispatcher_context.current_request->has_type = false;
	bool result = handle_request_payload(&istream, NULL, &addr_handle_request_args);

	TEST_ASSERT_FALSE(result);
}


TEST(AgentDispatcher, MissingEndpointId)
{
	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_ApduRequest request = nxp_iot_ApduRequest_init_default;
	encode_apdu_request(buffer, sz, &request);

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	void* addr_handle_request_args = &handle_request_args;

	dispatcher_context.current_request->has_endpointId = false;
	bool result = handle_request_payload(&istream, NULL, &addr_handle_request_args);

	TEST_ASSERT_FALSE(result);
}


TEST(AgentDispatcher, EndpointNotFound)
{
	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_ApduRequest request = nxp_iot_ApduRequest_init_default;
	encode_apdu_request(buffer, sz, &request);

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	void* addr_handle_request_args = &handle_request_args;

	dispatcher_context.current_request->endpointId = 1;
	bool result = handle_request_payload(&istream, NULL, &addr_handle_request_args);

	TEST_ASSERT_FALSE(result);
}


TEST(AgentDispatcher, EndpointCantHandleRequest)
{
	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_ApduRequest request = nxp_iot_ApduRequest_init_default;
	encode_apdu_request(buffer, sz, &request);

	dispatcher_context.endpoints[0].id = 0;
	dispatcher_context.endpoints[0].type = nxp_iot_EndpointType_AGENT;
	dispatcher_context.endpoints[0].endpoint_interface.get_endpoint_information = &get_no_endpoint_info;
	dispatcher_context.endpoints[0].endpoint_interface.handle_request = &fail_handle_request;

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	void* addr_handle_request_args = &handle_request_args;
	bool result = handle_request_payload(&istream, NULL, &addr_handle_request_args);

	TEST_ASSERT_FALSE(result);
}


TEST(AgentDispatcher, InvalidRequests)
{
	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_Requests requests = nxp_iot_Requests_init_default;
	requests.payload.funcs.encode = &encode_broken_endpoint_request;

	pb_ostream_t ostream = pb_ostream_from_buffer(buffer, sz);
	pb_encode(&ostream, nxp_iot_Requests_fields, &requests);

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);

	void* addr_handle_request_args = &handle_request_args;
	bool result = handle_requests(&istream, NULL, &addr_handle_request_args);
	TEST_ASSERT_FALSE(result);
}


TEST(AgentDispatcher, NetworkStreamError)
{
	uint8_t buffer[64] = { 0 };
	size_t sz = sizeof(buffer);

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	iot_agent_status_t agent_status = iot_agent_dispatcher(&dispatcher_context, &istream, NULL);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
}


TEST(AgentDispatcher, BufferStream)
{
	uint8_t buffer[64] = { 0 };
	size_t sz = sizeof(buffer);

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	dispatcher_context.stream_type = STREAM_TYPE_BUFFER_REQUESTS;
	iot_agent_status_t agent_status = iot_agent_dispatcher(&dispatcher_context, &istream, NULL);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
}


TEST(AgentDispatcher, BufferStreamError)
{
	uint8_t buffer[64] = { 0 };
	size_t sz = sizeof(buffer);

	pb_ostream_t ostream = pb_ostream_from_buffer(buffer, sz);
	pb_encode_varint(&ostream, INT_MAX);

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	dispatcher_context.stream_type = STREAM_TYPE_BUFFER_REQUESTS;
	iot_agent_status_t agent_status = iot_agent_dispatcher(&dispatcher_context, &istream, NULL);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
}


TEST(AgentDispatcher, InvalidStreamType)
{
	dispatcher_context.stream_type = STREAM_TYPE_BUFFER_REQUESTS + 1;
	iot_agent_status_t agent_status = iot_agent_dispatcher(&dispatcher_context, NULL, NULL);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
}


TEST_GROUP_RUNNER(AgentDispatcher)
{
	RUN_TEST_CASE(AgentDispatcher, InvalidMessageBeforeCrlVerification);
	RUN_TEST_CASE(AgentDispatcher, InvalidHelloMessage);
	RUN_TEST_CASE(AgentDispatcher, EmptyHelloResponse);
	RUN_TEST_CASE(AgentDispatcher, InvalidEndpointTypeInResponse);
	RUN_TEST_CASE(AgentDispatcher, EncodingResponsesFails);
	RUN_TEST_CASE(AgentDispatcher, MissingEndpointType);
	RUN_TEST_CASE(AgentDispatcher, MissingEndpointId);
	RUN_TEST_CASE(AgentDispatcher, EndpointNotFound);
	RUN_TEST_CASE(AgentDispatcher, EndpointCantHandleRequest);
	RUN_TEST_CASE(AgentDispatcher, InvalidRequests);
	RUN_TEST_CASE(AgentDispatcher, NetworkStreamError);
	RUN_TEST_CASE(AgentDispatcher, BufferStream);
	RUN_TEST_CASE(AgentDispatcher, BufferStreamError);
	RUN_TEST_CASE(AgentDispatcher, InvalidStreamType);
}
