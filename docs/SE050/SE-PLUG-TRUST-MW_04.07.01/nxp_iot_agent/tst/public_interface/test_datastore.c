/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <nxp_iot_agent.h>
#include <nxp_iot_agent_datastore.h>
#include <nxp_iot_agent_macros.h>
#include <pb.h>
#include <pb_encode.h>
#include <Datastore.pb.h>
#include <test_datastore.h>
#include <test_agent_service.h>


/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

const uint8_t valid_datastore_contents[] = {
		0xfb, 0x11, 0xa2, 0x3b, 0xdb, 0x79, 0x03, 0x26, 0x10, 0x14, 0xc4, 0x9a,
		0x43, 0x89, 0x94, 0x87, 0x7c, 0x18, 0x79, 0x1e, 0x99, 0x87, 0x19, 0x4b,
		0x6e, 0x9c, 0x92, 0xdd, 0x8b, 0xd5, 0x06, 0xe3, 0x36, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x09, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
const size_t valid_datastore_content_size = sizeof(valid_datastore_contents);

const uint8_t valid_datastore_contents_with_two_services[] = {
	0x7b, 0xa6, 0xcf, 0xe1, 0xc4, 0x5b, 0x46, 0xfb, 0x01, 0xd2, 0x32, 0x7a, 0xcb, 0xa1, 0x58, 0x7c,
	0x2d, 0x2f, 0x00, 0xdc, 0x79, 0x8c, 0xae, 0x00, 0x10, 0x9d, 0xc9, 0x95, 0x67, 0xeb, 0x1f, 0x7d,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0x09, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const uint8_t valid_datastore_contents_with_two_services_size = sizeof(valid_datastore_contents_with_two_services);



static const uint8_t garbage[] = { 1, 2, 3 };

void encode_datastore_request(uint8_t* buffer, size_t sz, nxp_iot_DatastoreRequest* request)
{
	nxp_iot_RequestPayload request_payload = nxp_iot_RequestPayload_init_default;
	request_payload.which_payload = nxp_iot_RequestPayload_datastore_tag;
	request_payload.payload.datastore = *request;

	pb_ostream_t ostream = pb_ostream_from_buffer(buffer, sz);
	pb_encode(&ostream, nxp_iot_RequestPayload_fields, &request_payload);
}

void write_and_commit_contents(iot_agent_datastore_t* datastore, const uint8_t* data, size_t len) {
	iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
	agent_status = iot_agent_datastore_allocate(datastore, len);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_datastore_write(datastore, 0U, data, len);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_datastore_commit(datastore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
}

void write_and_commit_valid_contents(iot_agent_datastore_t* datastore)
{
	write_and_commit_contents(datastore, valid_datastore_contents, sizeof(valid_datastore_contents));
}

void datastore_commit_test(iot_agent_datastore_t* datastore)
{
	configuration_data_header_t header1 = { 0 };
	configuration_data_header_t header2 = { 0 };
	configuration_data_header_t header3 = { 0 };

	configuration_data_header_t header_read = { 0 };

	iot_agent_status_t agent_status = IOT_AGENT_FAILURE;

	size_t total_size_read = 0U;
	size_t string_equal = 1U;

	memset(header1.checksum, 1U, sizeof(header1.checksum));
	memset(header2.checksum, 2U, sizeof(header2.checksum));
	memset(header2.checksum, 3U, sizeof(header3.checksum));

	// allocate, write and commit to datastore header 1
	agent_status = iot_agent_datastore_allocate(datastore, sizeof(header1));
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	agent_status = iot_agent_datastore_write(datastore, 0U, &header1, sizeof(header1));
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	agent_status = iot_agent_datastore_commit(datastore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	// the data that is read back needs to be header 1 - the same as the data written
	// to the datastore
	total_size_read = sizeof(header_read);
	agent_status = iot_agent_datastore_read(datastore, &header_read, 0U, &total_size_read);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	TEST_ASSERT_EQUAL_UINT(sizeof(header_read), total_size_read);
	string_equal = strcmp((char *)header1.checksum, (char *)header_read.checksum);
	TEST_ASSERT_EQUAL_UINT(0U, string_equal);

	// allocate and write to datastore header 2
	agent_status = iot_agent_datastore_allocate(datastore, sizeof(header2));
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	agent_status = iot_agent_datastore_write(datastore, 0U, &header2, sizeof(header2));
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	// no commit, a read must still result in header 1 to be returned
	total_size_read = sizeof(header_read);
	agent_status = iot_agent_datastore_read(datastore, &header_read, 0U, &total_size_read);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	TEST_ASSERT_EQUAL_UINT(sizeof(header_read), total_size_read);
	string_equal = strcmp((char *)header1.checksum, (char *)header_read.checksum);
	TEST_ASSERT_EQUAL_UINT(0U, string_equal);

	// allocate and write to datastore header 3 - this would discard the write
	// of header 2
	agent_status = iot_agent_datastore_allocate(datastore, sizeof(header3));
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	agent_status = iot_agent_datastore_write(datastore, 0U, &header3, sizeof(header3));
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	// as long as there is no commit, it still shall return header 1
	total_size_read = sizeof(header_read);
	agent_status = iot_agent_datastore_read(datastore, &header_read, 0U, &total_size_read);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	TEST_ASSERT_EQUAL_UINT(sizeof(header_read), total_size_read);
	string_equal = strcmp((char *)header1.checksum, (char *)header_read.checksum);
	TEST_ASSERT_EQUAL_UINT(0U, string_equal);

	// this commit finishes the write of header 3
	agent_status = iot_agent_datastore_commit(datastore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	// now the contents shall be header 3
	total_size_read = sizeof(header_read);
	agent_status = iot_agent_datastore_read(datastore, &header_read, 0U, &total_size_read);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	string_equal = strcmp((char *)header3.checksum, (char *)header_read.checksum);
	TEST_ASSERT_EQUAL_UINT(0U, string_equal);
}

static bool decode_responses(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
	AX_UNUSED_ARG(field);
	nxp_iot_ResponsePayload* response_payload = (nxp_iot_ResponsePayload*)(*arg);

	if (!pb_decode(stream, nxp_iot_ResponsePayload_fields, response_payload))
		return false;

	return true;
}

bool datastore_execute_request_with_response_buffer(iot_agent_datastore_t* datastore, iot_agent_response_buffer_t* response_buffer,
	nxp_iot_DatastoreRequest* request, nxp_iot_DatastoreResponse* response)
{
	uint8_t request_buffer[1024] = { 0 };

	pb_ostream_t reqstream = pb_ostream_from_buffer(request_buffer, sizeof(request_buffer));
	pb_encode_delimited(&reqstream, nxp_iot_DatastoreRequest_fields, request);

	pb_istream_t istream = pb_istream_from_buffer(request_buffer, sizeof(request_buffer));
	pb_ostream_t ostream = pb_ostream_from_response_buffer(response_buffer);
	datastore->iface.endpoint_interface.handle_request(&istream, &ostream, nxp_iot_DatastoreRequest_fields, datastore->context);

	pb_istream_t respstream = pb_istream_from_buffer(response_buffer->start, response_buffer->remaining);
	nxp_iot_ResponsePayload response_payload = nxp_iot_ResponsePayload_init_default;
	nxp_iot_Responses responses = nxp_iot_Responses_init_default;
	responses.responses.funcs.decode = &decode_responses;
	responses.responses.arg = &response_payload;
	bool response_decoded = pb_decode(&respstream, nxp_iot_Responses_fields, &responses);
	response_decoded &= (pb_size_t)nxp_iot_ResponsePayload_datastore_tag == response_payload.which_message;
	*response = response_payload.message.datastore;
	return response_decoded;
}

bool datastore_execute_request(iot_agent_datastore_t* datastore, nxp_iot_DatastoreRequest* request, nxp_iot_DatastoreResponse* response)
{
	uint8_t response_buffer_memory[1024] = { 0 };
	size_t response_buffer_size = sizeof(response_buffer_memory);

	iot_agent_response_buffer_t response_buffer = { 0 };
	response_buffer.start = response_buffer_memory;
	response_buffer.pos = response_buffer.start;
	response_buffer.remaining = response_buffer_size;

	return datastore_execute_request_with_response_buffer(datastore, &response_buffer, request, response);
}


void datastore_handle_allocate(iot_agent_datastore_t* datastore, size_t len)
{
	nxp_iot_DatastoreRequest request = nxp_iot_DatastoreRequest_init_default;
	request.has_operation = true;
	request.operation = nxp_iot_DatastoreOperation_ALLOCATE;
	request.has_length = true;
	request.length = len;

	nxp_iot_DatastoreResponse response = nxp_iot_DatastoreResponse_init_default;
	bool result = datastore_execute_request(datastore, &request, &response);
	TEST_ASSERT_TRUE(result);
	TEST_ASSERT_TRUE(response.has_status);
	TEST_ASSERT_EQUAL_INT(nxp_iot_DatastoreStatus_OK, response.status);
}


void datastore_handle_write(iot_agent_datastore_t* datastore, const uint8_t* data, const size_t len)
{
	buffer_t read_buffer = { 0 };
	read_buffer.buf = (uint8_t*)data;
	read_buffer.len = len;

	nxp_iot_DatastoreRequest request = nxp_iot_DatastoreRequest_init_default;
	request.has_operation = true;
	request.operation = nxp_iot_DatastoreOperation_WRITE;
	request.data.funcs.encode = &encode_byte_field;
	request.data.arg = &read_buffer;

	nxp_iot_DatastoreResponse response = nxp_iot_DatastoreResponse_init_default;
	bool result = datastore_execute_request(datastore, &request, &response);
	TEST_ASSERT_TRUE(result);
	TEST_ASSERT_TRUE(response.has_status);
	TEST_ASSERT_EQUAL_INT(nxp_iot_DatastoreStatus_OK, response.status);
}


void datastore_handle_commit(iot_agent_datastore_t* datastore)
{
	nxp_iot_DatastoreRequest request = nxp_iot_DatastoreRequest_init_default;
	request.has_operation = true;
	request.operation = nxp_iot_DatastoreOperation_COMMIT;

	nxp_iot_DatastoreResponse response = nxp_iot_DatastoreResponse_init_default;
	bool result = datastore_execute_request(datastore, &request, &response);
	TEST_ASSERT_TRUE(result);
	TEST_ASSERT_TRUE(response.has_status);
	TEST_ASSERT_EQUAL_INT(nxp_iot_DatastoreStatus_OK, response.status);
}


void datastore_complete_write_via_requests_test(iot_agent_datastore_t* datastore)
{
	// Invalidate datastore contents.
	write_and_commit_contents(datastore, garbage, sizeof(garbage));

	// Fill the datastore via requests message with valid content.
	datastore_handle_allocate(datastore, sizeof(valid_datastore_contents));
	datastore_handle_write(datastore, valid_datastore_contents, sizeof(valid_datastore_contents));
	datastore_handle_commit(datastore);

	bool is_valid = iot_agent_service_is_configuration_data_valid(datastore);
	TEST_ASSERT_TRUE(is_valid);
}


void datastore_write_via_request_encode_fails(iot_agent_datastore_t* datastore)
{
	buffer_t read_buffer = { 0 };
	read_buffer.buf = (uint8_t*)valid_datastore_contents;
	read_buffer.len = sizeof(valid_datastore_contents);

	nxp_iot_DatastoreRequest request = nxp_iot_DatastoreRequest_init_default;
	request.has_operation = true;
	request.operation = nxp_iot_DatastoreOperation_WRITE;
	request.data.funcs.encode = &encode_byte_field;
	request.data.arg = &read_buffer;

	iot_agent_response_buffer_t response_buffer = { 0 };
	nxp_iot_DatastoreResponse response = nxp_iot_DatastoreResponse_init_default;
	bool result = datastore_execute_request_with_response_buffer(datastore, &response_buffer, &request, &response);
	TEST_ASSERT_FALSE(result);
}


void datastore_invalid_request(iot_agent_datastore_t* datastore) {
	pb_istream_t istream = pb_istream_from_buffer(NULL, 0);
	bool result = datastore->iface.endpoint_interface.handle_request(&istream, NULL, NULL, NULL);
	TEST_ASSERT_FALSE(result);
}


void datastore_corrupt_request(iot_agent_datastore_t* datastore) {
	uint8_t buffer[64];
	size_t sz = sizeof(buffer);

	nxp_iot_DatastoreRequest request = nxp_iot_DatastoreRequest_init_default;
	request.has_length = true;
	request.has_length = 0x7F;
	encode_datastore_request(buffer, sz, &request);

	// corrupt the message so we can not decode it (but keep the message type intact)
	// make the length field be interpreted as string, this will cause decoding issues
	// together with the value of the length from above, this will read out of the buffer
	buffer[2] = 0x40 | PB_WT_STRING;

	pb_istream_t istream = pb_istream_from_buffer(buffer, sz);
	bool result = datastore->iface.endpoint_interface.handle_request(&istream, NULL, nxp_iot_DatastoreRequest_fields, NULL);
	TEST_ASSERT_FALSE(result);
}


void datastore_read_too_much(iot_agent_datastore_t* datastore) {
	nxp_iot_DatastoreRequest request = nxp_iot_DatastoreRequest_init_default;
	request.has_operation = true;
	request.operation = nxp_iot_DatastoreOperation_READ;
	request.has_length = true;
	request.length = 128;

	uint8_t response_buffer_memory[64];
	iot_agent_response_buffer_t response_buffer = { 0 };
	response_buffer.start = response_buffer_memory;
	response_buffer.pos = response_buffer.start;
	response_buffer.remaining = sizeof(response_buffer_memory);

	nxp_iot_DatastoreResponse response = nxp_iot_DatastoreResponse_init_default;
	bool result = datastore_execute_request_with_response_buffer(datastore, &response_buffer, &request, &response);
	TEST_ASSERT_FALSE(result);
}


TEST_SETUP(Datastore)
{
}


TEST_TEAR_DOWN(Datastore)
{
}


static iot_agent_status_t fail(void* context)
{
	AX_UNUSED_ARG(context);
	return IOT_AGENT_FAILURE;
}

TEST(Datastore, FreeFails)
{
	iot_agent_datastore_t datastore = { 0 };
	datastore.iface.destroy = &fail;
	iot_agent_status_t agent_status = iot_agent_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
}


TEST(Datastore, EncodeResponseFails)
{
	pb_ostream_t ostream = pb_ostream_from_buffer(NULL, 0);
	bool result = iot_agent_datastore_encode_datastore_ok_response(&ostream);
	TEST_ASSERT_FALSE(result);
}


TEST_GROUP_RUNNER(Datastore)
{
	RUN_TEST_CASE(Datastore, FreeFails);
	RUN_TEST_CASE(Datastore, EncodeResponseFails);
}
