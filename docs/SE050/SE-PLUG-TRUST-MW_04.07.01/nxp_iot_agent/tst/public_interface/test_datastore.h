/*
 * Copyright 2020-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NXP_IOT_AGENT_TEST_DATASTORE_
#define NXP_IOT_AGENT_TEST_DATASTORE_

#include <unity_fixture.h>
#include <nxp_iot_agent_datastore.h>
#include <Datastore.pb.h>
#include <nxp_iot_agent_utils_protobuf.h>

extern const uint8_t valid_datastore_contents[];
extern const size_t valid_datastore_content_size;

extern const uint8_t valid_datastore_contents_with_two_services[];
extern const uint8_t valid_datastore_contents_with_two_services_size;


void encode_datastore_request(uint8_t* buffer, size_t sz, nxp_iot_DatastoreRequest* request);
void write_and_commit_contents(iot_agent_datastore_t* datastore, const uint8_t* data, size_t len);
void write_and_commit_valid_contents(iot_agent_datastore_t* datastore);
void datastore_commit_test(iot_agent_datastore_t* datastore);

void datastore_complete_write_via_requests_test(iot_agent_datastore_t* datastore);

void datastore_invalid_request(iot_agent_datastore_t* datastore);
void datastore_corrupt_request(iot_agent_datastore_t* datastore);
void datastore_read_too_much(iot_agent_datastore_t* datastore);
bool datastore_execute_request(iot_agent_datastore_t* datastore, nxp_iot_DatastoreRequest* request, nxp_iot_DatastoreResponse* response);
bool datastore_execute_request_with_response_buffer(iot_agent_datastore_t* datastore, iot_agent_response_buffer_t* response_buffer,
	nxp_iot_DatastoreRequest* request, nxp_iot_DatastoreResponse* response);
void datastore_handle_allocate(iot_agent_datastore_t* datastore, size_t len);
void datastore_handle_write(iot_agent_datastore_t* datastore, const uint8_t* data, const size_t len);
void datastore_handle_commit(iot_agent_datastore_t* datastore);
void datastore_write_via_request_encode_fails(iot_agent_datastore_t* datastore);


TEST_GROUP(Datastore);
TEST_SETUP(Datastore);
TEST_TEAR_DOWN(Datastore);

#endif /* NXP_IOT_AGENT_TEST_DATASTORE_ */
