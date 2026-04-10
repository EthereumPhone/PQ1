/*
 * Copyright 2018-2021,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <test_datastore_fs.h>

#include <nxp_iot_agent.h>
#include <nxp_iot_agent_datastore_fs.h>
#include <test_datastore.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#define TEST_ROOT_FOLDER "."
#define DATASTORE_BASENAME "datastore_file.bin"

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static iot_agent_datastore_t datastore = { 0 };

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

static void remove_datastore_files(char* basename)
{
	size_t filename_size = strlen(basename) + 16U;
	char* filename = malloc(filename_size);
	for (int i = 0; i < 2; i++) {
		sprintf(filename, "%s.%u", basename, i);
		remove(filename);
	}
	free(filename);
}

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

TEST_SETUP(DatastoreFS)
{
	iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
	agent_status = iot_agent_datastore_fs_init(&datastore, 0,
		DATASTORE_BASENAME, &iot_agent_service_is_configuration_data_valid);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
}

TEST_TEAR_DOWN(DatastoreFS)
{
	iot_agent_datastore_free(&datastore);
	remove_datastore_files(DATASTORE_BASENAME);
}

TEST(DatastoreFS, AntiTearing)
{
	datastore_commit_test(&datastore);
}


TEST(DatastoreFS, WriteViaProtobuf)
{
	datastore_complete_write_via_requests_test(&datastore);
}


TEST(DatastoreFS, InvalidRequest)
{
	datastore_invalid_request(&datastore);
}


TEST(DatastoreFS, CorruptRequest)
{
	datastore_corrupt_request(&datastore);
}


TEST(DatastoreFS, ReadTooMuch)
{
	uint8_t dummy_data[512] = {0};
	write_and_commit_contents(&datastore, dummy_data, sizeof(dummy_data));
	datastore_read_too_much(&datastore);
}


TEST(DatastoreFS, PickValidFile)
{
	iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
	iot_agent_datastore_t local_datastore = { 0 };
	iot_agent_datastore_fs_context_t* datastore_context = NULL;
	uint8_t garbage[] = { 0, 1, 2, 3 };

	char *datastore_file = "datastore_file_PickValidFile.bin";

	agent_status = iot_agent_datastore_fs_init(&local_datastore, 0,
		datastore_file, &iot_agent_service_is_configuration_data_valid);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	// invalidate both copies of the contents of the datastore
	write_and_commit_contents(&local_datastore, garbage, sizeof(garbage));
	write_and_commit_contents(&local_datastore, garbage, sizeof(garbage));

	// close the datastore, both copies are invalid
	iot_agent_datastore_free(&local_datastore);

	// re-open the datastore
	agent_status = iot_agent_datastore_fs_init(&local_datastore, 0,
		datastore_file, &iot_agent_service_is_configuration_data_valid);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	// fill the datastore with valid contents
	write_and_commit_valid_contents(&local_datastore);

	// close the datastore
	iot_agent_datastore_free(&local_datastore);

	// re-open the datastore, we expect to have valid contents, coming from copy 1
	agent_status = iot_agent_datastore_fs_init(&local_datastore, 0,
		datastore_file, &iot_agent_service_is_configuration_data_valid);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	datastore_context = (iot_agent_datastore_fs_context_t*)local_datastore.context;
	TEST_ASSERT_EQUAL_UINT(1, datastore_context->idx_read);

	// fill the datastore with valid contents
	write_and_commit_valid_contents(&local_datastore);

	// close the datastore, copy 0 is valid
	iot_agent_datastore_free(&local_datastore);

	// re-open the datastore, we expect to have valid contents, coming from copy 0
	agent_status = iot_agent_datastore_fs_init(&local_datastore, 0,
		datastore_file, &iot_agent_service_is_configuration_data_valid);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	datastore_context = (iot_agent_datastore_fs_context_t*)local_datastore.context;
	TEST_ASSERT_EQUAL_UINT(0, datastore_context->idx_read);

	remove_datastore_files(datastore_file);
}


TEST_GROUP_RUNNER(DatastoreFS)
{
   RUN_TEST_CASE(DatastoreFS, AntiTearing);
   RUN_TEST_CASE(DatastoreFS, WriteViaProtobuf);
   RUN_TEST_CASE(DatastoreFS, InvalidRequest);
   RUN_TEST_CASE(DatastoreFS, CorruptRequest);
   RUN_TEST_CASE(DatastoreFS, ReadTooMuch);
   RUN_TEST_CASE(DatastoreFS, PickValidFile);
}
