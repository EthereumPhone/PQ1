/*
* Copyright 2018-2021,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
*/

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <test_public_interface.h>
#include <test_agent_service.h>
#include <test_agent_utils.h>
#include <test_datastore.h>
#include <test_keystore.h>
#include <nxp_iot_agent.h>
#include <nxp_iot_agent_datastore.h>
#include <nxp_iot_agent_datastore_fs.h>
#include <nxp_iot_agent_keystore_sss_se05x.h>


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

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

static void runAllTests(void);

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

TEST_GROUP(PublicInterface);

TEST_SETUP(PublicInterface)
{
}

TEST_TEAR_DOWN(PublicInterface)
{
}

TEST(PublicInterface, DoInitContext)
{
	iot_agent_context_t iot_agent_context = { 0 };
	iot_agent_status_t init_status = iot_agent_init(&iot_agent_context);

	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, init_status);
	TEST_ASSERT_EQUAL_UINT(0, iot_agent_context.numKeystores);
	TEST_ASSERT_EQUAL_UINT(0, iot_agent_context.numDatastores);
}

TEST(PublicInterface, DoRegisterKeystore)
{
#if NXP_IOT_AGENT_HAVE_SSS
	iot_agent_context_t iot_agent_context = { 0 };
	iot_agent_keystore_t keystore = { 0 };
	uint32_t keystore_id = 0x1234; // freely choosable

	iot_agent_status_t agent_status = iot_agent_init(&iot_agent_context);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

    agent_status = iot_agent_keystore_sss_se05x_init(&keystore, keystore_id, NULL, false);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

    agent_status = iot_agent_register_keystore(&iot_agent_context, &keystore);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
    TEST_ASSERT_EQUAL_UINT(1, iot_agent_context.numKeystores);

    agent_status = iot_agent_keystore_free(&keystore);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

#else
    TEST_IGNORE_MESSAGE("Only with SE05X");
#endif
}

TEST(PublicInterface, DoRegisterDatastore)
{
	iot_agent_context_t iot_agent_context = { 0 };
	iot_agent_datastore_t datastore = { 0 };
	uint32_t datastore_id = 0x1234; // freely choosable

	iot_agent_status_t agent_status = iot_agent_init(&iot_agent_context);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

    agent_status = iot_agent_datastore_fs_init(&datastore, datastore_id, DATASTORE_BASENAME,
		&iot_agent_service_is_configuration_data_valid);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

    agent_status = iot_agent_register_datastore(&iot_agent_context, &datastore);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
    TEST_ASSERT_EQUAL_UINT(1, iot_agent_context.numDatastores);

    agent_status = iot_agent_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
 }

// ------------------------------------

TEST(PublicInterface, DoRegisterTooManyKeystores)
{
#if NXP_IOT_AGENT_HAVE_SSS
	iot_agent_context_t iot_agent_context = { 0 };
	iot_agent_keystore_t keystore[NXP_IOT_AGENT_MAX_NUM_KEYSTORES + 1U] = { 0 };
	iot_agent_status_t agent_status;

    agent_status = iot_agent_init(&iot_agent_context);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

    // Fill all available keystore slots + exceed the maximum number of keystores
	for (size_t i = 0U; i <= NXP_IOT_AGENT_MAX_NUM_KEYSTORES; i++)
	{
        agent_status = iot_agent_keystore_sss_se05x_init(&keystore[i], i, NULL, false);
        TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

        agent_status = iot_agent_register_keystore(&iot_agent_context, &keystore[i]);
        if (i != NXP_IOT_AGENT_MAX_NUM_KEYSTORES)
        {
            TEST_ASSERT_EQUAL_UINT(i + 1U, iot_agent_context.numKeystores);
            TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
        }
        else
        {
            TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
        }
    }

	for (size_t i = 0U; i <= NXP_IOT_AGENT_MAX_NUM_KEYSTORES; i++)
	{
		iot_agent_keystore_free(&keystore[i]);
	}
#else
    TEST_IGNORE_MESSAGE("Only with SE05X");
#endif
}


TEST(PublicInterface, DoRegisterTooManyDatastores)
{
	iot_agent_context_t iot_agent_context = { 0 };

	iot_agent_datastore_t datastore[NXP_IOT_AGENT_MAX_NUM_DATASTORES + 1] = { 0 };

    iot_agent_status_t agent_status;
    agent_status = iot_agent_init(&iot_agent_context);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	// Fill all available datastore slots + 1
	for (size_t i = 0U; i <= NXP_IOT_AGENT_MAX_NUM_DATASTORES; i++)
	{
		agent_status = iot_agent_datastore_fs_init(&datastore[i], (int32_t)i, DATASTORE_BASENAME,
			&iot_agent_service_is_configuration_data_valid);
        TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

        agent_status = iot_agent_register_datastore(&iot_agent_context, &datastore[i]);
        if (i != NXP_IOT_AGENT_MAX_NUM_DATASTORES)
        {
            TEST_ASSERT_EQUAL_UINT(i+1U, iot_agent_context.numDatastores);
            TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
        }
        else
        {
            TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
        }

        agent_status = iot_agent_datastore_free(&datastore[i]);
        TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
    }
}

TEST(PublicInterface, DoUpdateConfigFromConstants)
{
	iot_agent_context_t iot_agent_context = { 0 };
	//iot_agent_keystore_t keystore = { 0 };
	iot_agent_status_t agent_status = IOT_AGENT_FAILURE;

	agent_status = iot_agent_update_device_configuration_from_constants(&iot_agent_context, NULL);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
}


TEST(PublicInterface, DoGetDataStoreById)
{
	iot_agent_context_t iot_agent_context = { 0 };
	iot_agent_status_t agent_status = IOT_AGENT_FAILURE;

	iot_agent_datastore_t datastore = { 0 };
	uint32_t datastore_id = 7;

	agent_status = iot_agent_datastore_fs_init(&datastore, datastore_id, DATASTORE_BASENAME,
		&iot_agent_service_is_configuration_data_valid);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_register_datastore(&iot_agent_context, &datastore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	iot_agent_datastore_t* retrieved_datastore = NULL;
	agent_status = iot_agent_get_datastore_by_id(&iot_agent_context, datastore_id, &retrieved_datastore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
	TEST_ASSERT(&datastore == retrieved_datastore);
}


TEST(PublicInterface, DoIsServiceConfigurationValid)
{
	iot_agent_context_t iot_agent_context = { 0 };
	iot_agent_status_t agent_status = IOT_AGENT_FAILURE;

	iot_agent_datastore_t datastore = { 0 };
	uint32_t datastore_id = 7;

	agent_status = iot_agent_datastore_fs_init(&datastore, datastore_id, DATASTORE_BASENAME,
		&iot_agent_service_is_configuration_data_valid);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_register_datastore(&iot_agent_context, &datastore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	bool valid = iot_agent_is_service_configuration_data_valid(&iot_agent_context);
	TEST_ASSERT_FALSE(valid);

	agent_status = iot_agent_datastore_allocate(&datastore, valid_datastore_content_size);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_datastore_write(&datastore, 0, valid_datastore_contents, valid_datastore_content_size);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	valid = iot_agent_is_service_configuration_data_valid(&iot_agent_context);
	TEST_ASSERT_TRUE(valid);
}

static void print_binary_data(const char* info, const uint8_t* buf, size_t len) {
	size_t i;
	printf("%-20s length: %d\n        ", info, (int)len);
	for (i = 0; i < len;) {
		printf("%02x", buf[i]);
		++i;

		if ((i % 16) == 0) {
			printf("\n        ");
		}
	}
	printf("\n");
}

TEST(PublicInterface, DoSelectServiceById)
{
	iot_agent_context_t iot_agent_context = { 0 };
	iot_agent_status_t agent_status = IOT_AGENT_FAILURE;


	iot_agent_datastore_t datastore = { 0 };
	uint32_t datastore_id = 7;

	nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;

	agent_status = iot_agent_datastore_fs_init(&datastore, datastore_id, DATASTORE_BASENAME,
		&iot_agent_service_is_configuration_data_valid);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_register_datastore(&iot_agent_context, &datastore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_select_service_by_id(&iot_agent_context, 1, &service_descriptor);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);

	agent_status = iot_agent_datastore_allocate(&datastore, valid_datastore_contents_with_two_services_size);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_datastore_write(&datastore, 0, valid_datastore_contents_with_two_services, valid_datastore_contents_with_two_services_size);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	agent_status = iot_agent_select_service_by_id(&iot_agent_context, 1, &service_descriptor);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

	iot_agent_free_service_descriptor(&service_descriptor);
}


TEST_GROUP_RUNNER(PublicInterface)
{
	RUN_TEST_CASE(PublicInterface, DoInitContext);
	RUN_TEST_CASE(PublicInterface, DoRegisterKeystore);
	RUN_TEST_CASE(PublicInterface, DoRegisterDatastore);
	RUN_TEST_CASE(PublicInterface, DoRegisterTooManyKeystores);
	RUN_TEST_CASE(PublicInterface, DoRegisterTooManyDatastores);
	RUN_TEST_CASE(PublicInterface, DoUpdateConfigFromConstants);
	RUN_TEST_CASE(PublicInterface, DoGetDataStoreById);
	RUN_TEST_CASE(PublicInterface, DoIsServiceConfigurationValid);
	RUN_TEST_CASE(PublicInterface, DoSelectServiceById);
}

int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, runAllTests);
}

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

static void runAllTests(void)
{
    RUN_TEST_GROUP(PublicInterface);
	RUN_TEST_GROUP(AgentDispatcher);
	RUN_TEST_GROUP(AgentService);
#if IOT_AGENT_TIME_MEASUREMENT_ENABLE
	RUN_TEST_GROUP(AgentTime);
#endif
	RUN_TEST_GROUP(AgentUtils);
	RUN_TEST_GROUP(Datastore);
	RUN_TEST_GROUP(DatastoreFS);
	RUN_TEST_GROUP(Keystore);
}
