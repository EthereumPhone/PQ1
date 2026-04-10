/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
//#include "test_public_interface.h"
#include "test_agent_service.h"
#include <nxp_iot_agent.h>
#include <nxp_iot_agent_datastore_fs.h>
#include <nxp_iot_agent_keystore_sss_se05x.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#define TEST_ROOT_FOLDER "."
#define NUMBER_OF_PROTOCOL_SERVICES 7U //7 Protocol Services are available
#define NUMBER_OF_SERVICES 6U          //7 Service Services are available

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

//static void runAllTests(void);

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

//TEST_GROUP(AgentService);

TEST_SETUP(AgentService)
{
}

TEST_TEAR_DOWN(AgentService)
{
}

TEST(AgentService, GetProtocolNameOfService)
{
    const char *buffer = "empty";
    char protocolNameOfService[NUMBER_OF_PROTOCOL_SERVICES][7] = {
        "HTTPS", "MQTTS", "AMQPS", "XMPP", "DDS", "COAP", "empty"};
    char *protocolName = NULL;
    iot_agent_context_t iot_agent_context = {0};
    nxp_iot_ServiceDescriptor service_descriptor =
        nxp_iot_ServiceDescriptor_init_default;
    nxp_iot_ServiceDescriptor *service_descriptor_pointer = &service_descriptor;

    //Set a protocol
    service_descriptor_pointer->has_protocol = true;

    iot_agent_status_t agent_status = iot_agent_init(&iot_agent_context);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

    for (size_t iService = 0U; iService < NUMBER_OF_PROTOCOL_SERVICES; iService++) {
        protocolName = protocolNameOfService[iService];

        //Services are starting from 1
        service_descriptor.protocol = (nxp_iot_ServiceProtocolType)(iService + 1U);
        agent_status = iot_agent_service_get_protocol_of_service_as_string(
            &service_descriptor, &buffer);

        // If the protocol name is empty or doesn't equal one of the given names,
        // function returns an IOT_AGENT_FAILURE
        if (strcmp(protocolName, "empty") != 0) {
            TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
            //check for the right protocol Name
            TEST_ASSERT_EQUAL_STRING((const char *)(protocolName), buffer);
        }
        else {
            TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
        }
    }
}

TEST(AgentService, GetServiceNameOfService)
{
    const char *buffer = "empty";
    char serviceNameOfService[NUMBER_OF_SERVICES][7] = {
        "aws", "google", "azure", "ibm", "custom", "empty"};
    char *serviceName = NULL;

    iot_agent_context_t iot_agent_context = {0};
    nxp_iot_ServiceDescriptor service_descriptor =
        nxp_iot_ServiceDescriptor_init_default;

    nxp_iot_ServiceDescriptor *service_descriptor_pointer = &service_descriptor;

    iot_agent_status_t agent_status = iot_agent_init(&iot_agent_context);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

    //Set a has_service_type to false
    service_descriptor_pointer->has_service_type = false;
    agent_status = iot_agent_service_get_service_type_as_string(
        &service_descriptor, &buffer);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);

    //run through all Service names
    service_descriptor_pointer->has_service_type = true;

    for (size_t iService = 0U; iService < NUMBER_OF_SERVICES; iService++) {
        //set Name to compare out of predefined list
        serviceName = serviceNameOfService[iService];

        //Services are starting from 0
        if (iService == 4U) {
            service_descriptor.service_type = nxp_iot_ServiceType_CUSTOMSERVICE; //custom service
        }
        else {
            service_descriptor.service_type = (nxp_iot_ServiceType)iService;
        }

        agent_status = iot_agent_service_get_service_type_as_string(
            &service_descriptor, &buffer);

        // If the service type is empty or doesn't equal one of the given names,
        // function returns an IOT_AGENT_FAILURE
        if (strcmp(serviceName, "empty") != 0) {
            TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
            //check for corrct service type
            TEST_ASSERT_EQUAL_STRING((const char *)(serviceName), buffer);
        }
        else {
            TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
        }
    }
}

TEST(AgentService, GetServiceDescriptorOfService)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    iot_agent_datastore_t datastore = {0};
    /* has to be located in
	simw-top\bin-se50\windows\nxp_iot_agent\tst\public_interface,
	has to be copied by Jenkins script!*/
    const char *gszDatastoreFilename = "datastore.bin";
    size_t offset = 0;
    nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;

	//allocate and initialises the datastore
    agent_status = iot_agent_datastore_fs_init(
        &datastore,
        0,
        gszDatastoreFilename,
        &iot_agent_service_is_configuration_data_valid);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);

    //calls function to test
    agent_status = iot_agent_service_get_service_descriptor_of_service(
        &datastore, offset, &service_descriptor);
    TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
	}


TEST_GROUP_RUNNER(AgentService)
{
    RUN_TEST_CASE(AgentService, GetProtocolNameOfService);
    RUN_TEST_CASE(AgentService, GetServiceNameOfService);
    RUN_TEST_CASE(AgentService, GetServiceDescriptorOfService);
}
