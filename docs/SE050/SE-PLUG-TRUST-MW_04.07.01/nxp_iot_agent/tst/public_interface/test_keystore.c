/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <nxp_iot_agent.h>
#include <nxp_iot_agent_keystore.h>
#include <nxp_iot_agent_macros.h>
#include <pb.h>
#include <pb_encode.h>
#include <test_keystore.h>

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

TEST_SETUP(Keystore)
{
}


TEST_TEAR_DOWN(Keystore)
{
}


static iot_agent_status_t fail(void* context)
{
	AX_UNUSED_ARG(context);
	return IOT_AGENT_FAILURE;
}


TEST(Keystore, FreeFails)
{
	iot_agent_keystore_t keystore = { 0 };
	keystore.iface.destroy = &fail;
	iot_agent_status_t agent_status = iot_agent_keystore_free(&keystore);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_FAILURE, agent_status);
}


TEST_GROUP_RUNNER(Keystore)
{
	RUN_TEST_CASE(Keystore, FreeFails);
}
