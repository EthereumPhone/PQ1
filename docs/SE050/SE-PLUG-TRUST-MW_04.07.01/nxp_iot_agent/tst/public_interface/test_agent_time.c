/*
 * Copyright 2020-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <test_agent_time.h>

#include <nxp_iot_agent.h>
#include <nxp_iot_agent_time.h>

#if IOT_AGENT_TIME_MEASUREMENT_ENABLE

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

TEST_SETUP(AgentTime)
{
}

TEST_TEAR_DOWN(AgentTime)
{
}

TEST(AgentTime, LogPerformance)
{
	iot_agent_status_t agent_status = iot_agent_log_performance_timing();
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
}


TEST_GROUP_RUNNER(AgentTime)
{
   RUN_TEST_CASE(AgentTime, LogPerformance);
}

#endif