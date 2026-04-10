/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file */

#ifndef SEMS_LITE_AGENT_COMMON_INC
#define SEMS_LITE_AGENT_COMMON_INC

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * ***************************************************************************************************************** */

#ifndef __DOXYGEN__

#define SEMS_LITE_AGENT_KEYSTORE_ID 1

#define SEMS_LITE_AGENT_STATUS_WORD_INIT 0xFFFFFFFF
#define SEMS_LITE_AGENT_STATUS_WORD_HOST_CMD_OK 0xFFFF9000
#define SEMS_LITE_AGENT_STATUS_WORD_HOST_CMD_MASK 0xFFFF0000
#define SEMS_LITE_AGENT_STATUS_WORD_COM_FAILURE 0xF0000000
#define SEMS_LITE_AGENT_STATUS_WORD_USER_DEFINE_SUCCESS 0xF8000000

#define SEMS_LITE_AGENT_INVLAID_VERSION_MSB 0xFF
#define SEMS_LITE_AGENT_INVLAID_VERSION_LSB 0xFF

#define SEMS_LITE_AGENT_INVALID_FREE_COD 0xFFFFFFFF

#define SEMS_LITE_MAX_SUBCOMPONENT_NUMBER 6

//#define SEMS_LITE_AGENT_CHANNEL_1 0x01
//#define SEMS_LITE_AGENT_CHANNEL_0 0x00

//#define SEMS_LITE_AGENT_SKIP_MEMORY_CHECK 1
#endif /* __DOXYGEN__ */

/**
 * @addtogroup sems_lite_agent_types
 * @{
 */

/** Status of SEMS Lite update operation */
typedef enum _sems_lite_status
{
    /** Operation was successful */
    kStatus_SEMS_Lite_Success = 0x00,
    /** Communication Error */
    kStatus_SEMS_Lite_ERR_COM,
    /** Update not completed please provide update package again. */
    kStatus_SEMS_Lite_ERR_DoReRun,
    /** Update not applicable on this Chip/type. */
    kStatus_SEMS_Lite_ERR_NotApplicable,
    /** Update can not be completed. Please provide recovery package, to roll back to last working version. */
    kStatus_SEMS_Lite_ERR_DoRecovery,
    /** Unresolvable error. */
    kStatus_SEMS_Lite_ERR_Fatal,
    /** Not enough NV memory. */
    kStatus_SEMS_Lite_ERR_NotEnoughNVMemory,
    /** Not enough transient memory. */
    kStatus_SEMS_Lite_ERR_NotEnoughTransientMemory,
    /** Current SE version not meet min previous version request. */
    kStatus_SEMS_Lite_ERR_MinPreviousVersion,
    /** Older than current SE version */
    kStatus_SEMS_Lite_ERR_OlderVersion,
    /** General error. */
    kStatus_SEMS_Lite_ERR_General
} sems_lite_status_t;

/** Status of SEMS Lite version check result */
typedef enum _sems_lite_version_check_result_t
{
    /** Operation was successful */
    kStatus_SEMS_Lite_Version_Pass = 0x00,
    /** Failed due to min previous version. */
    kStatus_SEMS_Lite_Version_ERR_MIN,
    /** Failed due to downgrade. */
    kStatus_SEMS_Lite_Version_ERR_Downgrade
} sems_lite_version_check_result_t;

/**
 *@}
 */ /* end of sems_lite_agent_types */

#endif // !SEMS_LITE_AGENT_COMMON_INC
