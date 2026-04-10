/* Copyright 2020 NXP
*
* SPDX-License-Identifier: Apache-2.0
*/

#include "sems_lite_api.h"
#if defined(SMCOM_JRCP_V2) && SSSFTR_SW_TESTCOUNTERPART
/* NXP Internal Testing */
#include "SEMS_Lite_UpgradeTo_iotDev-7_3_0_SIM.h"
#else // JRCP_V2
#include "SEMS_Lite_UpgradeTo_iotDev-7_3_0_A8FA.h"
#endif

/* doc:start:SEMS-Lite-protobuf-declare */

static const uint8_t aid_1[] = M_subComponent_1_aid;

static const sub_component_metaData_t subcomponent_1 = {
	.nameLen = \
		M_subComponent_1_nameLen,
	.pName = \
		M_subComponent_1_szName,
	.aidLen = \
		M_subComponent_1_aidLen,
	.pAid = \
		aid_1,
	.version = \
		M_subComponent_1_version,
	.swContentRegisterLen = \
		M_subComponent_1_SWContentRegisterLen,
	.pSWContentRegister = \
		M_subComponent_1_SWContentRegister,
	.minimumPreviousVersion = \
		M_subComponent_1_minimumPreviousVersion,
	.pNextSubComponentMetaData = \
		NULL,
};

static const uint8_t cmd_signature[] = M_signatureOverCommands;

static const uint8_t ca_public_key[] = M_pkSemsCaAut;

static const uint8_t commands[] = M_multicastCommands;

const multicast_package_t multicast_package = {
	.semsLiteAPIVersion = \
		M_semsLiteAPIVersion,
	.targetEntityID = \
		M_targetEntityID,
	.target12Nc = \
		M_target12Nc,
	.requiredFreeBytesNonVolatileMemory = \
		M_requiredFreeBytesNonVolatileMemory,
	.requiredFreeBytesTransientMemory = \
		M_requiredFreeBytesTransientMemory,
	.multicastPackageNameLen = \
		M_multicastPackageNameLen,
	.pMulticastPackageName = \
		M_szMulticastPackageName,
	.multicastPackageVersion = \
		M_multicastPackageVersion,
	.pSubComponentMetaData = \
		&subcomponent_1,
	.signatureOverCommandsLen = \
		M_signatureOverCommandsLen,
	.pSignatureOverCommands = \
		cmd_signature,
	.pkSemsCaAutLen = \
		M_pkSemsCaAutLen,
	.pPkSemsCaAut = \
		ca_public_key,
	.multicastCommandsLen = \
		M_multicastCommandsLen,
	.pMulticastCommands = \
		commands,
};

/* doc:end:SEMS-Lite-protobuf-declare */
