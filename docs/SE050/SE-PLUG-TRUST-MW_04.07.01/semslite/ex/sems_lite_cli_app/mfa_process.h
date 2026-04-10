/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#ifndef MFA_PROCESS_H_INCLUDED
#define MFA_PROCESS_H_INCLUDED

#include <stdint.h>

#include "./protobuf/Agent.pb.h"
#include "./protobuf/Dispatcher.pb.h"
#include "./protobuf/pb.h"
#include "./protobuf/pb_decode.h"
#include "./protobuf/pb_encode.h"
#include "sems_lite_api.h"

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/*********************************************************************************
* Binary File format
* 0x21	Len								multicastPackage
* 	|-	0x22	Len	Major	Minor				MulticastPackageFormatVersion
* 	|-	0x23	Len	Binary					TargetEntityID
*   |-  0x2F	Len	Binary					Target12nc
*   |-  0x31	Len	Binary					PkSemsCaAut
* 	|-	0x24	Len	u32/u16					requiredFreeBytesNonVolatileMemory
* 	|-	0x25	Len	u32/u16					requiredFreeBytesTransientMemory
* 	|-	0x26	Len	String					MulticastPackageName
* 	|-	0x27	Len	Major	Minor				MulticastPackageVersion
* 	|-	0x28	Len						SubComponentMetaData
* 	|-		|-	0x2B	Len	String			SubComponentMetaData.name 1
* 	|-		|-	0x2C	Len	Binary			SubComponentMetaData.aid 1
* 	|-		|-	0x2D	Len	Major	Minor	SubComponentMetaData.version 1
* 	|-		|-	0x30	Len	String  		SubComponentMetaData.SWContentRegister 1
* 	|-		|-	0x2E	Len	Major	Minor	SubComponentMetaData.minimumPreviousVersion 1
* 	|-		|-	0x2B	Len	String			SubComponentMetaData.name 2
* 	|-		|-	0x2C	Len	Binary			SubComponentMetaData.aid 2
* 	|-		|-	0x2D	Len	Major	Minor		SubComponentMetaData.version 2
* 	|-		|-	0x30	Len	String  		SubComponentMetaData.SWContentRegister 2
* 	|-		|-	0x2E	Len	Major	Minor	SubComponentMetaData.minimumPreviousVersion 2
* 	|-		|-	0x2B	Len	String			SubComponentMetaData.name N
* 	|-		|-	0x2C	Len	Binary			SubComponentMetaData.aid N
* 	|-		|-	0x30	Len	String  		SubComponentMetaData.SWContentRegister N
* 	|-		|-	0x2E	Len	Major	Minor	SubComponentMetaData.minimumPreviousVersion N
* 	|-		|-	0x2D	Len	Major	Minor		SubComponentMetaData.version N
* 	|-	0x29	Len	Binary					SignatureOverCommands
* 	|-	0x2A	Len	Binary					MulticastCommands
**********************************************************************************/
typedef enum
{
    /** Invalid */
    SEMS_LITE_TAG_NA = 0,
    SEMS_LITE_TAG_MULTTICAST_PACKAGE = 0x21,
    SEMS_LITE_TAG_MULTICAST_PACKAGE_FORMAT_VERSION = 0x22,
    SEMS_LITE_TAG_TARGET_ENTITY_ID = 0x23,
    SEMS_LITE_TAG_REQUIRED_FREE_BYTES_NON_VOLATILE_MEMORY = 0x24,
    SEMS_LITE_TAG_REQUIRED_FREE_BYTES_TRANSIENT_MEMORY = 0x25,
    SEMS_LITE_TAG_MULTICAST_PACKAGE_NAME = 0x26,
    SEMS_LITE_TAG_MULTICAST_PACKAGE_VERSION = 0x27,
    SEMS_LITE_TAG_SUBCOMPONENT_META_DATA = 0x28,
    SEMS_LITE_TAG_SIGNATURE_OVER_COMMANDS = 0x29,
    SEMS_LITE_TAG_MULTICAST_COMMANDS = 0x2A,
    SEMS_LITE_TAG_SUBCOMPONENT_META_DATA_NAME = 0x2B,
    SEMS_LITE_TAG_SUBCOMPONENT_META_DATA_AID = 0x2C,
    SEMS_LITE_TAG_SUBCOMPONENT_META_DATA_VERSION = 0x2D,
    SEMS_LITE_TAG_SUBCOMPONENT_MINI_PREVIOUS_VERSION = 0x2E,
    SEMS_LITE_TAG_TARGET_12_NC = 0x2F,
    SEMS_LITE_TAG_SUBCOMPONENT_SW_CONTENT_REGISTER = 0x30,
    SEMS_LITE_TAG_CA_PUB_KEY = 0x31,
} SEMS_LITE_BIN_PKG_TAG_t;

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* clang-format off */

/* clang-format on */

/* ************************************************************************** */
/* Function declarations                                                      */
/* ************************************************************************** */

void mfa_process_loadpkg(const char *);
void mfa_process_getuid();
void mfa_process_getcardcontents(const char *);
void mfa_process_getPbkeyId();
void mfa_process_semslitegetversion();
void mfa_process_getsignature(const char *);
void mfa_process_checkTear();
void mfa_process_checkUpgradeProgress();
void mfa_process_getENCIdentifier();
void mfa_process_getappcontents(const char *);
void mfa_process_getpkgcontents(const char *);
void mfa_process_getCAIdentifier();
void mfa_process_getCAKeyIdentifier();
void mfa_process_getPkgVerion(const char *pkgAid);
void mfa_process_getFreePHeap();
sss_status_t mfa_process_parse_binary(uint8_t * buffer,
    size_t buffer_size,
    multicast_package_t * package,
    sub_component_metaData_t * subcomponent);
void mfa_process_getECParameter();
void mfa_process_getFIPSInfo();

#endif //MFA_PROCESS_H_INCLUDED
