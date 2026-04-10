/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SEMS_LITE_API_H_INC
#define SEMS_LITE_API_H_INC

#include <fsl_sss_se05x_types.h>
#include <sems_lite_agent_common.h>
#include <sems_lite_agent_context.h>
#include <sm_types.h>

#include "sems_lite_api_ver.h"
#include "fsl_sss_api.h"
#include "nxLog.h"
#include "nxScp03_Types.h"

/* *****************************************************************************************************************
 * Global Variables
 * ***************************************************************************************************************** */
#define SEMS_LITE_API_VERSION_MAJOR SEMS_LITE_AGENT_VER_MAJOR
#define SEMS_LITE_API_VERSION_MINOR SEMS_LITE_AGENT_VER_MINOR
#define SEMS_LITE_API_VERSION_PATCH SEMS_LITE_AGENT_VER_DEV

#define SEMS_LITE_GET_DATA_CMD_BUF_LEN (256 + 5)

#define SEMS_LITE_PKG_VERSION_LEN 2

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * ***************************************************************************************************************** */

/**
 * @addtogroup sems_lite_agent_types
 * @{
 */

/** Check Tear down Amd-I section 4.14 */
typedef enum _sems_lite_tearDown_status_t
{
    /** The script has been completely executed */
    sems_lite_notear = 0,
    /** Script execution was interrupted because of teardown. */
    sems_lite_tear                    = 1,
    sems_lite_tearDown_status_invalid = 0x7F,
} sems_lite_tearDown_status_t;

/**Track the progress of an upgrade process in a
*software system, distinguishing between when the
*upgrade session is active or not, and providing
*a special value for invalid states.
*/
typedef enum _sems_lite_upgradeProgress_status_t
{
    /** Upgrade session Not in Progress */
    sems_lite_upgrade_not_inProgress = 0,
    /** Upgrade session In Progress */
    sems_lite_upgrade_inProgress = 1,
    sems_lite_upgrade_invalid    = 0x7F,
} sems_lite_upgradeProgress_status_t;

/** Indicates the current state of recovery process in a System*/
typedef enum _sems_lite_recovery_status_t
{
    /** Recovery Not Started */
    sems_lite_recovery_not_started = 0,
    /** Recovery Started */
    sems_lite_recovery_started = 1,
} sems_lite_recovery_status_t;

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * ***************************************************************************************************************** */

/** Information of about Applet/Package
 *
 * See Table 11-36: GlobalPlatform Registry Data (TLV), GPCardSpc_v2.2.pdf
 *
 * The response from Applet is put to rspBuf
 *
 * After parsing that response, the pointers to respective members is
 * set and it points to relevant part in rspBuf, this way saving
 * memory.  However, the Length is updated so that application use
 * this information.
 *
 */
typedef struct
{
    // 'E3' Variable GlobalPlatform Registry related data
    // '4F' 5 - 16 AID
    /** Applet ID */
    uint8_t *pAID;
    /** Length of the Applet ID */
    uint8_t AIDLen;
    // '9F70' 1 Life Cycle State
    /** Life-cycle state */
    uint8_t LifeCycleState;
    // 'C5' 0, 1, 3 Privileges(byte 1 - byte 2 - byte 3)
    /** Privileges. */
    uint8_t *pPriviledges;
    /** Length of Privileges */
    uint8_t PriviledgesLen;
    //
    // 'C4' 1 - n
    //! Application's Executable Load File AID
    uint8_t *pLoadFileAID;
    //! Length of LoadFileAID
    uint8_t LoadFileAIDLen;
    // 'CE' 1 - n
    //! Executable Load File Version Number
    uint8_t *pLoadFileVersionNumber;
    //! Length of pLoadFileVersionNumber
    uint8_t LoadFileVersionNumberLen;
    // '84' 1 - n First or only Executable Module AID
    // ... ... ... ...
    // '84' 1 - n Last Executable Module AID
    // 'CC' 1-n
    //! Associated Security Domain's AID
    uint8_t *pSecurityDomainAID;
    //! Length of SecurityDomainAID
    uint8_t SecurityDomainAIDLen;
    //! Response from Applet
    uint8_t rspBuf[SEMS_LITE_GET_DATA_CMD_BUF_LEN];
    //! Length of response from Applet
    size_t rspBufLen;
} sems_lite_SEAppInfoList_t;

/** Same as @ref sems_lite_SEAppInfoList_t for for list of installed packages */
typedef sems_lite_SEAppInfoList_t sems_lite_PKGInfoList_t;

/***************************************************************************
* Structure multicast_package_t:
*     multicastPackageFormatVersion
*     targetEntityID
*     requiredFreeBytesNonVolatileMemory
*     requiredFreeBytesTransientMemory
*     pMulticastPackageName--->multicastPackageName
*     multicastPackageVersion
*     pSubComponentMetaData--->subComponentMetaData1.pName--->name
*                              subComponentMetaData1.pAid --->aid
*                              subComponentMetaData1.version
*                              subComponentMetaData1.minimumPreviousVersion
*                              subComponentMetaData2.pName--->name
*                              subComponentMetaData2.pAid --->aid
*                              subComponentMetaData2.version
*                              subComponentMetaData2.minimumPreviousVersion
*                              subComponentMetaDataN.pName--->name
*                              subComponentMetaDataN.pAid --->aid
*                              subComponentMetaDataN.version
*                              subComponentMetaDataN.minimumPreviousVersion
*     pSignatureOverCommands-->signatureOverCommands
*     pMulticastCommands------>multicastCommands
***************************************************************************/
typedef struct _sub_component_metaData_t
{
    /**Length of name*/
    size_t nameLen;
    /**A human readable name for this subcomponent.*/
    char *pName;
    /**Length of aid*/
    size_t aidLen;
    /**The Application Identifier (AID) of the Executable Load File (ELF) which is in this subcomponent.
    * This is stored as string to have it formatted in hexadecimal and therefore recognizable form.
    * Encoded as binary.
    */
    const uint8_t *pAid;
    /** Version information of this subcomponent. Version information major.minor, according to java card
    * virtual machine package versions, both values in range 0 to 127.
    * bypte 0 is Major value, byte 1 is Minor value.
    */
    uint8_t version[SEMS_LITE_PKG_VERSION_LEN];
    /**Length of SWContentRegister */
    size_t swContentRegisterLen;
    /**NXP Software Content Register, specifies the Outgoing License, mostly: LA_OPT_NXP_Software_License.*/
    char *pSWContentRegister;
    /**Minimum version number of this subcomponent as installed on the secure element before this script
    * is executed. If this field is omitted there is no minimum version requirement, e.g. initial
    * Installation of an applet. If the minimumPreviousVersion is 4.11 but the secure element contains
    * version 3.2, the intermediate update packages need to be applied to reach version 4.11 before
    * this package. Version information major.minor, according to java card virtual machine package
    * versions, both values in range 0 to 127.
    * bypte 0 is Major value, byte 1 is Minor value.
    */
    uint8_t minimumPreviousVersion[SEMS_LITE_PKG_VERSION_LEN];
    /**Next subcomponent meta data*/
    struct _sub_component_metaData_t *pNextSubComponentMetaData;
} sub_component_metaData_t;

/**Information about package*/
typedef struct
{
    /** Version information of SEMS Lite Agent API
    * Defined follow SEMS_LITE_AGENT_VER_MAJOR
    */
    uint32_t semsLiteAPIVersion;
    /** Entity ID, 16bytes long Binary Coded Decimal, of the target device where this MulticastPackage is
    * intended to be executed on. It is an identifier of the key-set of the Multicast Applet Loader.
    * As the key-set and related Entity ID can change over the lifetime of the device it is separated
    * from the Commercial Name. This is stored to have it formatted in the BCD encoded and therefore
    * recognizable form.
    */
    uint8_t targetEntityID[16];
    /** Target 12nc is a 12 digit numerical code identifying the target device where this MulticastPackage
    *is intended to be executed on, as known to customers and used on EdgeLock2Go to identify device types.
    */
    uint8_t target12Nc[6];
    /** Minimum required free Non Volatile memory in bytes that have to be free on the target device
    * before execution of MulticastPackage.
    */
    uint32_t requiredFreeBytesNonVolatileMemory;
    /** Minimum required free transient (RAM) memory in bytes that have to be present on the target device
    * before execution of MulticastPackage.
    */
    uint32_t requiredFreeBytesTransientMemory;
    /** Length of  multicast Package name*/
    size_t multicastPackageNameLen;
    /** Giving a descriptive name to the content of the Multicast Package. It is possible that one Multicast
    * Package contains multiple Applet binaries and also that a Multicast Package contains no Applet binary
    * at all (e.g. for deletion).
    */
    const char *pMulticastPackageName;
    /** Version information of this MulticastPackage, describing the sum version over all contained content.
    * In case exactly one SubComponent is contained this version is equal to the version of this SubComponent.
    * Version information major.minor, both values in range 0 to 127.
    * bypte 0 is Major value, byte 1 is Minor value.
    */
    uint8_t multicastPackageVersion[SEMS_LITE_PKG_VERSION_LEN];
    /** A list of subcomponents of this MulticastPackage, designating all Executable Load Files (ELFs) Contained.
    * It usually contains one entry, but can have multiple in the case multiple dependent ELFs get modified.
    * This list can be empty, e.g. for a KeyRotation or content deletion MulticastPackage.
    */
    const sub_component_metaData_t *pSubComponentMetaData;
    /** Length of pPkSemsCaAut */
    size_t pkSemsCaAutLen;
    /**The PkSemsCaAut key found in the SEMS_SP_AUT.txt file as PK.AP.AUT. */
    const uint8_t *pPkSemsCaAut;
    /**Length of signatureOverCommands */
    size_t signatureOverCommandsLen;
    /**The signature over the multicast commands in an machine readable form. So it does not have to be parsed
    * form the script commands. String encoding is chosen here, as mayna json parsers can not handle such large
    * integer values.
    */
    const uint8_t *pSignatureOverCommands;
    /**Length of multicast commands (as pointed by ``pMulticastCommands``).
    *If multicastCommandsLen mismatches to contents of pMulticastCommands,
    *there will be undesired behavior of system.
    */
    size_t multicastCommandsLen;
    /** The complete Multicast Applet Loader Script (certificate, signature, encrypted and signed commands) in
    * protobuf format.
    */
    const uint8_t *pMulticastCommands;
} multicast_package_t;

/** Represents available memory for differnet components , such as COD,COR
*PersistentMemory, IDX
*/
typedef struct _sems_lite_available_mem_t
{
    /**Indicates teh available memory for COD (Card Operating System)*/
    uint32_t availableCODMemory; // 80CA00FE#(DF25)00, {response;s14,8}
                                 /**Indicates teh available memory for COR (Card operating Runtime)*/
    uint32_t availableCORMemory; // 80CA00FE#(DF25)00, {response;s26,8}
    /**Indicates Available PersistentMemory*/
    uint32_t availablePersistentMemory; // 80CA00FE#(DF25)00, {response;s38,8}
    /**Indicates Available IDX*/
    uint32_t availableIDX; // 80CA00FE#(DF25)00, {response;s50,8}
    /**Indicates amount of free memory in the central gap of the PHeap */
    uint32_t freePHeapCentralGap;
    /**Represents free transient memory from cOD from JCOP*/
    uint32_t freeTransient; // COD from JCOP
} sems_lite_available_mem_t;

/**
 *@}
 */ /* end of sems_lite_agent_types */

/**
 * @addtogroup sems_lite_agent
 * @{
 */

/**
 * @brief Load Applet package.
 *
 * This function load an available update package on the SE and assure
 * the tearing safe update of the SE.
 *
 * @param context Pointer to sems lite agent context.
 *
 * @param multiPkgBuf Pointer to package. It must follow the format defined in multicast_package_t.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SEMS_Lite_Success The operation has completed
 * successfully.
 *
 * @retval #kStatus_SEMS_Lite_ERR_COM Communication to SE failed.
 *
 * @retval #kStatus_SEMS_Lite_ERR_DoReRun Update not completed please
 * provide update package again.
 *
 * @retval #kStatus_SEMS_Lite_ERR_NotApplicable Update not applicable on
 * this Chip/type.
 *
 * @retval #kStatus_SEMS_Lite_ERR_DoRecovery Update can not be
 * completed. Please provide recovery package, to roll back to last
 * working version.
 *
 * @retval #kStatus_SEMS_Lite_ERR_Fatal Unresolvable error. (This category
 * of errors can only appear in testing of an update package, in the
 * case of NXP updates this is testes before by NXP)
 *
 * @retval #kStatus_SEMS_Lite_ERR_NotEnoughNVMemory Don't have has enough
 * NV memory for the SEMS Lite Script.
 *
 * @retval #kStatus_SEMS_Lite_ERR_NotEnoughTransientMemory Don't have enough
 * transient memory for the SEMS Lite Script .
 *
 * @note More return codes would be added to request host to either
 * retry or install older package.
 *
 */
sems_lite_status_t sems_lite_agent_load_package(sems_lite_agent_ctx_t *context, multicast_package_t *multiPkgBuf);

/**
 * @brief Initialize SEMS Lite agent context.
 *
 * This function is used to initialize SEMS Lite agent context.
 *
 * @param context Pointer to sems lite agent context.
 *
 * @param boot_ctx Pointer to sss session context
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SEMS_Lite_Success The operation has completed successfully.
 *
 * @retval #kStatus_SEMS_Lite_ERR_General The operation has failed.
 *
 */
sss_status_t sems_lite_agent_init_context(sems_lite_agent_ctx_t *context, sss_session_t *boot_ctx);

/**
 * @brief      Open a Physical connection to SEMS Lite Applet
 *
 * Calling this API opens Locical Connection 1 and selecs the SEMS Lite
 * applet.
 *
 * @param      context  SEMS Lite Agent Context
 *
 * @return     The api status.
 *
 * @retval #kStatus_SEMS_Lite_Success Could connect to SEMS Lite Applet.
 *
 * @retval #kStatus_SEMS_Lite_ERR_General Could not connect to SEMS Lite Applet.
 */
sss_status_t sems_lite_agent_session_open(sems_lite_agent_ctx_t *context);

/**
 * @brief      Close the connection to SEMS Lite Applet
 *
 * @param      context  The context
 *
 * @return     The api status.
 *
 * @retval #kStatus_SEMS_Lite_Success Could close connection 1.
 *
 * @retval #kStatus_SEMS_Lite_ERR_General Could not close connection 1.
 */
sss_status_t sems_lite_agent_session_close(sems_lite_agent_ctx_t *context);

/**
 * @brief Retrieve UUID from SE
 *
 * This API read UUID of the SE.
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pRspBuf Pointer to response Buffer.
 *
 * @param pRspBufLen Pointer to length of the response Buffer.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_get_UUID(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen);

/**
 * @brief Read Public Key
 *
 * This API will read root certificates public key of the device.
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pRspBuf Pointer to response Buffer.
 *
 * @param pRspBufLen Pointer to length of the response Buffer.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_get_Publickey(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen);

/**
 * @brief Low level API to get Raw App INFO from the SE
 *
 * This API will read the currently present Applications ELF/ELM AIDs and
 * versions as well as the present instances from the SE.
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param[out] pRspBuf Pointer to response Buffer.
 *
 * @param[in]  searchAID     The search aid
 *
 * @param[in]  searchAidLen  The search aid length
 *
 * @param[in,out] pRspBufLen Pointer to length of the response Buffer.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 */
sss_status_t sems_lite_get_SEAppInfoRAW(sems_lite_agent_ctx_t *pContext,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    uint8_t *pRspBuf,
    size_t *pRspBufLen);

/**
 * @brief Low level API to get App INFO from the SE
 * according to format mentioned in -
 * Table 11-36: GlobalPlatform Registry Data (TLV), GPCardSpc_v2.2.pdf
 *
 * This API will read the currently present Applications ELF/ELM AIDs and
 * versions as well as the present instances from the SE.
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param[in]  searchAID     The search aid
 *
 * @param[in]  searchAidLen  The search aid length
 *
 * @param      pAppInfo      Parsed structures
 *
 * @param[in,out]      pAppInfoLen   Length of parsed structures.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 */

sss_status_t sems_lite_get_SEAppInfo(sems_lite_agent_ctx_t *pContext,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    sems_lite_SEAppInfoList_t *pAppInfo,
    size_t *pAppInfoLen);

/**
 * @brief Low level API to get RAW PKG INFO from the SE
 *
 * This API will read the currently present Applications ELF/ELM AIDs and
 * versions as well as the present instances from the SE.
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param[in]  searchAID     The search aid
 *
 * @param[in]  searchAidLen  The search aid length
 *
 * @param[out] pRspBuf Pointer to response Buffer.
 *
 * @param[in,out] pRspBufLen Pointer to length of the response Buffer.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sems_lite_get_SEPkgInfoRAW(sems_lite_agent_ctx_t *pContext,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    uint8_t *pRspBuf,
    size_t *pRspBufLen);

/**
 * @brief Low level API to get PKG INFO from the SE
 * according to format mentioned in -
 * Table 11-36: GlobalPlatform Registry Data (TLV), GPCardSpc_v2.2.pdf
 *
 * This API will read the currently present Applications ELF/ELM AIDs and
 * versions as well as the present instances from the SE.
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param[in]  searchAID     The search aid
 *
 * @param[in]  searchAidLen  The search aid length
 *
 * @param      pAppInfo      Parsed structures
 *
 * @param[in,out]      pAppInfoLen   Length of parsed structures.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 */

sss_status_t sems_lite_get_SEPkgInfo(sems_lite_agent_ctx_t *pContext,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    sems_lite_SEAppInfoList_t *pAppInfo,
    size_t *pAppInfoLen);

/**
 * @brief Check Tear during script execution
 *
 * This API will check whether there was tear during
 * script execution
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pTearStatus Pointer to tear status.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_check_Tear(sems_lite_agent_ctx_t *pContext, sems_lite_tearDown_status_t *pTearStatus);

/**
 * @brief Get the signature of last executed script
 *
 * This API will called in case there is tear down
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pRspBuf Pointer to response Buffer.
 *
 * @param pRspBufLen Pointer to length of the response Buffer
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_get_SignatureofLastScript(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen);

/**
 * @brief Get the SEMS Lite Agent version
 *
 * This API will return the SEMS Lite Agent Version no.
 *
 * @param pRspBuf Pointer to response Buffer.
 *
 * @param pRspBufLen Pointer to length of the response Buffer
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_get_AgentVersion(uint8_t *pRspBuf, size_t *pRspBufLen);

/**
 * @brief Get the Applet version
 *
 * This API will return the SEMS Lite Applet Version no.
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pRspBuf Pointer to response Buffer.
 *
 * @param pRspBufLen Pointer to length of the response Buffer
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_get_AppletVersion(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen);

/**
 * @brief Check Applet Upgrade Progress
 *
 * This API will return the status of applet upgrade progress status
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pUpgradeStatus Pointer to upgrade status.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_check_AppletUpgradeProgress(
    sems_lite_agent_ctx_t *pContext, sems_lite_upgradeProgress_status_t *pUpgradeStatus);

/**
 * @brief Check Applet Recovery Status
 *
 * This API will return the status of applet recovery status
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pRecoveryStatus Pointer to recovery status.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_check_AppletRecoveryStatus(
    sems_lite_agent_ctx_t *pContext, sems_lite_recovery_status_t *pRecoveryStatus);

/**
 * @brief Get the ENC Identifier.
 *
 * This API will return the ENC Identifier.
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pRspBuf Pointer to response Buffer.
 *
 * @param pRspBufLen Pointer to length of the response Buffer
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_get_ENCIdentifier(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen);

/**
 * @brief      { function_description }
 *
 * @param      pContext  The context
 * @param      pAvailableMem  Availalbe Memory Space Information
 *
 * @return     The sss status.
 */
sss_status_t sems_lite_get_available_mem(sems_lite_agent_ctx_t *pContext, uint8_t *pAvailableMem);

/**
 * @brief Get the CA Identifier.
 *
 * This API will return the CA Identifier.
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pRspBuf Pointer to response Buffer.
 *
 * @param pRspBufLen Pointer to length of the response Buffer
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_get_CA_identifier(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen);

/**
 * @brief Get Configured EC domain parameter type
 *
 * This API will return Configured EC domain parameter type
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pParamType Pointer to parameter type.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_get_FIPS_EC_parameter_type(sems_lite_agent_ctx_t *pContext, uint8_t *pParamType);

/**
 * @brief Get Configured FIPS Information
 *
 * This API will return Configured FIPS Information
 *
 * @param pContext Pointer to sems lite agent context.
 *
 * @param pFIPSInfo Pointer to FIPS Info.
 *
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 *
 * @retval #kStatus_SSS_Fail The operation has failed.
 *
 *
 */
sss_status_t sems_lite_get_FIPS_info(sems_lite_agent_ctx_t *pContext, uint8_t *pFIPSInfo);

/**
 *@}
 */ /* end of sems_lite_agent */

#endif // !SEMS_LITE_API_H_INC
