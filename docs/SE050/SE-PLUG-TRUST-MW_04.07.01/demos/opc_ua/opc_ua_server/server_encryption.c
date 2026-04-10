/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2019 (c) Kalycito Infotech Private Limited
 *    Copyright 2019 NXP.
 *
 */

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>

#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include <signal.h>
#include <stdlib.h>

#include "common.h"

#include "sss_interface.h"

static ex_sss_boot_ctx_t gex_sss_opc_ua_boot_ctx;
sss_session_t *gSESession = NULL;
UA_Boolean running = true;
UA_Int32 sensor1 = 0;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_opc_ua_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1
#define EX_SSS_BOOT_DO_ERASE 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "received ctrl-c");
    running = false;
}

static UA_StatusCode
readSensor1Value(UA_Server *server,
    const UA_NodeId *sessionId, void *sessionContext,
    const UA_NodeId *nodeId, void *nodeContext,
    UA_Boolean sourceTimeStamp, const UA_NumericRange *range,
    UA_DataValue *dataValue) {
    UA_Int32 now = sensor1;
    UA_Variant_setScalarCopy(&dataValue->value, &now,
        &UA_TYPES[UA_TYPES_UINT32]);
    dataValue->hasValue = true;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeSensor1Value(UA_Server *server,
    const UA_NodeId *sessionId, void *sessionContext,
    const UA_NodeId *nodeId, void *nodeContext,
    const UA_NumericRange *range, const UA_DataValue *data) {
    UA_UInt16 i = 0;
    char *mem = NULL;
    UA_Int32 val = 0;

    if (strcmp(data->value.type->typeName, "UInt32") == 0)
    {
        mem = data->value.data;
        for (i = 0; i < data->value.type->memSize; i++)
        {
            val |= mem[i] << (8 * i);
        }
        sensor1 = val;
    }
    else
    {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
            "Cannot handle the data type");
    }

    return UA_STATUSCODE_GOOD;
}

static void
addSensor1Variable(UA_Server *server) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("en-US", "Sensor1");
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    UA_NodeId currentNodeId = UA_NODEID_STRING(1, "Sensor1");
    UA_QualifiedName currentName = UA_QUALIFIEDNAME(1, "Sensor1");
    UA_NodeId parentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    UA_NodeId parentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
    UA_NodeId variableTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE);

    UA_DataSource timeDataSource;
    timeDataSource.read = readSensor1Value;
    timeDataSource.write = writeSensor1Value;
    UA_Server_addDataSourceVariableNode(server, currentNodeId, parentNodeId,
        parentReferenceNodeId, currentName,
        variableTypeNodeId, attr,
        timeDataSource, NULL, NULL);
}

//int main(int argc, char* argv[]) {
sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx){
    UA_ByteString certificate = UA_STRING_NULL;
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    gex_sss_argc--;
    gSESession = &(pCtx->session);

    if(gex_sss_argc < 3) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Missing arguments. Arguments are "
                     "<server-certificate.der> <private-key.der> "
                     "[<trustlist1.crl>, ...]");
        return EXIT_FAILURE;
    }

    /* Load certificate and private key */

    if (strcmp(gex_sss_argv[1], "NULL") == 0)
    {
        /* Read certificate from SE */
        if (sss_interface_init() != 0) {
            return EXIT_FAILURE;
        }
        if (sss_interface_read_certificate(&(certificate.data), &(certificate.length)) != 0) {
            return EXIT_FAILURE;
        }
    }
    else
    {
        certificate = loadFile(gex_sss_argv[1]);
    }

    UA_ByteString privateKey = loadFile(gex_sss_argv[2]);

    /* Load the trustlist */
    size_t trustListSize = 0;
    if(gex_sss_argc > 3) {
        trustListSize = (size_t)gex_sss_argc -3;
    }
    UA_STACKARRAY(UA_ByteString, trustList, trustListSize);
    for(size_t i = 0; i < trustListSize; i++)
        trustList[i] = loadFile(gex_sss_argv[i+3]);

    /* Loading of a issuer list, not used in this application */
    size_t issuerListSize = 0;
    UA_ByteString *issuerList = NULL;

    /* Loading of a revocation list currently unsupported */
    UA_ByteString *revocationList = NULL;
    size_t revocationListSize = 0;

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    if (privateKey.length != 0)
    {
        UA_realloc(privateKey.data, (privateKey.length + 1) * sizeof(UA_Byte));
        privateKey.data[privateKey.length] = '\0';
        privateKey.length = privateKey.length + 1;
    }

    UA_StatusCode retval =
        UA_ServerConfig_setDefaultWithSecurityPolicies(config, 4840,
                                                       &certificate, &privateKey,
                                                       trustList, trustListSize,
                                                       issuerList, issuerListSize,
                                                       revocationList, revocationListSize);

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    for(size_t i = 0; i < trustListSize; i++)
        UA_ByteString_clear(&trustList[i]);
    if(retval != UA_STATUSCODE_GOOD) {
        goto cleanup;
    }

    addSensor1Variable(server);

    retval = UA_Server_run(server, &running);

 cleanup:
    UA_Server_delete(server);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
