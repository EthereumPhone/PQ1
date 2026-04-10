/**
 * @file tlsSe050Client.cpp
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2019,2020,2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description:
 * Simple TLS client
 * - Fetch client certificate from provisioned SE
 * - Load OpenSSL engine
 * - Establish TLS connection (use client key pair provisioned in SE) and send message#1
 * - Close TLS connection
 * - Close comm. link of OpenSSL engine with SE
 * - Fetch client certificate from provisioned SE
 * - Re-open comm. link of OpenSSL engine with SE
 * - Establish TLS connection (use client key pair provisioned in SE) and send message#2
 * - Close TLS connection
 *
 * Precondition:
 * - SE (SE050) has been provisioned with appropriate credentials
 * - Server side has been setup and has been provisioned with appropriate credentials
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/engine.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
#include <openssl/store.h>
#include <openssl/provider.h>
#endif

#define SSS_USE_FTR_FILE
#define FTR_FILE_SYSTEM

#include "snw_common.h"

/* App version */
const int v_major = 0;
const int v_minor = 9;
const int v_patch = 2;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
#define OPENSSL30_SE05X_CNF_FILE "../../common/openssl30_sss_se050.cnf"
#endif

int certVerifyCb(int preverifyOk, X509_STORE_CTX *pX509CTX)
{
    char szData[256];
    X509 *cert = X509_STORE_CTX_get_current_cert(pX509CTX);
    int depth = X509_STORE_CTX_get_error_depth(pX509CTX);

    if (!preverifyOk) {
        int err = X509_STORE_CTX_get_error(pX509CTX);
        printf("Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), szData, 256);
        printf(" issuer = %s\n", szData);
        X509_NAME_oneline(X509_get_subject_name(cert), szData, 256);
        printf(" subject = %s\n", szData);
        printf(" err %i:%s\n", err, X509_verify_cert_error_string(err));
    }
    else {
        printf("Certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), szData, 256);
        printf(" issuer = %s\n", szData);
        X509_NAME_oneline(X509_get_subject_name(cert), szData, 256);
        printf(" subject = %s\n", szData);
    }
    return preverifyOk;
}

#define MAX_DER_CERT_SIZE    1024
#define MAX_DATA_OBJECT_SIZE 1024

int main(int argc, char **argv)
{
    int nStatus = 0;
    ENGINE *e;
    const SSL_METHOD *method;
    SSL_CTX *pSSLContext;
    SSL *pSSLHandle;
    char pDestinationURL[256];
    int nDestinationPort = 8080;
    int nRet = SE_TLS_CLIENT_OK;
    int sockfd;
    char fileRootCA[256];
    char keyType[256];
    char fileClientKey[256];
    X509 *certRcv;
    char clientMessage[256];
    int clientMessageLen;
    char engineId[256];
    U8 clientCerDer[MAX_DER_CERT_SIZE];
    size_t clientCerDerLen = MAX_DER_CERT_SIZE;
    char clientCertFile[256]; // Optional filename of client certificate
    int certId = 0;
    U8 dataObject[MAX_DATA_OBJECT_SIZE];
    U16 dataObjectLen = MAX_DATA_OBJECT_SIZE;
    int objectIndex = 0;
    U16 dataOffset;
    U16 dataLen;
    U8 clientCerDer_2[MAX_DER_CERT_SIZE];
    size_t clientCerDer_2Len = MAX_DER_CERT_SIZE;
    ex_sss_boot_ctx_t gdirectSeSessionCtx;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
    EVP_PKEY *p_client_pkey       = NULL;
    OSSL_LIB_CTX *ossl_ctx = NULL;
#endif

    printf("%s (Rev.%d.%d.%d)\n", argv[0], v_major, v_minor, v_patch);

    // Evaluate command line arguments
    if (argc < 5 || argc > 7) {
        printf("Usage: %s <ipAddress:port> <EC|RSA> <caCert.pem> <clientKey.pem|clientKeyRef.pem> [<clientCert.pem>]\n", argv[0]);
        nRet = SE_TLS_CLIENT_CMDLINE_ARGS;
        goto leaving;
    }

    memset(&gdirectSeSessionCtx, 0, sizeof(ex_sss_boot_ctx_t));

    // Deal with first argument: <address|name>:<port>
    // ***********************************************
    {
        unsigned int i;
        int fColonFound = 0;
        int nSuccess;

        if (strlen(argv[1]) >= sizeof(pDestinationURL)) {
            // A bit too cautious (as port number may also be attached)
            nRet = SE_TLS_CLIENT_BUFFER_TOO_SMALL;
            goto leaving;
        }

        for (i = 0; i < strlen(argv[1]); i++) {
            if (argv[1][i] == ':') {
                strncpy(pDestinationURL, argv[1], i);
                pDestinationURL[i] = 0;
                fColonFound = 1;
                // printf("servername/address: %s\n", pDestinationURL);
                break;
            }
            else {
                // Simply copy the full argument
                strcpy(pDestinationURL, argv[1]);
            }
        }

        if ((fColonFound == 1) && (i != 0)) {
            nSuccess = sscanf(&argv[1][i], ":%5u[0-9]", (unsigned int *)&nDestinationPort);
            if (nSuccess != 1) {
                nRet = SE_TLS_CLIENT_ILLEGAL_PORT_NR;
                goto leaving;
            }
        }
        else {
            // Choose default value for port
            nDestinationPort = 8080;
        }
    }
    printf("\t servername:port = %s:%d\n", pDestinationURL, nDestinationPort);

    // Deal with second argument: key type (either EC or RSA for now)
    // ***************************************************************
    if (strlen(argv[2]) >= sizeof(keyType)) {
        nRet = SE_TLS_CLIENT_BUFFER_TOO_SMALL;
        goto leaving;
    }
    strcpy(keyType, argv[2]);
    if ( (strcmp(keyType, "RSA") != 0) && (strcmp(keyType, "EC") != 0) ) {
        printf("\t keyType: %s is not defined, choose from EC or RSA.\n", keyType);
        nRet = SE_TLS_CLIENT_CMDLINE_ARGS;
        goto leaving;
    }
    printf("\t keyType: %s\n", keyType);

    // Deal with third argument: root CA certificate
    // **********************************************
    if (strlen(argv[3]) >= sizeof(fileRootCA)) {
        nRet = SE_TLS_CLIENT_BUFFER_TOO_SMALL;
        goto leaving;
    }
    strcpy(fileRootCA, argv[3]);
    printf("\t rootCA: %s\n", fileRootCA);

    // Deal with fourth argument: key or reference key
    // **********************************************
    if (strlen(argv[4]) >= sizeof(fileClientKey)) {
        nRet = SE_TLS_CLIENT_BUFFER_TOO_SMALL;
        goto leaving;
    }
    strcpy(fileClientKey, argv[4]);
    printf("\t clientKey: %s\n", fileClientKey);

    // Deal with optional fifth argument
    // **********************************
    if (argc == 6) {
        if (strlen(argv[5]) >= sizeof(clientCertFile)) {
            nRet = SE_TLS_CLIENT_BUFFER_TOO_SMALL;
            goto leaving;
        }
        strcpy(clientCertFile, argv[5]);
        printf("\t clientCertFile: %s\n", clientCertFile);
    }
    else {
        clientCertFile[0] = 0;
    }

    strcpy(clientMessage, "Hello to Server from TLS client using credentials stored in Secure Element.\n");
    clientMessageLen = strlen(clientMessage);

    /* Session is used to retrive cert from SE */
    nRet = wrapConnectToSe(&gdirectSeSessionCtx);
    if (nRet != SE_TLS_CLIENT_OK) {
        printf("Failed to connect to Secure Element.\n");
        goto leaving;
    }

    // Ensure the matching TLS Client certificate has been provisioned before running the demo
    if ( strcmp(keyType, "RSA") == 0)  {
        certId = OBJID_DEMO_RSA_TLS_CLIENT_CERT;
    }
    else if (strcmp(keyType, "EC") == 0) {
        certId = OBJID_DEMO_EC_TLS_CLIENT_CERT;
    }
    else {
        printf("Don't know about keyType %s (leaving)\n", keyType);
        goto leaving;
    }

#if 1
    if (clientCertFile[0] == 0) {
        nRet = seGetClientCertificate(&(gdirectSeSessionCtx.ks), certId, clientCerDer, &clientCerDerLen);
        if (nRet != SE_TLS_CLIENT_OK) {
            printf("Failed to retrieve client certificate.\n");
            goto leaving;
        }
    }
#endif

    wrapDisconnectFromSe(&gdirectSeSessionCtx);

    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if (SSL_library_init() < 0) {
        nRet = SE_TLS_CLIENT_SSL_LIB_INIT_ERROR;
        goto leaving;
    }

#if (OPENSSL_VERSION_NUMBER < 0x10101000L)
    method = TLSv1_2_method();
#else
    method = TLS_method();
#endif

#if SSS_HAVE_APPLET_SE05X_IOT
    strcpy(engineId, "e4sss");
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
    fprintf(stderr, "Load openssl 3.0 config file.\n");

    if (OSSL_LIB_CTX_load_config(ossl_ctx, OPENSSL30_SE05X_CNF_FILE) != 1) {
        printf("Error in loading openssl 3.0 config file \n");
        nRet  = SE_ERR_SE_LOADING_ENGINE_ERR;
        goto leaving;
    }
#else
    if (!(e = ENGINE_by_id(engineId)))
    {
        fprintf(stderr, "Error finding OpenSSL Engine by id (id = %s)\n", engineId);
        nRet = SE_ERR_SE_LOADING_ENGINE_ERR;
        goto leaving;
    }
    else
    {
        unsigned int logLevel = 0x05;
        fprintf(stderr, "Setting log level OpenSSL-engine %s to 0x%02X.\n", engineId, logLevel);
        // Illustrates setting log level of e4sss engine.
        // 0x04 : Error message
        // 0x02 : Debug messages
        // 0x01 : Flow messages
        // (0x07 corresponds to all, which is the default)
        ENGINE_ctrl(e, ENGINE_CMD_BASE, logLevel, NULL, NULL);
    }
#endif

    if ((pSSLContext = SSL_CTX_new(method)) == NULL) {
        printf("SSL_CTX_new failed - Unable to create SSL Context\n");
        nRet = SE_TLS_CLIENT_SSL_INIT_ERROR;
        goto leaving;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        nRet = SE_TLS_CLIENT_TCP_SETUP_ERROR;
        goto leaving;
    }

    if (!SSL_CTX_load_verify_locations(pSSLContext, fileRootCA, NULL)) {
        nRet = SE_TLS_CLIENT_SSL_CERT_ERROR;
        goto leaving;
    }

    if (clientCertFile[0] != 0) {
        if (!SSL_CTX_use_certificate_file(pSSLContext, clientCertFile, SSL_FILETYPE_PEM)) {
            printf("Client Certificate (%s) Loading error.\n", clientCertFile);
            nRet = SE_TLS_CLIENT_SSL_CERT_ERROR;
            goto leaving;
        }
    }
    else if (!SSL_CTX_use_certificate_ASN1(pSSLContext, clientCerDerLen, clientCerDer)) {
        printf("Client Certificate Loading error.\n");
        nRet = SE_TLS_CLIENT_SSL_CERT_ERROR;
        goto leaving;
    }

#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
    {
        OSSL_STORE_CTX *p_client_pkey_ctx = NULL;
        OSSL_STORE_INFO *p_client_pkey_info = NULL;

        p_client_pkey_ctx = OSSL_STORE_open_ex(fileClientKey, ossl_ctx, NULL, NULL, NULL, NULL, NULL, NULL);
        if (p_client_pkey_ctx == NULL){
            printf("Error in OSSL_STORE_open for %s. \n", fileClientKey);
            nRet  = SE_ERR_SE_LOADING_ENGINE_ERR;
            goto leaving;
        }

        p_client_pkey_info = OSSL_STORE_load(p_client_pkey_ctx);
        if (p_client_pkey_info == NULL){
            printf("Error in OSSL_STORE_load. \n");
            OSSL_STORE_close(p_client_pkey_ctx);
            nRet  = SE_ERR_SE_LOADING_ENGINE_ERR;
            goto leaving;
        }

        p_client_pkey       = OSSL_STORE_INFO_get1_PKEY(p_client_pkey_info);
        if (p_client_pkey == NULL){
            printf("Error in OSSL_STORE_INFO_get1_PKEY. \n");
            OSSL_STORE_close(p_client_pkey_ctx);
            OSSL_STORE_INFO_free(p_client_pkey_info);
            nRet  = SE_ERR_SE_LOADING_ENGINE_ERR;
            goto leaving;
        }

        OSSL_STORE_close(p_client_pkey_ctx);
        OSSL_STORE_INFO_free(p_client_pkey_info);

        SSL_CTX_use_PrivateKey(pSSLContext, p_client_pkey);
    }
#else
    if (SSL_CTX_use_PrivateKey_file(pSSLContext, fileClientKey, SSL_FILETYPE_PEM) != 1){
        printf("Client Private Key Loading error.\n");
        nRet = SE_TLS_CLIENT_SSL_KEY_ERROR;
        goto leaving;
    }
#endif

    SSL_CTX_set_verify(pSSLContext, SSL_VERIFY_PEER, certVerifyCb);
    // SSL_CTX_set_verify(pSSLContext, SSL_VERIFY_PEER, NULL);

    pSSLHandle = SSL_new(pSSLContext);

    nRet = snwTcpConnect(sockfd, pDestinationURL, nDestinationPort);
    if (nRet != SE_TLS_CLIENT_OK) {
        printf("TCP Connection error.\n");
        goto leaving;
    }

    SSL_set_fd(pSSLHandle, sockfd);

    nRet = snwSetSocketNonBlocking(sockfd);
    if (nRet != SE_TLS_CLIENT_OK) {
        printf("Unable to set the socket to Non-Blocking.\n");
        goto leaving;
    }

    nRet = snwSslConnect(pSSLHandle, sockfd, 2000);
    if (nRet != SE_TLS_CLIENT_OK) {
        printf("Unable to establish ssl session.\n");
        goto leaving;
    }

    if (X509_V_OK != SSL_get_verify_result(pSSLHandle)) {
        printf("Server Certificate Verification failed");
        nRet = SE_TLS_CLIENT_SSL_CONNECT_ERROR;
        goto leaving;
    }

    // Ensure a valid certificate was returned, otherwise no certificate exchange happened!
    if (NULL == (certRcv = SSL_get_peer_certificate(pSSLHandle)) ) {
        printf(" No certificate exchange happened");
        nRet = SE_TLS_CLIENT_SSL_CONNECT_ERROR;
        goto leaving;
    }
    else {
        X509_NAME *subj;
        char szData[256];

        if ((subj = X509_get_subject_name(certRcv)) &&
                (X509_NAME_get_text_by_NID(subj, NID_commonName, szData, 256) > 0)) {
            printf("Peer Certificate CN: %s\n", szData);
        }
        X509_free(certRcv);
    }

    nRet = snwSslWrite(pSSLHandle, sockfd, (unsigned char *)clientMessage, &clientMessageLen, 2000);
    if (nRet != SE_TLS_CLIENT_OK) {
        printf("Unable to send message to server: nRet = %d.\n", nRet);
        goto leaving;
    }

    nRet = SSL_shutdown(pSSLHandle);
    if (nRet == 0) {
        sleep(1);
        printf("SSL_shutdown: Repeat shutdown.\n");
        nRet = SSL_shutdown(pSSLHandle);
    }

    if (nRet == 1) {
        printf("SSL_shutdown: successful.\n");
        nRet = SE_TLS_CLIENT_OK;
    }
    else if (nRet == 0) {
        printf("SSL_shutdown: not yet finished (second attempt).\n");
    }
    else {
        int errorCode;
        errorCode = SSL_get_error(pSSLHandle, nRet);
        printf("SSL_shutdown: error on shutdown (nRet=%d, SSL_error_code=%d)\n",
            nRet, errorCode);
        // if (errorCode == SSL_ERROR_ZERO_RETURN )
    }

    nRet = SSL_clear(pSSLHandle);
    if (nRet == 0) {
        int errorCode;
        printf("SSL_clear failed.\n");
        errorCode = SSL_get_error(pSSLHandle, nRet);
        printf("errorCode: %d\n", errorCode);
    }
    else if (nRet == 1) {
        printf("SSL_clear successful.\n");
        nRet = SE_TLS_CLIENT_OK;
    }

#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
    OSSL_LIB_CTX_free(ossl_ctx);
    ossl_ctx = NULL;
    fprintf(stderr, "Close connection to secure element.\n \n\n");
#else
    // NOTE: Close engine connection to SE via Engine control interface
    fprintf(stderr, "Close connection to secure element through Engine control interface (Engine=%s).\n", engineId);
    ENGINE_ctrl(e, ENGINE_CMD_BASE+2, 0, NULL, NULL);

    // To demonstrate one can alternate OpenSSL engine access and direct access
    // to the SE, another direct call to the SE
#endif

    printf("Re-establish connection to SE ...\n");

    nRet = wrapConnectToSe(&gdirectSeSessionCtx);
    if (nRet != SE_TLS_CLIENT_OK) {
        printf("Failed to connect to Secure Element.\n");
        goto leaving;
    }

    printf("Successfully established connection to SE\n");

    {
        if (clientCertFile[0] == 0) {
            nRet = seGetClientCertificate(&(gdirectSeSessionCtx.ks), certId, clientCerDer_2, &clientCerDer_2Len);
            if (nRet != SE_TLS_CLIENT_OK) {
                printf("Failed to retrieve client certificate.\n");
                goto leaving;
            }
            snwPrintDataAsHex(clientCerDer_2, clientCerDer_2Len);
        }
    }

    wrapDisconnectFromSe(&gdirectSeSessionCtx);

#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
    ossl_ctx =  OSSL_LIB_CTX_new();
    if (ossl_ctx == NULL) {
        printf("Error in OSSL_LIB_CTX_new \n");
        nRet  = SE_ERR_SE_LOADING_ENGINE_ERR;
        goto leaving;
    }

    fprintf(stderr, "Load openssl 3.0 config file.\n");

    if (OSSL_LIB_CTX_load_config(ossl_ctx, OPENSSL30_SE05X_CNF_FILE) != 1) {
        fprintf(stderr, "Error in loading openssl 3.0 config file \n");
        nRet  = SE_ERR_SE_LOADING_ENGINE_ERR;
        goto leaving;
    }
#else
    // NOTE: Open engine connection to SE via Engine control interface
    fprintf(stderr, "Open connection to secure element through Engine control interface (Engine=%s).\n", engineId);
    ENGINE_ctrl(e, ENGINE_CMD_BASE+1, 0, NULL, NULL);
#endif

    if ((pSSLContext = SSL_CTX_new(method)) == NULL) {
        printf("SSL_CTX_new failed - Unable to create SSL Context\n");
        nRet = SE_TLS_CLIENT_SSL_INIT_ERROR;
        goto leaving;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        nRet = SE_TLS_CLIENT_TCP_SETUP_ERROR;
        goto leaving;
    }

    if (!SSL_CTX_load_verify_locations(pSSLContext, fileRootCA, NULL)) {
        nRet = SE_TLS_CLIENT_SSL_CERT_ERROR;
        goto leaving;
    }

    if (clientCertFile[0] != 0) {
        if (!SSL_CTX_use_certificate_file(pSSLContext, clientCertFile, SSL_FILETYPE_PEM)) {
            printf("Client Certificate (%s) Loading error.\n", clientCertFile);
            nRet = SE_TLS_CLIENT_SSL_CERT_ERROR;
            goto leaving;
        }
    }

    else if (!SSL_CTX_use_certificate_ASN1(pSSLContext, clientCerDer_2Len, clientCerDer_2)) {
        printf("Client Certificate Loading error.\n");
        nRet = SE_TLS_CLIENT_SSL_CERT_ERROR;
        goto leaving;
    }

#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
    {
        OSSL_STORE_CTX *p_client_pkey_ctx = NULL;
        OSSL_STORE_INFO *p_client_pkey_info = NULL;

        p_client_pkey_ctx = OSSL_STORE_open_ex(fileClientKey, ossl_ctx, NULL, NULL, NULL, NULL, NULL, NULL);
        if (p_client_pkey_ctx == NULL){
            printf("Error in OSSL_STORE_open for %s. \n", fileClientKey);
            nRet  = SE_ERR_SE_LOADING_ENGINE_ERR;
            goto leaving;
        }

        p_client_pkey_info = OSSL_STORE_load(p_client_pkey_ctx);
        if (p_client_pkey_info == NULL){
            printf("Error in OSSL_STORE_load. \n");
            OSSL_STORE_close(p_client_pkey_ctx);
            nRet  = SE_ERR_SE_LOADING_ENGINE_ERR;
            goto leaving;
        }

        p_client_pkey       = OSSL_STORE_INFO_get1_PKEY(p_client_pkey_info);
        if (p_client_pkey == NULL){
            printf("Error in OSSL_STORE_INFO_get1_PKEY. \n");
            OSSL_STORE_close(p_client_pkey_ctx);
            OSSL_STORE_INFO_free(p_client_pkey_info);
            nRet  = SE_ERR_SE_LOADING_ENGINE_ERR;
            goto leaving;
        }

        OSSL_STORE_close(p_client_pkey_ctx);
        OSSL_STORE_INFO_free(p_client_pkey_info);

        SSL_CTX_use_PrivateKey(pSSLContext, p_client_pkey);
    }
#else
    if (SSL_CTX_use_PrivateKey_file(pSSLContext, fileClientKey, SSL_FILETYPE_PEM) != 1){
        printf("Client Private Key Loading error.\n");
        nRet = SE_TLS_CLIENT_SSL_KEY_ERROR;
        goto leaving;
    }
#endif

    SSL_CTX_set_verify(pSSLContext, SSL_VERIFY_PEER, certVerifyCb);
    // SSL_CTX_set_verify(pSSLContext, SSL_VERIFY_PEER, NULL);

    pSSLHandle = SSL_new(pSSLContext);

    nRet = snwTcpConnect(sockfd, pDestinationURL, nDestinationPort);
    if (nRet != SE_TLS_CLIENT_OK) {
        printf("TCP Connection error.\n");
        goto leaving;
    }

    SSL_set_fd(pSSLHandle, sockfd);

    nRet = snwSetSocketNonBlocking(sockfd);
    if (nRet != SE_TLS_CLIENT_OK) {
        printf("Unable to set the socket to Non-Blocking.\n");
        goto leaving;
    }

    nRet = snwSslConnect(pSSLHandle, sockfd, 2000);
    if (nRet != SE_TLS_CLIENT_OK) {
        printf("Unable to establish ssl session.\n");
        goto leaving;
    }

    if (X509_V_OK != SSL_get_verify_result(pSSLHandle)) {
        printf("Server Certificate Verification failed");
        nRet = SE_TLS_CLIENT_SSL_CONNECT_ERROR;
        goto leaving;
    }

    // Ensure a valid certificate was returned, otherwise no certificate exchange happened!
    if (NULL == (certRcv = SSL_get_peer_certificate(pSSLHandle)) ) {
        printf(" No certificate exchange happened");
        nRet = SE_TLS_CLIENT_SSL_CONNECT_ERROR;
        goto leaving;
    }
    else {
        X509_NAME *subj;
        char szData[256];

        if ((subj = X509_get_subject_name(certRcv)) &&
                (X509_NAME_get_text_by_NID(subj, NID_commonName, szData, 256) > 0)) {
            printf("Peer Certificate CN: %s\n", szData);
        }
        X509_free(certRcv);
    }

    strcpy(clientMessage, "Another message from TLS client using credentials stored in Secure Element.\n");
    clientMessageLen = strlen(clientMessage);

    nRet = snwSslWrite(pSSLHandle, sockfd, (unsigned char *)clientMessage, &clientMessageLen, 2000);
    if (nRet != SE_TLS_CLIENT_OK) {
        printf("Unable to send message to server: nRet = %d.\n", nRet);
        goto leaving;
    }

    nRet = SSL_shutdown(pSSLHandle);
    if (nRet == 0) {
        sleep(1);
        printf("SSL_shutdown: Repeat shutdown.\n");
        nRet = SSL_shutdown(pSSLHandle);
    }

    if (nRet == 1) {
        printf("SSL_shutdown: successful.\n");
        nRet = SE_TLS_CLIENT_OK;
    }
    else if (nRet == 0) {
        printf("SSL_shutdown: not yet finished (second attempt).\n");
    }
    else {
        int errorCode;
        errorCode = SSL_get_error(pSSLHandle, nRet);
        printf("SSL_shutdown: error on shutdown (nRet=%d, SSL_error_code=%d)\n",
            nRet, errorCode);
        // if (errorCode == SSL_ERROR_ZERO_RETURN )
    }

    nRet = SSL_clear(pSSLHandle);
    if (nRet == 0) {
        int errorCode;
        printf("SSL_clear failed.\n");
        errorCode = SSL_get_error(pSSLHandle, nRet);
        printf("errorCode: %d\n", errorCode);
    }
    else if (nRet == 1) {
        printf("SSL_clear successful.\n");
        nRet = SE_TLS_CLIENT_OK;
    }

    printf("\n\t servername:port = %s:%d\n", pDestinationURL, nDestinationPort);
    printf("\t rootCA: %s\n", fileRootCA);
    // printf("\t Retrieved client certificate from SE (stored at index 0)\n");
    printf("\t clientKey: %s\n\n", fileClientKey);

leaving:
    printf("\n******** TLS Client Example (Credentials in Secure Element) = %s ********\n",
        (nRet == SE_TLS_CLIENT_OK) ? "Pass" : "Fail");
    nStatus = (nRet == SE_TLS_CLIENT_OK) ? OK_STATUS : FAILURE_STATUS;

    return nStatus;
}
