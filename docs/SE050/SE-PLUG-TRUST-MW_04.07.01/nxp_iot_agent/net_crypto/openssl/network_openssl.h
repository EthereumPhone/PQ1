/*
 * Copyright 2018-2021,2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _NXP_IOT_AGENT_PLATFORM_NETWORK_OPENSSL_H_
#define _NXP_IOT_AGENT_PLATFORM_NETWORK_OPENSSL_H_

#include <stdbool.h>


#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <ws2tcpip.h>
#endif

// Winsock must be included before openssl!
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
#include <sssProvider_main.h>
#include <openssl/params.h>
#endif

#include <network.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * The identifier of the engine that is used for TLS network connection support with openssl.
 */
#define NETWORK_OPENSSL_ENGINE_ID "e4sss"

typedef struct openssl_network_config_t
{
    const char* hostname;
	int port;
	X509* certificate;
	X509_STORE* ca_chain;
#if (OPENSSL_VERSION_NUMBER < 0x30000000)
	EVP_PKEY* private_key;
#else
	OSSL_PARAM* private_key;
#endif //if (OPENSSL_VERSION_NUMBER < 0x30000000)
} openssl_network_config_t;


typedef struct openssl_network_context_t
{
    openssl_network_config_t network_config;
    SSL* ssl;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
	OSSL_PROVIDER *sss_provider;
	sss_provider_context_t* sss_provider_ctx;
#endif //if (OPENSSL_VERSION_NUMBER >= 0x30000000)
} openssl_network_context_t;


// Note: This call initializes openssl from the config file. This implies this is 
// the point which enables the engine.
// ATTENTION: Invoke this method before creating any keys!
//   Openssl key objects (EVP_PKEY, EC_KEY, RSA, etc.) internally store
//   function pointers for the methods that are to be used for particular operations.
//   This means that keys that are created (e.g. by reading a file/or by reading 
//   from a SE) BEFORE openssl is properly initialized, their method function 
//   pointers will not consider the engine!
int network_openssl_init(openssl_network_context_t* context);

/**
 * Make the openssl engine establish a connection to the secure element.
 */
int network_openssl_engine_session_connect(openssl_network_context_t* context);

/**
* Make the openssl engine disconnect from the secure element.
*/
int network_openssl_engine_session_disconnect(openssl_network_context_t* context);



void print_openssl_errors(char* function);


#ifdef __cplusplus
}
#endif

#endif // _NXP_IOT_AGENT_PLATFORM_NETWORK_OPENSSL_H_
