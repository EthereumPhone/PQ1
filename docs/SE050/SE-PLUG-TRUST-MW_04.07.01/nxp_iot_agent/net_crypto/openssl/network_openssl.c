/*
 * Copyright 2018-2021,2024-2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <network_openssl.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/conf.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
#include <openssl/provider.h>
#include <openssl/core_names.h>
#endif //if (OPENSSL_VERSION_NUMBER >= 0x30000000)

#include <nxp_iot_agent.h>
#include <nxp_iot_agent_common.h>
#include <nxp_iot_agent_macros.h>
#include <nxp_iot_agent_session.h>

#ifndef NETWORK_malloc
#define NETWORK_malloc malloc
#endif

#ifndef NETWORK_free
#define NETWORK_free free
#endif

#ifndef _WIN32
#include <unistd.h>
#define closesocket(a) close(a)
#endif

static void warn_crt_crl_period(uint32_t verify_result)
{
	if ((verify_result == X509_V_ERR_CRL_HAS_EXPIRED) || (verify_result == X509_V_ERR_CRL_NOT_YET_VALID) ||
		(verify_result == X509_V_ERR_CERT_HAS_EXPIRED) || (verify_result == X509_V_ERR_CERT_NOT_YET_VALID))
	{
		IOT_AGENT_WARN("The certificate and/or CRL are outside of their validity period, which may be caused by the boards time being out of sync. \
						Please make sure that the time is correctly set.");
	}
}

#ifdef _WIN32

#pragma comment(lib,"ws2_32.lib") // Winsock Library

static int network_tcp_connect(const char *hostname, const int port, void* context)
{
    SOCKET* pSocket = (SOCKET*) context;

    WSADATA wsa;
    struct addrinfo hints;
    struct addrinfo *res;
    INT ret;
	
	// Winsock api expects the port as string. Convert it.
	char port_str[32] = { 0 };
	snprintf(port_str, sizeof(port_str), "%d", port);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        IOT_AGENT_ERROR("WSAStartup failed: %d", WSAGetLastError());
        return 1;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_TCP;
    ret = getaddrinfo(hostname, port_str, &hints, &res);

    if ((ret != 0) || (res == NULL)) {
        IOT_AGENT_ERROR("getaddrinfo failed: %d", WSAGetLastError());
        return 1;
    }

    *pSocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (*pSocket < 0) {
        IOT_AGENT_ERROR("socket open failed: %d", WSAGetLastError());
        return 1;
    }

    ret = connect(*pSocket, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (ret != 0) {
        closesocket(*pSocket);
        IOT_AGENT_ERROR("connect failed: %d", WSAGetLastError());
        return 1;
    }
    return 0;
}

#elif __linux__ || __APPLE__ || __CYGWIN__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

int network_tcp_connect(const char *hostname, const int port, void* context)
{
    int* sockfd = (int*) context;

    struct sockaddr_in serv_addr;
    struct hostent *server;

    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sockfd < 0)
    {
        IOT_AGENT_ERROR("ERROR opening socket");
        return 1;
    }
    server = gethostbyname(hostname);
    if (server == NULL)
    {
        IOT_AGENT_ERROR("ERROR, no such host");
        return 1;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = (unsigned short)AF_INET;
	if (server->h_length < 0) {
		IOT_AGENT_ERROR("ERROR in the length before casting it.");
		return 1;
	}
    bcopy((char *)server->h_addr,
         (char *)&serv_addr.sin_addr.s_addr,
         (size_t)server->h_length);
	if ((port < 0) || (port > UINT16_MAX))
	{
		IOT_AGENT_ERROR("Error in the port value");
		return 1;
	}
    serv_addr.sin_port = htons((unsigned short)port);
    if (connect(*sockfd,(struct sockaddr *) &serv_addr, (socklen_t)sizeof(serv_addr)) < 0)
    {
        IOT_AGENT_ERROR("ERROR connecting");
        return 1;
    }

    return 0;
}

#endif // _WIN32


void print_openssl_errors(char* function)
{
#ifdef ENABLE_IOT_AGENT_ERROR
	IOT_AGENT_ERROR("openssl error calling %s:", function);
	ERR_print_errors_fp(stderr);
#endif
}


int network_openssl_init(openssl_network_context_t* network_ctx) {
	int network_status = NETWORK_STATUS_OK;
#if (OPENSSL_VERSION_NUMBER < 0x30000000)
	AX_UNUSED_ARG(network_ctx);
	int openssl_status;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	// Load the config file:
	OpenSSL_add_all_algorithms();

	// Load error messages:
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
#else //if (OPENSSL_VERSION_NUMBER < 0x10100000L)	
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif //if (OPENSSL_VERSION_NUMBER < 0x10100000L)

	ENGINE *e = ENGINE_by_id(NETWORK_OPENSSL_ENGINE_ID);
	NETWORK_ASSERT_OR_EXIT_MSG(e != NULL, "Error finding OpenSSL Engine by id (id = %s)\n", NETWORK_OPENSSL_ENGINE_ID);

	IOT_AGENT_INFO("Setting log level OpenSSL-engine %s to 0x%02X.\n", NETWORK_OPENSSL_ENGINE_ID, NXP_IOT_AGENT_OPENSSL_ENGINE_LOG_LEVEL);
	openssl_status = ENGINE_ctrl(e, ENGINE_CMD_BASE, NXP_IOT_AGENT_OPENSSL_ENGINE_LOG_LEVEL, NULL, NULL);
	NETWORK_ASSERT_OR_EXIT_MSG(openssl_status == 1, "Using ENGINE_ctrl for setting log level failed: %d", openssl_status);
#else //if (OPENSSL_VERSION_NUMBER < 0x30000000)
	// In OpenSSL 3.x version of library the concept of using builtin providers was introduced. This allows quite some useful
	// features respect to the providers loaded via configuration file when using custom built providers as is the sssProvider:
	// - possibility to load/unload the provider during runtime
	// - possibility to retrieve the provider internal context => especially this feature is useful since allows the application
	//   to get the boot context of the sssProvider and control opening/closing of SE05x sessions
	// - possibility to get/set specific provider parameters

	// The first parameter set to NULL means that the default OpenSSL context will be used
	NETWORK_ASSERT_OR_EXIT_MSG(OSSL_PROVIDER_add_builtin(NULL, "nxp_prov", sssProvider_init) == 1, "Error adding builtin provider");

	network_ctx->sss_provider = OSSL_PROVIDER_load(NULL, "nxp_prov");
	NETWORK_ASSERT_OR_EXIT_MSG(network_ctx->sss_provider != NULL, "Error in loading the sssProvider provider");

	// The internal provider context will be useful for controlling the sessions from sssProvider to SE05x
	network_ctx->sss_provider_ctx = OSSL_PROVIDER_get0_provider_ctx(network_ctx->sss_provider);
	NETWORK_ASSERT_OR_EXIT_MSG(network_ctx->sss_provider_ctx != NULL, "Error in getting the sssProvider provider context");

	// After loading the sssProvider is mandatory to reload the default one which will act as fallback for crypto functionalities
	// not supported by the sssProvider
	NETWORK_ASSERT_OR_EXIT_MSG(OSSL_PROVIDER_load(NULL, "default") != NULL, "Error in loading the sefault provider");

	// The following property will instruct the default Open SSL context to preferably use the sssProvider cryptographic functionalities
	// if they are present
	NETWORK_ASSERT_OR_EXIT_MSG(EVP_set_default_properties(NULL, "?provider=nxp_prov") == 1,
		"Error in setting default properties");

#endif //if (OPENSSL_VERSION_NUMBER < 0x30000000)
exit:
#if (OPENSSL_VERSION_NUMBER < 0x30000000)
	ENGINE_free(e);
#endif //if (OPENSSL_VERSION_NUMBER < 0x30000000)
	return network_status;
}

int network_openssl_engine_session_connect(openssl_network_context_t* network_ctx) {

	int network_status = NETWORK_STATUS_OK;
#if (OPENSSL_VERSION_NUMBER < 0x30000000)
    AX_UNUSED_ARG(network_ctx);
	ENGINE *e = ENGINE_by_id(NETWORK_OPENSSL_ENGINE_ID);
	NETWORK_ASSERT_OR_EXIT_MSG(e != NULL, "Error finding OpenSSL Engine by id (id = %s)\n", NETWORK_OPENSSL_ENGINE_ID);

	// NOTE: Open engine connection to SE via Engine control interface
	IOT_AGENT_INFO("Open connection to secure element through Engine control interface (Engine=%s).\n", NETWORK_OPENSSL_ENGINE_ID);
	ENGINE_ctrl(e, ENGINE_CMD_BASE + 1, 0, NULL, NULL);
#else
	NETWORK_ASSERT_OR_EXIT_MSG(iot_agent_session_connect(network_ctx->sss_provider_ctx->p_ex_sss_boot_ctx) == IOT_AGENT_SUCCESS,
		"Error in opening session");
	if (ex_sss_boot_open_host_session(network_ctx->sss_provider_ctx->p_ex_sss_boot_ctx) != kStatus_SSS_Success) {
		IOT_AGENT_TRACE("ex_sss_boot_open_host_session return a failure: this can occur when the host session was open \
in the ex_sss_boot_open which is needed for SCP03 Authentication");
	}
#endif
exit:
#if (OPENSSL_VERSION_NUMBER < 0x30000000)
	ENGINE_free(e);
#endif //if (OPENSSL_VERSION_NUMBER < 0x30000000)
	return network_status;
}


int network_openssl_engine_session_disconnect(openssl_network_context_t* network_ctx) {
	int network_status = NETWORK_STATUS_OK;
#if (OPENSSL_VERSION_NUMBER < 0x30000000)
	AX_UNUSED_ARG(network_ctx);

	ENGINE *e = ENGINE_by_id(NETWORK_OPENSSL_ENGINE_ID);
	NETWORK_ASSERT_OR_EXIT_MSG(e != NULL, "Error finding OpenSSL Engine by id (id = %s)\n", NETWORK_OPENSSL_ENGINE_ID);

	IOT_AGENT_INFO("Close connection to secure element through Engine control interface (Engine=%s).\n", NETWORK_OPENSSL_ENGINE_ID);
	ENGINE_ctrl(e, ENGINE_CMD_BASE + 2, 0, NULL, NULL);
#else
	if (network_ctx != NULL) {
	iot_agent_session_disconnect(network_ctx->sss_provider_ctx->p_ex_sss_boot_ctx);
	}
#endif
#if (OPENSSL_VERSION_NUMBER < 0x30000000)
exit:
	ENGINE_free(e);
#endif //if (OPENSSL_VERSION_NUMBER < 0x30000000)
	return network_status;
}


void* network_new(void)
{
	openssl_network_context_t* network_ctx = (openssl_network_context_t*)NETWORK_malloc(sizeof(openssl_network_context_t));
	if (network_ctx != NULL) {
		memset(network_ctx, 0, sizeof(*network_ctx));
	}
	return network_ctx;
}


void network_free(void* ctx)
{
	if (ctx != NULL)
	{
		openssl_network_context_t* network_ctx = (openssl_network_context_t*) ctx;
		SSL_free(network_ctx->ssl);
		NETWORK_free(ctx);
	}
}


int network_configure(void* context, void* opaque_network_config)
{
	int network_status = NETWORK_STATUS_OK;
	const SSL_METHOD *method = NULL;
	SSL_CTX *ctx = NULL;
	EVP_PKEY* pkey = NULL;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
	EVP_PKEY_CTX* key_ctx = NULL;
	OSSL_PARAM* rsa_param = NULL;
#endif //if (OPENSSL_VERSION_NUMBER >= 0x30000000)
	NETWORK_ASSERT_OR_EXIT_MSG(context != NULL, "Network context is NULL");
	NETWORK_ASSERT_OR_EXIT_MSG(opaque_network_config != NULL, "Opaque netwrok config is NULL");
	openssl_network_context_t* network_context = (openssl_network_context_t*) context;
	openssl_network_config_t* network_config = (openssl_network_config_t*)opaque_network_config;
	network_context->network_config = *network_config;
#if (OPENSSL_VERSION_NUMBER < 0x30000000)
	pkey = network_config->private_key;
#else
	// OpenSSL 3.x is opening a session with SE05x from sssProvider as soon as the provider init
	// function is called. If between provider initialization and usage for signature calculation
	// SE05x will be used from the EL2GO Agent (for reading keys), the TLS hanshake will fail when
	// trying to compute the signature since will not be able to initialize SE05x. For this reason
	// all the provider initialization + EVP_PKEY creation is executed just before executing TLS
	// connection
	rsa_param = OSSL_PARAM_locate(network_config->private_key, OSSL_PKEY_PARAM_RSA_N);
	if (rsa_param == NULL) {
		key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=nxp_prov");
	} 
	else {
		key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=nxp_prov");
	}
	NETWORK_ASSERT_OR_EXIT_MSG(key_ctx != NULL, "Error getting context");

	NETWORK_ASSERT_OR_EXIT_MSG(EVP_PKEY_fromdata_init(key_ctx) == 1, "Error initializing key");
	pkey = EVP_PKEY_new();
	NETWORK_ASSERT_OR_EXIT_MSG(pkey != NULL, "private_key is NULL.");
	NETWORK_ASSERT_OR_EXIT_MSG(EVP_PKEY_fromdata(key_ctx, &pkey, EVP_PKEY_KEYPAIR, network_config->private_key) == 1,
		"Error getting  key from data");
#endif //if (OPENSSL_VERSION_NUMBER >= 0x30000000)
	if (SSL_library_init() < (int)0)
	{
		print_openssl_errors("SSL_library_init");
		return IOT_AGENT_ERROR_CRYPTO_ENGINE_FAILED;
	}

	// Set SSLv2 client hello, also announce SSLv3 and TLSv1
	method = SSLv23_client_method();

	if ((ctx = SSL_CTX_new(method)) == NULL)
	{
		print_openssl_errors("SSL_CTX_new");
		return IOT_AGENT_ERROR_CRYPTO_ENGINE_FAILED;
	}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	// Disabling SSLv2 will leave v3 and TSLv1 for negotiation
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
#else //if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	// As of OpenSSL 1.1.0, setting protocol versions using set_options is 
	// deprecated, use SSL_CTX_set_min_proto_version() and 
	// SSL_CTX_set_max_proto_version() instead.
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
#endif //if (OPENSSL_VERSION_NUMBER < 0x10100000L)

	if (SSL_CTX_use_certificate(ctx, network_config->certificate) != 1)
	{
		print_openssl_errors("SSL_CTX_use_certificate");
		SSL_CTX_free(ctx);
		return IOT_AGENT_ERROR_CRYPTO_ENGINE_FAILED;
	}

	if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
	{
		print_openssl_errors("SSL_CTX_use_PrivateKey");
		SSL_CTX_free(ctx);
		return IOT_AGENT_ERROR_CRYPTO_ENGINE_FAILED;
	}

#if NXP_IOT_AGENT_VERIFY_EDGELOCK_2GO_SERVER_CERTIFICATE
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set1_verify_cert_store(ctx, network_config->ca_chain);
#else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
#endif

	// Create new SSL connection state object
	network_context->ssl = SSL_new(ctx);

exit:
	// The ctx is not needed any more
	SSL_CTX_free(ctx);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
	EVP_PKEY_CTX_free(key_ctx);
	EVP_PKEY_free(pkey);
#endif //if (OPENSSL_VERSION_NUMBER >= 0x30000000)

	return network_status;
}


int network_connect(void* opaque_ctx)
{
	openssl_network_context_t* network_context = (openssl_network_context_t*) opaque_ctx;
	openssl_network_config_t* network_config = &network_context->network_config;
	SSL *ssl = network_context->ssl;
	int socket;

	// Make the underlying TCP socket connection
	if ((network_tcp_connect(network_config->hostname, network_config->port, &socket) != 0) || socket == 0)
	{
		IOT_AGENT_ERROR("%s: %s", __FUNCTION__, "connecting tcp socket failed");
		return 1;
	}

	// Attach the SSL session to the socket descriptor
	if (SSL_set_fd(ssl, socket) != 1)
	{
		print_openssl_errors("SSL_set_fd");
		return 1;
	}

	// Make openssl verify also the servername in the certificate.
#if NXP_IOT_AGENT_VERIFY_EDGELOCK_2GO_SERVER_CERTIFICATE
	#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
	if (!X509_VERIFY_PARAM_set1_host(param, network_config->hostname, strlen(network_config->hostname))) {
		print_openssl_errors("X509_VERIFY_PARAM_set1_host");
		return 1;
	}
	#else
	if (!SSL_set1_host(ssl, network_config->hostname)) {
		print_openssl_errors("SSL_set1_host");
		return 1;
	}
	#endif
#endif

	// Make openssl send a server name indication (SNI) extension.
	SSL_set_tlsext_host_name(ssl, network_config->hostname);
	
	// Try to SSL-connect here, returns 1 for success
	if (SSL_connect(ssl) != 1)
	{
		long verify_result = SSL_get_verify_result(ssl);
		if ((verify_result < 0) || (verify_result > INT32_MAX)) {
			IOT_AGENT_ERROR("SSL_connect failed");
		}
		else {
		warn_crt_crl_period(verify_result);
		IOT_AGENT_ERROR("SSL_connect failed, verify result (see man openssl verify): 0x%08x", verify_result);
		}
		print_openssl_errors("SSL_connect");
		return 1;
	}

	return 0;
}

#if (OPENSSL_VERSION_NUMBER >= 0x10101000L)
static X509_CRL* d2i_X509_CRL_buffer(const uint8_t* buffer, size_t sz) {
	if (sz > INT32_MAX) {
		IOT_AGENT_ERROR("Issue in casting the size variable");
	}
	BIO* bio = BIO_new_mem_buf(buffer, (int)sz);
	if (bio == NULL) return NULL;
	X509_CRL * crl = d2i_X509_CRL_bio(bio, NULL);
	BIO_free(bio);
	return crl;
}

static X509* d2i_X509_buffer(const uint8_t* buffer, size_t sz) {
	if (sz > INT32_MAX) {
		IOT_AGENT_ERROR("Issue in casting the size variable");
	}
	BIO* bio = BIO_new_mem_buf(buffer, (int)sz);
	if (bio == NULL) return NULL;
	X509 * cert = d2i_X509_bio(bio, NULL);
	BIO_free(bio);
	return cert;
}
#endif

static void network_print_X509_NAME(X509_NAME* name) {
	if (name == NULL) {
		printf("NULL");
		return;
	}
	for (int i = 0; i < X509_NAME_entry_count(name); i++) {
		X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
		ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(entry);
		int nid = OBJ_obj2nid(obj);
		const char* short_name = OBJ_nid2sn(nid);
		ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
		printf("            %s = ", short_name);
		ASN1_STRING_print_ex_fp(stdout, data, ASN1_STRFLGS_RFC2253);
		printf("\n");
	}
}

int network_verify_server_certificate(void* opaque_ctx, uint8_t* trusted_bytes, size_t trusted_size, 
	uint8_t* crl_bytes, size_t crl_size, uint32_t* error)
{
#if (OPENSSL_VERSION_NUMBER < 0x10101000L)
	IOT_AGENT_WARN("CRL verification is not implemented for openssl versions < 1.1.1.");
	IOT_AGENT_WARN("The certificate is considered VALID.");
	return NETWORK_STATUS_OK;
#else
	openssl_network_context_t* network_ctx = (openssl_network_context_t*)opaque_ctx;
	SSL* ssl = network_ctx->ssl;

	STACK_OF(X509)* untrusted = NULL;
	X509* to_be_verified = NULL;
	BIO* trusted_cert_bio = NULL;
	X509_CRL * crl = NULL;
	X509_STORE* truststore = NULL;
	X509_STORE_CTX* verify_store = NULL;
	X509_VERIFY_PARAM* param = NULL;

	int network_status = NETWORK_STATUS_OK;
	int openssl_status = 1;

	// Note: SSL_get_peer_certificate does NOT increment the reference counter on 
	// any certificate. The ownership stays with the SSL object!
	untrusted = SSL_get_peer_cert_chain(ssl);
	NETWORK_ASSERT_OR_EXIT_MSG(sk_X509_num(untrusted) > 0, "No untrusted server certs found.");
	to_be_verified = sk_X509_value(untrusted, 0);
	NETWORK_ASSERT_OR_EXIT_MSG(to_be_verified != NULL, "Cannot extract server certificate from untrusted certificates.");

	crl = d2i_X509_CRL_buffer(crl_bytes, crl_size);
	NETWORK_ASSERT_OR_EXIT_MSG(crl != NULL, "Error parsing CRL.");

	truststore = X509_STORE_new();
	NETWORK_ASSERT_OR_EXIT_MSG(truststore != NULL, "Error creating truststore.");

	NETWORK_ASSERT_OR_EXIT_STATUS_MSG(trusted_size <= INT32_MAX, NETWORK_STATUS_FAIL, "Issue in casting of trusted size variable.");
	trusted_cert_bio = BIO_new_mem_buf(trusted_bytes, trusted_size);
	while (true) {
		X509* trusted_cert = d2i_X509_bio(trusted_cert_bio, NULL);
		if (trusted_cert == NULL) {
			// We try here to parse certificates until there is no more data left. The 
			// last attempt (where no data is remaining) causes an error in the openssl 
			// error queue (for unparsable certificate). We should clear that one here so it 
			// can not cause unexpexted errors elsewhere. The error code is unused.
			(void)ERR_get_error();
			break;
		}
		openssl_status = X509_STORE_add_cert(truststore, trusted_cert);
		X509_free(trusted_cert);
		trusted_cert = NULL;
		NETWORK_ASSERT_OR_EXIT_MSG(openssl_status == 1, "Error adding root CA certificate to truststore.");
	}

	openssl_status = X509_STORE_add_crl(truststore, crl);
	NETWORK_ASSERT_OR_EXIT_MSG(openssl_status == 1, "Error adding CRL to truststore.");

	verify_store = X509_STORE_CTX_new();
	NETWORK_ASSERT_OR_EXIT_MSG(verify_store != NULL, "Error creating verify store.");
	openssl_status = X509_STORE_CTX_init(verify_store, truststore, to_be_verified, untrusted);
	NETWORK_ASSERT_OR_EXIT_MSG(openssl_status == 1, "Error initializing verify store.");

	param = X509_VERIFY_PARAM_new();
	NETWORK_ASSERT_OR_EXIT_MSG(param != NULL, "Error creating verification parameters.");
	openssl_status = X509_VERIFY_PARAM_set_flags(param, X509_VERIFY_PARAM_get_flags(param) | X509_V_FLAG_CRL_CHECK);
	NETWORK_ASSERT_OR_EXIT_MSG(openssl_status == 1, "Error creating verification parameters.");
	X509_VERIFY_PARAM_set_depth(param, 10);
	// Note: the openssl set0 functions make the context take ownership of 
	// the object that is set. Therefore, we do not free param ourselves.
	X509_STORE_CTX_set0_param(verify_store, param);

	openssl_status = X509_verify_cert(verify_store);
	int x509_store_status = X509_STORE_CTX_get_error(verify_store);
	NETWORK_ASSERT_OR_EXIT_STATUS_MSG(x509_store_status >= 0, NETWORK_STATUS_FAIL, "Error in execution of get error function,");
	*error = x509_store_status;
	warn_crt_crl_period(*error);
	NETWORK_ASSERT_OR_EXIT_MSG(openssl_status == 1, "Server cert verification with CRL failed. Openssl indicates error %d.", *error);

exit:
#if ENABLE_IOT_AGENT_DEBUG
	printf("openssl CRL verification for \n    Certificate:\n        Subject:\n");
	network_print_X509_NAME(X509_get_subject_name(to_be_verified));
	printf("        Issuer:\n");
	network_print_X509_NAME(X509_get_issuer_name(to_be_verified));
	printf("    with CRL:\n        Issuer:\n");
	network_print_X509_NAME(X509_CRL_get_issuer(crl));
	printf("    completed with status: %d\n", *error);
#endif
	X509_STORE_CTX_free(verify_store);
	BIO_free(trusted_cert_bio);
	X509_STORE_free(truststore);
	X509_CRL_free(crl);
	X509_free(to_be_verified);

	return network_status;
#endif
}

int network_disconnect(void* opaque_ctx)
{
	int network_status = NETWORK_STATUS_OK;
	uint8_t dummy_read[512];
	openssl_network_context_t* network_ctx = (openssl_network_context_t*) opaque_ctx;
	SSL* ssl = network_ctx->ssl;
	// Send the close_notify to the server.
	int openssl_status = SSL_shutdown(ssl);
	if (openssl_status == 0) {
		// Wait for the server's close_notify.
		do {
			openssl_status = SSL_read(ssl, dummy_read, sizeof(dummy_read));
		} while (openssl_status > 0);

		// We would expect an SSL_ERROR_ZERO_RETURN. However, if we do 
		// not, we can continue as well, since the SSL connection is no 
		// longer in use. Just inform the user but still continue 
		// the shutdown.
		int openssl_error = SSL_get_error(ssl, openssl_status);
		if (openssl_error != SSL_ERROR_ZERO_RETURN) {
			print_openssl_errors("SSL_shutdown");
		}
	}

	int socket_fd = SSL_get_fd(ssl);

	if (socket_fd < 0)
	{
		IOT_AGENT_ERROR("Socket close failed");
		network_status = NETWORK_STATUS_FAIL;
		goto exit;
	}
	
	network_status = closesocket(socket_fd);
	
exit:
#ifdef _WIN32
	if (WSACleanup() != 0)
	{
		IOT_AGENT_ERROR("WSACleanup failed: %d", WSAGetLastError());
		network_status = NETWORK_STATUS_FAIL;
	}
#endif
	return network_status;
}


int network_read(void* context, uint8_t* buffer, size_t len)
{
    openssl_network_context_t* network_ctx = (openssl_network_context_t*) context;
    SSL* ssl = network_ctx->ssl;
	if (len > INT32_MAX)
	{
		IOT_AGENT_ERROR("Error in checking the size of length variable");
	}
    return SSL_read(ssl, buffer, len);
}

int network_write(void* context, const uint8_t* buffer, size_t len)
{
    openssl_network_context_t* network_ctx = (openssl_network_context_t*) context;
    SSL* ssl = network_ctx->ssl;
	if (len > INT32_MAX)
	{
		IOT_AGENT_ERROR("Error in checking the size of length variable");
	}
    return SSL_write(ssl, buffer, len);
}

