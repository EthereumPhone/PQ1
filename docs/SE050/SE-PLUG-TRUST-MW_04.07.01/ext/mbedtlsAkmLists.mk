# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

#This file is required for ANDROID to compile all mbedtls realted  source files.
#Android Keymaster is having dependancies on below source files. 

MBEDTLS_SRC_FILES_LIST := \
		ext/mbedtls/library/aes.c \
		ext/mbedtls/library/aesni.c \
		ext/mbedtls/library/arc4.c \
		ext/mbedtls/library/aria.c \
		ext/mbedtls/library/asn1parse.c \
		ext/mbedtls/library/asn1write.c \
		ext/mbedtls/library/base64.c \
		ext/mbedtls/library/bignum.c \
		ext/mbedtls/library/blowfish.c \
		ext/mbedtls/library/camellia.c \
		ext/mbedtls/library/ccm.c \
		ext/mbedtls/library/certs.c \
		ext/mbedtls/library/chacha20.c \
		ext/mbedtls/library/chachapoly.c \
		ext/mbedtls/library/cipher.c \
		ext/mbedtls/library/cipher_wrap.c \
		ext/mbedtls/library/cmac.c \
		ext/mbedtls/library/constant_time.c \
		ext/mbedtls/library/ctr_drbg.c \
		ext/mbedtls/library/debug.c \
		ext/mbedtls/library/des.c \
		ext/mbedtls/library/dhm.c \
		ext/mbedtls/library/ecdh.c \
		ext/mbedtls/library/ecdsa.c \
		ext/mbedtls/library/ecjpake.c \
		ext/mbedtls/library/ecp.c \
		ext/mbedtls/library/ecp_curves.c \
		ext/mbedtls/library/entropy.c \
		ext/mbedtls/library/entropy_poll.c \
		ext/mbedtls/library/error.c \
		ext/mbedtls/library/gcm.c \
		ext/mbedtls/library/havege.c \
		ext/mbedtls/library/hkdf.c \
		ext/mbedtls/library/hmac_drbg.c \
		ext/mbedtls/library/md.c \
		ext/mbedtls/library/md2.c \
		ext/mbedtls/library/md4.c \
		ext/mbedtls/library/md5.c \
		ext/mbedtls/library/memory_buffer_alloc.c \
		ext/mbedtls/library/net_sockets.c \
		ext/mbedtls/library/nist_kw.c \
		ext/mbedtls/library/oid.c \
		ext/mbedtls/library/padlock.c \
		ext/mbedtls/library/pem.c \
		ext/mbedtls/library/pk.c \
		ext/mbedtls/library/pk_wrap.c \
		ext/mbedtls/library/pkcs11.c \
		ext/mbedtls/library/pkcs12.c \
		ext/mbedtls/library/pkcs5.c \
		ext/mbedtls/library/pkparse.c \
		ext/mbedtls/library/pkwrite.c \
		ext/mbedtls/library/platform.c \
		ext/mbedtls/library/platform_util.c \
		ext/mbedtls/library/poly1305.c \
		ext/mbedtls/library/psa_crypto.c \
		ext/mbedtls/library/psa_crypto_client.c \
		ext/mbedtls/library/psa_crypto_driver_wrappers.c \
		ext/mbedtls/library/psa_crypto_ecp.c \
		ext/mbedtls/library/psa_crypto_rsa.c \
		ext/mbedtls/library/psa_crypto_se.c \
		ext/mbedtls/library/psa_crypto_slot_management.c \
		ext/mbedtls/library/psa_crypto_storage.c \
		ext/mbedtls/library/psa_its_file.c \
		ext/mbedtls/library/ripemd160.c \
		ext/mbedtls/library/rsa.c \
		ext/mbedtls/library/rsa_internal.c \
		ext/mbedtls/library/sha1.c \
		ext/mbedtls/library/sha256.c \
		ext/mbedtls/library/sha512.c \
		ext/mbedtls/library/ssl_cache.c \
		ext/mbedtls/library/ssl_ciphersuites.c \
		ext/mbedtls/library/ssl_cli.c \
		ext/mbedtls/library/ssl_cookie.c \
		ext/mbedtls/library/ssl_msg.c \
		ext/mbedtls/library/ssl_srv.c \
		ext/mbedtls/library/ssl_ticket.c \
		ext/mbedtls/library/ssl_tls.c \
		ext/mbedtls/library/ssl_tls13_keys.c \
		ext/mbedtls/library/threading.c \
		ext/mbedtls/library/timing.c \
		ext/mbedtls/library/version.c \
		ext/mbedtls/library/version_features.c \
		ext/mbedtls/library/x509.c \
		ext/mbedtls/library/x509_create.c \
		ext/mbedtls/library/x509_crl.c \
		ext/mbedtls/library/x509_crt.c \
		ext/mbedtls/library/x509_csr.c \
		ext/mbedtls/library/x509write_crt.c \
		ext/mbedtls/library/x509write_csr.c \
		ext/mbedtls/library/xtea.c
