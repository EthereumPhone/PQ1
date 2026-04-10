..
    Copyright 2019,2024 NXP



.. _mbedTLS-alt:

Introduction on MbedTLS ALT (2.x) Implementation
=========================================================

MbedTLS ALT implementation allows mbedTLS stack use the secure element
access using SSS layer. Crypto operations performed during TLS handshake
between client and server are performed using the secure element.


SE05X usage in TLS handshake (ECC Cipher suites)
---------------------------------------------------------

SE05X is used for following operations during TLS handshake

1) Verification using root CA pub key (root CA public key provisioned in SE05X)

#) Calculate shared key using sss_derive_key_dh (only for ECDH cipher suites. For ECDHE, ecc key and shared secret are generated on host).

#) Sign handshake messages using provisioned client key.

#) Optional - All public key ECDSA verify operation.



SE05X usage in TLS handshake (RSA Cipher suites)
---------------------------------------------------------

SE05X is used for following operations during TLS handshake

1) Verification using root CA pub key (root CA public key provisioned in SE05X).

#) Sign handshake messages using provisioned client key.

#) Optional - All public key ECDSA verify operation. Public key is set during TLS handshake.


Using SE05X for all Public key ECDSA verify operation
---------------------------------------------------------

With default mbedtls config file, SE05X is used only for Root CA public key verify operation.
To use secure element for all public key ecdsa verify operation, enable ``MBEDTLS_ECDSA_VERIFY_ALT`` in mbedtls config file.

This feature will add some limitations as explained below.

1) NVM writes will be observed when public key is set in secured element during TLS handshake.

#) NVM writes can be avoided by overwriting the existing keys without deleting the last created key. But this limits the number of key types that can be used for handshake due to limited transient memory.

To avoid the NVM writes, modify the function `mbedtls_ecdsa_verify` in :file:`sss/plugin/mbedtls/ecdsa_verify_alt.c`. Create the required key type object in your application and use this key object in function `mbedtls_ecdsa_verify` for verify operation. Do not delete the keyobject at the end of verify operation.

Also when ``MBEDTLS_ECDSA_VERIFY_ALT`` is enabled, set the sss key store from application using api `sss_mbedtls_set_sss_keystore`. Refer example :file:`sss/ex/mbedtls/ex_sss_ssl2.c`.

.. literalinclude:: ../../../ex/mbedtls/ex_sss_ssl2.c
    :language: c
    :dedent: 8
    :start-after: /* doc+:ecdsa-verify-alt-set-keystore */
    :end-before: /* doc-:ecdsa-verify-alt-set-keystore */

Using mbedTLS ALT
---------------------------------------------------------

For reference, let's look at the :file:`sss/ex/mbedtls/ex_sss_ssl2.c`.
The important sections of the file are.

Here we initialize the keys and relevent objects.

.. literalinclude:: ../../../ex/mbedtls/ex_sss_ssl2.c
    :language: c
    :start-after: /* doc+:initialize-key-objs */
    :end-before: /* doc-:initialize-key-objs */

Here, we tell mbedTLS to use the root CA public key from the SE.

.. literalinclude:: ../../../ex/mbedtls/ex_sss_ssl2.c
    :language: c
    :dedent: 8
    :start-after: /* doc+:use-public-key-from-se */
    :end-before: /* doc-:use-public-key-from-se */

Here, get certificate in DER format from the SE, and then convert it to PEM and share it with the mbedTLS stack.

.. literalinclude:: ../../../ex/mbedtls/ex_sss_ssl2.c
    :language: c
    :dedent: 12
    :start-after: /* doc+:load-certificate-from-se */
    :end-before: /* doc-:load-certificate-from-se */

Here, we tell mbedTLS to use the device private key from the SE, generally for signing any contents.

.. literalinclude:: ../../../ex/mbedtls/ex_sss_ssl2.c
    :language: c
    :dedent: 8
    :start-after: /* doc+:set-handle-to-use-private-key-from-se */
    :end-before: /* doc-:set-handle-to-use-private-key-from-se */

Here, we tell mbedTLS to use the private key from the SE for ECDH handshake.

.. literalinclude:: ../../../ex/mbedtls/ex_sss_ssl2.c
    :language: c
    :dedent: 12
    :start-after: /* doc+:use-private-key-for-ecdh */
    :end-before: /* doc-:use-private-key-for-ecdh */



Testing on x86 / Linux
---------------------------------------------------------

Building mbedTLS SSL/DTLS server for testing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Build mbedTLS server - :

CMake configurations:

- ``RTOS_Default``: ON
- ``SSS_HAVE_HOSTCRYPTO_MBEDTLS``: ON
- ``SSS_HAVE_MBEDTLS_ALT_SSS``: ON

- Project: ``mbedtls_ex_orig_ssl_server2`` / ``mbedtls_ex_orig_dtls_server``


Building mbedTLS SSL/DTLS client (with SSS-APIs integration) for x86 / Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Build mbedTLS client - :

CMake configurations:

- ``RTOS_Default``: ON
- ``SSS_HAVE_HOSTCRYPTO_MBEDTLS``: ON
- ``SSS_HAVE_MBEDTLS_ALT_SSS``: ON

- Project: ``mbedtls_ex_sss_ssl2_client`` / ``mbedtls_ex_sss_dtls_client``


Running examples
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Directory ``simw-top\sss\plugin\mbedtls\scripts`` contains test scripts for
starting mbedTLS server and client applications with different cipher suites.
Before executing some test scripts, the secure element must first be
provisioned.

1)  Complete :numref:`cli-doc-pre-steps` :ref:`cli-doc-pre-steps`


#)  Provision secure element using python scripts in directory
    ``simw-top\sss\plugin\mbedtls\scripts``.
    Run the following commands in virtual environment:

    To provision secure element for ECC
        ``python3 create_and_provision_ecc_keys.py <keyType> <connection_type> <connection_string> <iot_se (optional. Default - se050)> <auth (optional. Default - None)> <auth_key>``

    To configure secure element for RSA
        ``python3 create_and_provision_rsa_keys.py <keyType> <connection_type> <connection_string> <auth (optional. Default - None)> <auth_key>``

    To see possible values of input arguments, run without any parameters
        ``create_and_provision_ecc_keys.py.`` or ``create_and_provision_rsa_keys.py``

    .. note::
        Once provisioning is done the virtual environment is not needed anymore.


#)  Starting mbedTLS SSL client and server applications::

        python3 start_ssl2_server.py <ec_curve>/<rsa_type>
        python3 start_ssl2_client.py <ec_curve>/<rsa_type> <cipher suite> <connection_string>

#)  Starting mbedTLS DTLS client and server applications::

        python3 start_dtls_server.py <ec_curve>/<rsa_type>
        python3 start_dtls_client.py <ec_curve>/<rsa_type> <cipher suite> <connection_string>



Testing mbedTLS client on frdm-k64
----------------------------------

Run SSL Server example on Windows / Linux. Refer previous section to build server example.

Building mbedTLS SSL client (with SSS-APIs integration) for k64
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The client example when run on micro-controller, takes the keys and certificates from
:file:`simw-top\\sss\\ex\\mbedtls\\mbed_lwip_client\\ex_sss_ssl2.h`.
Ensure that the file is updated with server ip address, key type and keys.

Build mbedTLS client for k64f:

CMake configurations:

- ``RTOS_FreeRTOS``: ON
- ``SSS_HAVE_HOSTCRYPTO_MBEDTLS``: ON
- ``SSS_HAVE_MBEDTLS_ALT_SSS``: ON
- ``SSS_HAVE_HOST_FRDMK64F`` : ON

- Project: ``mbedtls_ex_se05x_client_lwip``


Running examples
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1) On x86 / Linux machine - Start mbedtls server (add server_addr argument) as ::

        ./mbedtls_ex_orig_ssl_server2 exchanges=1 force_version=tls12 debug_level=1 ca_file=simw-top\sss\plugin\mbedtls\keys\prime256v1\tls_rootca.cer auth_mode=required key_file=simw-top\sss\plugin\mbedtls\keys\prime256v1\tls_server_key.pem crt_file=simw-top\sss\plugin\mbedtls\keys\prime256v1\tls_server.cer server_addr=<ip_address>

#) Flash mbedTLS client (mbedtls_ex_se05x_client_lwip) on K64F,








SE050 Performance Measurements
---------------------------------------------------------

The following measurements are performed on K-64 board with SE050 connected via T10I2C.


TLS1.2 using ECC Nist256 Keys (Using MbedTLS Alt)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ciphersuite used for TLS - TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA

Read the numbers as MIN - AVG - MAX milliseconds.

.. tabularcolumns:: |C|C|C|C|

================================  =====================  ====================  ===================
Operation                         SE05X (Auth - None)    K64 (with O0)         K64 (with O2)
================================  =====================  ====================  ===================
Server Certificate Verification   49  - 49.6  - 50       1885 - 1885.4 - 1887  754  - 754.2 - 755
DH key generation                 54  - 54  - 54         911 -  913.8 - 915    363  - 364.4 - 366
Sign Operation                    50  - 51.8  - 59       952 -  956   - 959    382  - 384   - 386

================================  =====================  ====================  ===================

sss_derive_key_dh is used for DH calulation. Time measured includes - set other party public key on host, Derive key, Get DH key from host.


TLS1.2 using RSA2048 (CRT) Keys (Using MbedTLS Alt)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ciphersuite used for TLS - TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256

Read the numbers as MAX - AVG - MIN milliseconds.

.. tabularcolumns:: |C|C|C|C|

================================  ===================  =====================  ====================
Operation                         SE05X (Auth - None)  K64 (with O0)          K64 (with O2)
================================  ===================  =====================  ====================
Server Certificate Verification    49 - 49.8  - 50     172 - 172.2  - 172     26 - 26.8  - 27
DH key generation                  NA -  NA   - NA     3151 - 3157.4 - 3179   813 - 834.6 - 847
Sign Operation                     102 - 102.4 - 103   8450 -  8521  - 8571   1143 - 1152  - 1164

================================  ===================  =====================  ====================

Secp521r1 key is used for DH.



mbedTLS ALT APIs
---------------------------------------------------------

.. doxygengroup:: ax_mbed_tls
    :no-link:
    :members:
    :protected-members:
    :private-members:
    :undoc-members:

