..
    Copyright 2024 NXP



.. _mbedTLS-3x-alt:

Introduction on Mbed TLS (3.x) ALT Implementation
=========================================================

Mbed TLS ALT implementation allows Mbed TLS stack use the secure element
access using SSS layer. Crypto operations performed during TLS handshake
between client and server are performed using the secure element.


Crypto operations supported -

1) ECDSA Sign.  (:file:`sss/plugin/mbedtls3x/ecdsa_sign_alt.c`)

#) ECDSA Verify.  (:file:`sss/plugin/mbedtls3x/ecdsa_verify_alt.c`)

#) RSA Sign.  (:file:`sss/plugin/mbedtls3x/rsa_alt.c`)

#) RSA Verify.  (:file:`sss/plugin/mbedtls3x/rsa_alt.c`)

#) Random number generation (:file:`sss/plugin/mbedtls3x/ctr_drbg_alt.c`)

#) ECDH (:file:`sss/plugin/mbedtls3x/ecdh_alt.c`)


.. note ::

    In the default implementation, every time the control goes to ALT implementation,
    session open and close is performed. This will have all transient objects will be lost.
    To avoid the session open / close in ALT implementation,
    Use the sss_mbedtls_set_keystore_ecdsa_sign() / sss_mbedtls_set_keystore_ecdsa_verify()/
    sss_mbedtls_set_keystore_rsa() / sss_mbedtls_set_keystore_rng() / sss_mbedtls_set_keystore_ecdh()
    APIs to pass the keystore.



Key Management
--------------

Mbed TLS requires a key pair, consisting of a private and a public key, to be
loaded before the cryptographic operations can be executed. This creates a
challenge when Mbed TLS is used in combination with a secure element as the
private key cannot be extracted out from the Secure Element.

The solution is to populate the Key data structure with only a
reference to the Private Key inside the Secure Element instead of the actual
Private Key. The public key as read from the Secure Element can still be
inserted into the key structure.

When the control comes to the ALT implementation, we check if the key is a
reference key or not. In case of reference key, the key id is extracted and
Secure element is used to perform Sign operation. If the key is not a reference key,
execution will roll back to software implementation.

Refer :ref:`ec-reference-key-format` and :ref:`rsa-reference-key-format` for reference key details.



Build / Configuration of Mbed TLS ALT files
-------------------------------------------

Mbed TLS library can be built with above ALT files using the below cmake options

CMake configurations (To be applied on top of a configured host build area)::

    cmake -DPTMW_HostCrypto:STRING=MBEDTLS -DPTMW_MBedTLS:STRING=3_X -DPTMW_mbedTLS_ALT:STRING=SSS .


The custom config file to enable required ALT operation is present in :file:`sss/plugin/mbedtls3x/mbedtls_sss_alt_config.h`
By default ECDSA Sign and RSA Sign are enabled.


Use the below macros in the config file (:file:`sss/plugin/mbedtls3x/mbedtls_sss_alt_config.h`)
to enable / disable required crypto operation

- MBEDTLS_ECDSA_SIGN_ALT

- MBEDTLS_ECDSA_VERIFY_ALT

- MBEDTLS_RSA_ALT

- MBEDTLS_ECDH_COMPUTE_SHARED_ALT


.. note ::

    1. RSA Verify is disabled by default. Enable `SSS_ENABLE_RSA_ALT_VERIFY` in :file:`sss/plugin/mbedtls3x/rsa_alt.c`.
    (Key id used for storing the public key is - 0x7D000021)


    2. When ECDSA Verify / RSA Verify is enabled, KeyId - 0x7D000011(for ECC) / 0x7D000021(for RSA) is used to store the public key (a transient key is created and will reduce the available RAM memory on secure element) and do the Verify operation.
    Assuming first time a NIST P256 key is set, only a NIST P256 key can be overwritten here for next ECDSA Verify.
    Any other key type if used, will result in error during set key.

    Solution -
    Enable `SSS_DELETE_SE05X_TMP_ECC_PUBLIC_KEY` / `SSS_DELETE_SE05X_TMP_RSA_PUBLIC_KEY` to delete the key after every Verify operation.
    This will ensure a new key is created next time and the implementation will work for all key types.
    NOTE THAT, THIS WILL RESULT IN NVM FLASH WRITES.


    3. Random number generation has no ALT define in Mbed TLS config file.
    The ctr_drbg.c file is reimplemented to use Secure Element is used while building the Mbed TLS with SSS_ALT config.
    To enable / disable the random number generation from SE, use `SSS_ENABLE_RND_ALT` in :file:`sss/plugin/mbedtls3x/ctr_drbg_alt.c`.

    4. When using any authenticated session, make sure to disable the random number generation ALT functionality (`SSS_ENABLE_RND_ALT`), to avoid
    using Secure Element before the session is open.




SE05X usage in TLS handshake
----------------------------

SE05X is used for following operations during TLS handshake.

1) Sign handshake messages using provisioned client key.

#) Optional - All public key verify operation. Public key is injected / deleted during TLS handshake.



Testing Mbed TLS ALT (Windows)
-------------------------------

Mbed TLS client and server example can be used to test the Mbed TLS ALT implementation.

- Project: ``mbedtls_3x_client`` and ``mbedtls_3x_server``


Build client example with ALT option enabled (-DPTMW_mbedTLS_ALT:STRING=SSS) and
server example with ALT option disabled (-DPTMW_mbedTLS_ALT:STRING=None)


Running examples -

Directory ``simw-top\sss\plugin\mbedtls3x\scripts`` contains test scripts for
starting Mbed TLS server and client applications with different cipher suites.
Before executing some test scripts, the secure element must first be
provisioned.

1)  Complete :numref:`cli-doc-pre-steps` :ref:`cli-doc-pre-steps`


#)  Provision secure element using python scripts in directory
    ``simw-top\sss\plugin\mbedtls3x\scripts``.
    Run the following commands in virtual environment:

    To provision secure element for ECC
        ``python3 create_and_provision_ecc_keys.py <keyType> <connection_type> <connection_string> <iot_se (optional. Default - se050)> <auth (optional. Default - None)> <auth_key>``

    To configure secure element for RSA
        ``python3 create_and_provision_rsa_keys.py <keyType> <connection_type> <connection_string> <auth (optional. Default - None)> <auth_key>``

    To see possible values of input arguments, run without any parameters
        ``create_and_provision_ecc_keys.py.`` or ``create_and_provision_rsa_keys.py``

    .. note::
        Once provisioning is done the virtual environment is not needed anymore.
        when running with vcom export port using EX_SSS_BOOT_SSS_PORT=<COM_PORT>.

#)  Starting Mbed TLS SSL client and server applications::

        python3 start_ssl2_server.py <ec_curve>/<rsa_type>
        python3 start_ssl2_client.py <ec_curve>/<rsa_type> <cipher suite>
