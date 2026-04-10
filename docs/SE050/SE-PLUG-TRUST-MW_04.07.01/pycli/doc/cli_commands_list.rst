

..
    Copyright 2019,2020,2025 NXP

.. highlight:: bat

.. _cli-cmd-list:

==================================
List of ``ssscli`` commands
==================================

ssscli uses PEM, DER and HEX data formats for keys and certificates. Refer :ref:`cli-data-format`.

.. note:: Linux Environment

    You can ``source pycli/ssscli-bash-completion.sh`` for auto-completion
    on bash with linux/posix based environemnt.


ssscli Commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These are the top level commands accepted by the ssscli Tool.

1) ``ssscli``::

    Usage: ssscli [OPTIONS] COMMAND [ARGS]...

      Command line interface for SE050

    Options:
      -v, --verbose  Enables verbose mode.
      --version      Show the version and exit.
      --help         Show this message and exit.

    Commands:
      cloud       (Not Implemented) Cloud Specific utilities.
      connect     Open Session.
      decrypt     Decrypt Operation
      disconnect  Close session.
      encrypt     Encrypt Operation
      erase       Erase ECC/RSA/AES Keys or Certificate (contents)
      generate    Generate ECC/RSA Key pair
      get         Get ECC/RSA/AES Keys or certificates
      policy      Create/Dump Object Policy
      refpem      Create Reference PEM/DER files (For OpenSSL Engine).
      se05x       SE05X specific commands
      set         Set ECC/RSA/AES Keys or certificates
      sign        Sign Operation
      verify      verify Operation


#) ``ssscli connect``::

    Usage: ssscli connect [OPTIONS] subsystem method port_name

      Open Session.

      subsystem = Security subsystem is selected to be used. Can be one of "se05x,
      auth, mbedtls, openssl"

      method = Connection method to the system. Can be one of "none, sci2c, vcom,
      t1oi2c, jrcpv1, jrcpv2, pcsc"

      port_name = Subsystem specific connection parameters. Example: COM6,
      127.0.0.1:8050. Use "None" where not applicable. e.g. SCI2C/T1oI2C. Default
      i2c port (i2c-1) will be used for port name = "None".

    Options:
      --auth_type [None|PlatformSCP|UserID|ECKey|AESKey|UserID_PlatformSCP|ECKey_PlatformSCP|AESKey_PlatformSCP]
                                      Authentication type. Default is "None". Can
                                      be one of "None, UserID, ECKey, AESKey,
                                      PlatformSCP, UserID_PlatformSCP,
                                      ECKey_PlatformSCP, AESKey_PlatformSCP"
      --scpkey TEXT                   File path of the platformscp keys for
                                      platformscp session
      --help                          Show this message and exit.


#) ``ssscli disconnect``::

    Usage: ssscli disconnect [OPTIONS]

      Close session.

    Options:
      --help  Show this message and exit.


#) ``ssscli set``::

    Usage: ssscli set [OPTIONS] COMMAND [ARGS]...

      Set ECC/RSA/AES Keys or certificates

    Options:
      --help  Show this message and exit.

    Commands:
      aes   Set AES Keys
      bin   Set Binary
      cert  Set Certificate
      ecc   Set ECC Keys
      hmac  Set HMAC Keys
      rsa   Set RSA Keys


#) ``ssscli get``::

    Usage: ssscli get [OPTIONS] COMMAND [ARGS]...

      Get ECC/RSA/AES Keys or certificates

    Options:
      --help  Show this message and exit.

    Commands:
      aes   Get AES Keys
      bin   Get Binary
      cert  Get Certificate
      ecc   Get ECC Keys
      rsa   Get RSA Keys


#) ``ssscli generate``::

    Usage: ssscli generate [OPTIONS] COMMAND [ARGS]...

      Generate ECC/RSA Key pair

    Options:
      --help  Show this message and exit.

    Commands:
      ecc  Generate ECC Key
      pub  Generate ECC Public Key to file
      rsa  Generate RSA Key


#) ``ssscli erase``::

    Usage: ssscli erase [OPTIONS] keyid

      Erase ECC/RSA/AES Keys or Certificate (contents)

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

    Options:
      --help  Show this message and exit.


#) ``ssscli cloud``::

    Usage: ssscli cloud [OPTIONS] COMMAND [ARGS]...

      (Not Implemented) Cloud Specific utilities.

      This helps to handle GCP/AWS/Watson specific settings.

    Options:
      --help  Show this message and exit.

    Commands:
      aws  (Not Implemented) AWS (Amazon Web Services) Specific utilities
      gcp  (Not Implemented) GCP (Google Cloud Platform) Specific utilities
      ibm  (Not Implemented) IBM Watson Specific utilities


#) ``ssscli se05x``::

    Usage: ssscli se05x [OPTIONS] COMMAND [ARGS]...

      SE05X specific commands

    Options:
      --help  Show this message and exit.

    Commands:
      certuid     Get SE05X Cert Unique ID (10 bytes)
      getmemory   Get available memory
      getrng      Get SE05X random number (10 bytes)
      readidlist  Read contents of SE050
      reset       Reset SE05X
      uid         Get SE05X Unique ID (18 bytes)


#) ``ssscli refpem``::

    Usage: ssscli refpem [OPTIONS] COMMAND [ARGS]...

      Create Reference PEM/DER files (For OpenSSL Engine).

    Options:
      --help  Show this message and exit.

    Commands:
      ecc  Refpem ECC Keys
      rsa  Refpem RSA Keys


#) ``ssscli sign``::

    Usage: ssscli sign [OPTIONS] keyid input_file signature_file

      Sign Operation

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      input_file = Input file to sign. By default filename with extension .pem and
      .cer considered as PEM format, others as DER/BINARY format.

      signature_file = File name to store signature data. By default filename with
      extension .pem in PEM format and others in DER format.

    Options:
      --informat TEXT   Input format. TEXT can be "DER" or "PEM".
      --outformat TEXT  Output file format. TEXT can be "DER" or "PEM"
      --hashalgo TEXT   Hash algorithm. TEXT can be one of "SHA1, SHA224, SHA256,
                        SHA384, SHA512,  RSASSA_PKCS1_V1_5_SHA1,
                        RSASSA_PKCS1_V1_5_SHA224,  RSASSA_PKCS1_V1_5_SHA256,
                        RSASSA_PKCS1_V1_5_SHA384,  RSASSA_PKCS1_V1_5_SHA512,
                        RSASSA_PKCS1_PSS_MGF1_SHA1,  RSASSA_PKCS1_PSS_MGF1_SHA224,
                        RSASSA_PKCS1_PSS_MGF1_SHA256,
                        RSASSA_PKCS1_PSS_MGF1_SHA384,
                        RSASSA_PKCS1_PSS_MGF1_SHA512"
      --help            Show this message and exit.


#) ``ssscli verify``::

    Usage: ssscli verify [OPTIONS] keyid input_file signature_file

      verify operation

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      input_file = Input file to verify. By default filename with extension .pem
      and .cer considered as PEM format, others as DER/BINARY format.

      filename = signature_file data file for verification. By default filename
      with extension .pem in PEM format and others in DER format.

    Options:
      --format TEXT    input_file and signature file format. TEXT can be "DER" or
                       "PEM"
      --hashalgo TEXT  Hash algorithm. TEXT can be one of "SHA1, SHA224, SHA256,
                       SHA384, SHA512,  RSASSA_PKCS1_V1_5_SHA1,
                       RSASSA_PKCS1_V1_5_SHA224,  RSASSA_PKCS1_V1_5_SHA256,
                       RSASSA_PKCS1_V1_5_SHA384,  RSASSA_PKCS1_V1_5_SHA512,
                       RSASSA_PKCS1_PSS_MGF1_SHA1,  RSASSA_PKCS1_PSS_MGF1_SHA224,
                       RSASSA_PKCS1_PSS_MGF1_SHA256, RSASSA_PKCS1_PSS_MGF1_SHA384,
                       RSASSA_PKCS1_PSS_MGF1_SHA512"
      --help           Show this message and exit.


#) ``ssscli encrypt``::

    Usage: ssscli encrypt [OPTIONS] keyid input_data filename

      Sign Operation

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      input_data = Input data to Encrypt. can be raw string or in file.

      filename = Output file name to store encrypted data. Encrypted data will be
      stored in DER format.

    Options:
      --algo TEXT  Algorithm. TEXT can be one of "oaep", "rsaes"
      --help       Show this message and exit.


#) ``ssscli decrypt``::

    Usage: ssscli decrypt [OPTIONS] keyid encrypted_data filename

      Sign Operation

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      encrypted_data = Encrypted data to Decrypt. can be raw data or in file.
      Input data should be in DER format.

      filename = Output file name to store Decrypted data.

    Options:
      --algo TEXT  Algorithm. TEXT can be one of "oaep", "rsaes"
      --help       Show this message and exit.


#) ``ssscli policy``::

    Usage: ssscli policy [OPTIONS] COMMAND [ARGS]...

      Create/Dump Object Policy

    Options:
      --help  Show this message and exit.

    Commands:
      asymkey  Create Asymmetric Key Object Policy
      counter  Create Counter Object Policy
      dump     Display Created Object Policy
      file     Create Binary file Object Policy
      pcr      Create PCR Object Policy
      symkey   Create Symmetric Key Object Policy
      userid   Create User ID Object Policy



Set Commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These commands are used to set/put objects/keys to the target secure subsystem.

#) ``ssscli set aes``::

    Usage: ssscli set aes [OPTIONS] keyid key

      Set AES Keys

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      key = Can be in file or raw key in DER or HEX format

    Options:
      --policy_name TEXT  File name of the policy to be applied
      --help              Show this message and exit.


#) ``ssscli set hmac``::

    Usage: ssscli set hmac [OPTIONS] keyid key

      Set HMAC Keys

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      key = Can be in file or raw key in DER or HEX format

    Options:
      --help  Show this message and exit.


#) ``ssscli set cert``::

    Usage: ssscli set cert [OPTIONS] keyid key

      Set Certificate

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      key = Can be raw certificate (DER format) or in file. For file, by default
      filename with extension .pem and .cer considered as PEM format and others as
      DER format.

    Options:
      --format TEXT       Input certificate format. TEXT can be "DER" or "PEM"
      --policy_name TEXT  File name of the policy to be applied
      --help              Show this message and exit.


#) ``ssscli set ecc pair``::

    Usage: ssscli set ecc pair [OPTIONS] keyid key

      Set ECC Key pair

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      key = Can be raw key (DER format) or in file. For file, by default filename
      with extension .pem considered as PEM format and others as DER format.

    Options:
      --format TEXT       Input key format. TEXT can be "DER" or "PEM"
      --policy_name TEXT  File name of the policy to be applied
      --help              Show this message and exit.


#) ``ssscli set ecc pub``::

    Usage: ssscli set ecc pub [OPTIONS] keyid key

      Set ECC Public Keys

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      key = Can be raw key (DER format) or in file. For file, by default filename
      with extension .pem considered as PEM format and others as DER format.

    Options:
      --format TEXT       Input key format. TEXT can be "DER" or "PEM"
      --policy_name TEXT  File name of the policy to be applied
      --help              Show this message and exit.


#) ``ssscli set rsa pair``::

    Usage: ssscli set rsa pair [OPTIONS] keyid key

      Set RSA Key Pair

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      key = Can be raw key (DER format) or in file. For file, by default filename
      with extension .pem considered as PEM format and others as DER format.

    Options:
      --format TEXT       Input key format. TEXT can be "DER" or "PEM"
      --policy_name TEXT  File name of the policy to be applied
      --help              Show this message and exit.


#) ``ssscli set rsa pub``::

    Usage: ssscli set rsa pub [OPTIONS] keyid key

      Set RSA Public Keys

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      key = Can be raw key (DER format) or in file. For file, by default filename
      with extension .pem considered as PEM format and others as DER format.

    Options:
      --format TEXT       Input key format. TEXT can be "DER" or "PEM"
      --policy_name TEXT  File name of the policy to be applied
      --help              Show this message and exit.


#) ``ssscli set bin``::

    Usage: ssscli set bin [OPTIONS] keyid data

      Set Certificate

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      data = Can be raw binary or in file

    Options:
      --policy_name TEXT  File name of the policy to be applied
      --help              Show this message and exit.



Get Commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These commands are used to retereive/get objects/keys from the target secure subsystem.

#) ``ssscli get aes``::

    Usage: ssscli get aes [OPTIONS] keyid filename

      Get AES Keys

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      filename = File name to store key. Data can be in PEM or DER format based on
      file extension. By default filename with extension .pem in PEM format and
      others in DER format.

    Options:
      --format TEXT  Output file format. TEXT can be "DER" or "PEM"
      --help         Show this message and exit.


#) ``ssscli get cert``::

    Usage: ssscli get cert [OPTIONS] keyid filename

      Get Certificate

      keyid = 32bit Key ID. Should be in hex format. Example: 401286E6

      filename = File name to store certificate. Data can be in PEM or DER format
      based on file extension. By default filename with extension .pem and .cer in
      PEM format and others in DER format.

    Options:
      --format TEXT  Output file format. TEXT can be "DER" or "PEM"
      --help         Show this message and exit.


#) ``ssscli get ecc pair``::

    Usage: ssscli get ecc pair [OPTIONS] keyid filename

      Get ECC Pair

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      filename = File name to store key. Data can be in PEM or DER format based on
      file extension. By default filename with extension .pem in PEM format and
      others in DER format.

    Options:
      --format TEXT  Output file format. TEXT can be "DER" or "PEM"
      --help         Show this message and exit.


#) ``ssscli get ecc pub``::

    Usage: ssscli get ecc pub [OPTIONS] keyid filename

      Get ECC Pub

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      filename = File name to store key. Data can be in PEM or DER format based on
      file extension. By default filename with extension .pem in PEM format and
      others in DER format.

    Options:
      --format TEXT  Output file format. TEXT can be "DER" or "PEM"
      --help         Show this message and exit.


#) ``ssscli get rsa pair``::

    Usage: ssscli get rsa pair [OPTIONS] keyid filename

      Get RSA Pair

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      filename = File name to store key. Data can be in PEM or DER format based on
      file extension. By default filename with extension .pem in PEM format and
      others in DER format.

    Options:
      --format TEXT  Output file format. TEXT can be "DER" or "PEM"
      --help         Show this message and exit.


#) ``ssscli get rsa pub``::

    Usage: ssscli get rsa pub [OPTIONS] keyid filename

      Get RSA Pub

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      filename = File name to store key. Data can be in PEM or DER format based on
      file extension. By default filename with extension .pem in PEM format and
      others in DER format.

    Options:
      --format TEXT  Output file format. TEXT can be "DER" or "PEM"
      --help         Show this message and exit.


#) ``ssscli get bin``::

    Usage: ssscli get bin [OPTIONS] keyid filename

      Get Binary

      keyid = 32bit Key ID. Should be in hex format. Example: 401286E6

      filename = File name to store binary data.

    Options:
      --help  Show this message and exit.



Generate Commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These commands are used to generate objects/keys inside the target secure subsystem.

#) ``ssscli generate ecc``::

    Usage: ssscli generate ecc [OPTIONS] keyid {NIST_P192|NIST_P224|NIST_P256|NIST
                               _P384|NIST_P521|Brainpool160|Brainpool192|Brainpool
                               224|Brainpool256|Brainpool320|Brainpool384|Brainpoo
                               l512|Secp160k1|Secp192k1|Secp224k1|Secp256k1|ED_255
                               19|MONT_DH_25519|MONT_DH_448|BN_P256}

      Generate ECC Key

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      curvetype = ECC Curve type. can be one of "NIST_P192, NIST_P224, NIST_P256,
      NIST_P384, NIST_P521, Brainpool160, Brainpool192, Brainpool224,
      Brainpool256, Brainpool320, Brainpool384, Brainpool512, Secp160k1,
      Secp192k1, Secp224k1, Secp256k1, ED_25519, MONT_DH_25519, MONT_DH_448"

    Options:
      --policy_name TEXT  File name of the policy to be applied
      --help              Show this message and exit.


#) ``ssscli generate rsa``::

    Usage: ssscli generate rsa [OPTIONS] keyid {1024|2048|3072|4096}

      Generate RSA Key

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      bits = Number of bits. can be one of "1024, 2048, 3072, 4096"

    Options:
      --policy_name TEXT  File name of the policy to be applied
      --help              Show this message and exit.



Refpem Commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These commands are used to get Reference/masked Keys usable by openssl engines.

#) ``ssscli refpem ecc pair``::

    Usage: ssscli refpem ecc pair [OPTIONS] keyid filename

      Create reference PEM file for ECC Pair

      keyid = 32bit Key ID. Should be in hex format. Example: 0x20E8A001

      filename = File name to store key. Can be in PEM or DER or PKCS12 format
      based on file extension. By default filename with extension .pem in PEM
      format, .pfx or .p12 in PKCS12 format and others in DER format.

    Options:
      --format TEXT    Output file format. TEXT can be "DER" or "PEM" or "PKCS12"
      --password TEXT  Password used for PKCS12 format.
      --cert TEXT      Certificate for PKCS12 format.
      --help           Show this message and exit.


#) ``ssscli refpem ecc pub``::

    Usage: ssscli refpem ecc pub [OPTIONS] keyid filename

      Create reference PEM file for ECC Pub

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      filename = File name to store key. Data Can be in PEM or DER format or
      PKCS12 format based on file extension. By default filename with extension
      .pem in PEM format, .pfx or .p12 in PKCS12 format and others in DER format.

    Options:
      --format TEXT    Output file format. TEXT can be "DER" or "PEM" or "PKCS12"
      --password TEXT  Password used for PKCS12 format.
      --cert TEXT      Certificate for PKCS12 format.
      --help           Show this message and exit.


#) ``ssscli refpem rsa pair``::

    Usage: ssscli refpem rsa pair [OPTIONS] keyid filename

      Create reference PEM file for RSA Pair

      keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001

      filename = File name to store key. Data Can be in PEM or DER format or
      PKCS12 format based on file extension. By default filename with extension
      .pem in PEM format, .pfx or .p12 in PKCS12 format and others in DER format.

    Options:
      --format TEXT    Output file format. TEXT can be "DER" or "PEM" or "PKCS12"
      --password TEXT  Password used for PKCS12 format.
      --cert TEXT      Certificate for PKCS12 format.
      --help           Show this message and exit.



Se05x Commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These are the SE05x specific commands.

#) ``ssscli se05x uid``::

    Usage: ssscli se05x uid [OPTIONS]

      Get 18 bytes Unique ID from the SE05X Secure Module.

    Options:
      --help  Show this message and exit.


#) ``ssscli se05x certuid``::

    Usage: ssscli se05x certuid [OPTIONS]

      Get 10 bytes Cert Unique ID from the SE05X Secure Module. The cert uid is a
      subset of the Secure Module Unique Identifier

    Options:
      --help  Show this message and exit.


#) ``ssscli se05x reset``::

    Usage: ssscli se05x reset [OPTIONS]

      Resets the SE05X Secure Module to the initial state.

      This command uses ``Se05x_API_DeleteAll_Iterative`` API of the SE05X MW to
      iterately delete objects provisioned inside the SE.  Because of this, some
      objects are purposefully skipped from deletion.

      It does not use the low level SE05X API ``Se05x_API_DeleteAll``

      For more information, see documentation/implementation of the
      ``Se05x_API_DeleteAll_Iterative`` API.

    Options:
      --help  Show this message and exit.


#) ``ssscli se05x readidlist``::

    Usage: ssscli se05x readidlist [OPTIONS]

      Read contents of SE050

    Options:
      --help  Show this message and exit.

#) ``ssscli se05x getmemory``::

    Usage: ssscli se05x getmemory [OPTIONS]

      Gets the amount of free memory.

    Options:
      --help  Show this message and exit.


POLICY Commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These are Policy commands.

#) ``ssscli policy asymkey``::

    Usage: ssscli policy asymkey [OPTIONS] policy_name auth_obj_id

      Create Asymmetric key object policy.

      policy_name = File name of the policy to be created. This policy name should
      be given as input while provisioning.

      auth_obj_id = Auth object id for each Object Policy.

    Options:
      --sign BOOLEAN                  Object policy Allow Sign. Enabled by Default
      --verify BOOLEAN                Object policy Allow Verify. Enabled by
                                      Default
      --encrypt BOOLEAN               Object policy Allow Encryption. Enabled by
                                      Default
      --decrypt BOOLEAN               Object policy Allow Decryption. Enabled by
                                      Default
      --key_derive BOOLEAN            Object policy Allow Key Derivation. Disabled
                                      by Default
      --wrap BOOLEAN                  Object policy Allow Wrap. Disabled by
                                      Default
      --generate BOOLEAN              Object policy Allow Generate. Enabled by
                                      Default
      --write BOOLEAN                 Object policy Allow Write. Enabled by
                                      Default
      --read BOOLEAN                  Object policy Allow Read. Enabled by Default
      --import_export BOOLEAN         Object policy Allow Import Export. Disabled
                                      by Default
      --key_agreement BOOLEAN         Object policy Allow Key Agreement. Disabled
                                      by Default
      --attest BOOLEAN                Object policy Allow attestation. Disabled by
                                      Default
      --forbid_derived_output BOOLEAN
                                      Object policy Forbid Derived Output.
                                      Disabled by Default
      --forbid_all BOOLEAN            Object policy forbid all. Disabled by
                                      Default
      --delete BOOLEAN                Object policy Allow Delete. Enabled by
                                      Default
      --req_sm BOOLEAN                Object policy Require Secure Messaging.
                                      Disabled by Default
      --req_pcr_val BOOLEAN           Object policy Require PCR Value. Disabled by
                                      Default
      --pcr_obj_id TEXT               Object policy PCR object ID in HEX format.
                                      Zero by Default
      --pcr_expected_value TEXT       Object policy PCR Expected in Hex byte
                                      string Value. Zero by Default
      --help                          Show this message and exit.


#) ``ssscli policy symkey``::

    Usage: ssscli policy symkey [OPTIONS] policy_name auth_obj_id

      Create Symmetric key object policy.

      policy_name = File name of the policy to be created. This policy name should
      be given as input while provisioning.

      auth_obj_id = Auth object id for each Object Policy.

    Options:
      --sign BOOLEAN                  Object policy Allow Sign. Enabled by Default
      --verify BOOLEAN                Object policy Allow Verify. Enabled by
                                      Default
      --encrypt BOOLEAN               Object policy Allow Encryption. Enabled by
                                      Default
      --decrypt BOOLEAN               Object policy Allow Decryption. Enabled by
                                      Default
      --key_derive BOOLEAN            Object policy Allow Key Derivation. Disabled
                                      by Default
      --wrap BOOLEAN                  Object policy Allow Wrap. Disabled by
                                      Default
      --generate BOOLEAN              Object policy Allow Generate. Disabled by
                                      Default
      --write BOOLEAN                 Object policy Allow Write. Enabled by
                                      Default
      --read BOOLEAN                  Object policy Allow Read. Enabled by Default
      --import_export BOOLEAN         Object policy Allow Import Export. Disabled
                                      by Default
      --desfire_auth BOOLEAN          Object policy Allow to perform DESFire
                                      authentication. Disabled by Default
      --desfire_dump BOOLEAN          Object policy Allow to dump DESFire session
                                      keys. Disabled by Default
      --forbid_derived_output BOOLEAN
                                      Object policy Forbid Derived Output.
                                      Disabled by Default
      --kdf_ext_random BOOLEAN        Object policy Allow key derivation ext
                                      random. Disabled by Default
      --tls_kdf BOOLEAN               Object policy Allow tls kdf. Disabled by
                                      Default
      --tls_pms_kd BOOLEAN            Object policy Allow tls pms kd. Disabled by
                                      Default
      --hkdf BOOLEAN                  Object policy Allow hkdf. Enabled by Default
      --pbkdf BOOLEAN                 Object policy Allow pbkdf. Disabled by
                                      Default
      --desfire_kd BOOLEAN            Object policy Allow desfire kd. Disabled by
                                      Default
      --forbid_external_iv BOOLEAN    Object policy forbid external IV. Disabled
                                      by Default
      --usage_hmac_pepper BOOLEAN     Object policy Allow usage hmac as pepper.
                                      Disabled by Default
      --desfire_change_key BOOLEAN    Object policy Allow desfire change key.
                                      Disabled by Default
      --derived_input BOOLEAN         Object policy Allow derived input. Disabled
                                      by Default
      --desfire_auth_id TEXT          32 bit desfire auth id for
                                      desfire_change_key policy
      --source_key_id TEXT            32 bit source key id for derived_input
                                      policy
      --forbid_all BOOLEAN            Object policy forbid all. Disabled by
                                      Default
      --delete BOOLEAN                Object policy Allow Delete. Enabled by
                                      Default
      --req_sm BOOLEAN                Object policy Require Secure Messaging.
                                      Disabled by Default
      --req_pcr_val BOOLEAN           Object policy Require PCR Value. Disabled by
                                      Default
      --pcr_obj_id TEXT               Object policy PCR object ID in HEX format.
                                      Zero by Default
      --pcr_expected_value TEXT       Object policy PCR Expected in Hex byte
                                      string Value. Zero by Default
      --help                          Show this message and exit.


#) ``ssscli policy file``::

    Usage: ssscli policy file [OPTIONS] policy_name auth_obj_id

      Create Binary file object policy.

      policy_name = File name of the policy to be created. This policy name should
      be given as input while provisioning.

      auth_obj_id = Auth object id for each Object Policy.

    Options:
      --write BOOLEAN            Object policy Allow Write. Enabled by Default
      --read BOOLEAN             Object policy Allow Read. Enabled by Default
      --forbid_all BOOLEAN       Object policy forbid all. Disabled by Default
      --delete BOOLEAN           Object policy Allow Delete. Enabled by Default
      --req_sm BOOLEAN           Object policy Require Secure Messaging. Disabled
                                 by Default
      --req_pcr_val BOOLEAN      Object policy Require PCR Value. Disabled by
                                 Default
      --pcr_obj_id TEXT          Object policy PCR object ID in HEX format. Zero
                                 by Default
      --pcr_expected_value TEXT  Object policy PCR Expected in Hex byte string
                                 Value. Zero by Default
      --help                     Show this message and exit.


#) ``ssscli policy counter``::

    Usage: ssscli policy counter [OPTIONS] policy_name auth_obj_id

      Create Counter object policy.

      policy_name = File name of the policy to be created. This policy name should
      be given as input while provisioning.

      auth_obj_id = Auth object id for each Object Policy.

    Options:
      --write BOOLEAN            Object policy Allow Write. Enabled by Default
      --read BOOLEAN             Object policy Allow Read. Enabled by Default
      --forbid_all BOOLEAN       Object policy forbid all. Disabled by Default
      --delete BOOLEAN           Object policy Allow Delete. Enabled by Default
      --req_sm BOOLEAN           Object policy Require Secure Messaging. Disabled
                                 by Default
      --req_pcr_val BOOLEAN      Object policy Require PCR Value. Disabled by
                                 Default
      --pcr_obj_id TEXT          Object policy PCR object ID in HEX format. Zero
                                 by Default
      --pcr_expected_value TEXT  Object policy PCR Expected in Hex byte string
                                 Value. Zero by Default
      --help                     Show this message and exit.


#) ``ssscli policy userid``::

    Usage: ssscli policy userid [OPTIONS] policy_name auth_obj_id

      Create user id object policy.

      policy_name = File name of the policy to be created. This policy name should
      be given as input while provisioning.

      auth_obj_id = Auth object id for each Object Policy.

    Options:
      --write BOOLEAN            Object policy Allow Write. Enabled by Default
      --forbid_all BOOLEAN       Object policy forbid all. Disabled by Default
      --delete BOOLEAN           Object policy Allow Delete. Enabled by Default
      --req_sm BOOLEAN           Object policy Require Secure Messaging. Disabled
                                 by Default
      --req_pcr_val BOOLEAN      Object policy Require PCR Value. Disabled by
                                 Default
      --pcr_obj_id TEXT          Object policy PCR object ID in HEX format. Zero
                                 by Default
      --pcr_expected_value TEXT  Object policy PCR Expected in Hex byte string
                                 Value. Zero by Default
      --help                     Show this message and exit.


#) ``ssscli policy pcr``::

    Usage: ssscli policy pcr [OPTIONS] policy_name auth_obj_id

      Create PCR object policy.

      policy_name = File name of the policy to be created. This policy name should
      be given as input while provisioning.

      auth_obj_id = Auth object id for each Object Policy.

    Options:
      --write BOOLEAN            Object policy Allow Write. Enabled by Default
      --read BOOLEAN             Object policy Allow Read. Enabled by Default
      --forbid_all BOOLEAN       Object policy forbid all. Disabled by Default
      --delete BOOLEAN           Object policy Allow Delete. Enabled by Default
      --req_sm BOOLEAN           Object policy Require Secure Messaging. Disabled
                                 by Default
      --req_pcr_val BOOLEAN      Object policy Require PCR Value. Disabled by
                                 Default
      --pcr_obj_id TEXT          Object policy PCR object ID in HEX format. Zero
                                 by Default
      --pcr_expected_value TEXT  Object policy PCR Expected in Hex byte string
                                 Value. Zero by Default
      --help                     Show this message and exit.


#) ``ssscli policy dump``::

    Usage: ssscli policy dump [OPTIONS] policy_name

      Display Created object policy.

      policy_name = File name of the policy to be displayed.

    Options:
      --help  Show this message and exit.


