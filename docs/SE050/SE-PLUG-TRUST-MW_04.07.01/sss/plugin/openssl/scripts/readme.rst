..
    Copyright 2019 NXP



.. _intro-openssl-engine:

Introduction on OpenSSL engine
==============================

Starting with OpenSSL 0.9.6 an ‘Engine interface’ was added to OpenSSL allowing support
for alternative cryptographic implementations. This Engine interface can be
used to interface with external crypto devices. The key injection process is
secure module specific and is not covered by the Engine interface.

Depending on the capabilities of the attached secure element (e.g. SE050_C, ...)
the following functionality can be made available over the OpenSSL Engine interface:

- EC crypto

  - EC sign/verify
  - ECDH compute key
  - Montgomery ECDH

- RSA crypto

  - RSA sign/verify
  - RSA priv_key_decrypt/pub_key_encrypt

- Fetching random data


General
-------

OpenSSL versions
~~~~~~~~~~~~~~~~
The OpenSSL Engine is compatible with OpenSSL versions 1.0.2 or 1.1.1.

OpenSSL Configuration file
~~~~~~~~~~~~~~~~~~~~~~~~~~
It's possible to add OpenSSL engine specific extensions to the OpenSSL configuration file.
Using these extensions one can control whether the supported crypto functionality is delegated to
the Secure Element or whether it is handled by the OpenSSL SW implementation.

The actual contents of the configuration file depends on the OpenSSL version and the attached
secure element (SE050, SE051, or SE052). The ``demos/linux/common folder`` of this SW package contains
4 reference configuration files covering SE050 for the two supported OpenSSL versions.

The following configuration file fragment (extracted from ``openssl11_sss_se050.cnf``) highlights
the required changes to enable the full functionality of the SE050_C OpenSSL Engine on an iMX Linux system::

  ...
  # System default
  openssl_conf = nxp_engine
  ...

  ...
  [nxp_engine]
  engines = engine_section

  [engine_section]
  e4sss_se050 = e4sss_se050_section

  [e4sss_se050_section]
  engine_id = e4sss
  dynamic_path = /usr/local/lib/libsss_engine.so
  init = 1
  default_algorithms = RAND,RSA,EC

One overrules the default OpenSSL configuration file by setting the environment variable
``OPENSSL_CONF`` to the path of the custom configuration file.

Platforms
~~~~~~~~~
The OpenSSL engine can be used on iMX boards (running Linux) or on Raspberry Pi (running Raspbian).


Keys
----

Key Management
~~~~~~~~~~~~~~

The cryptographic functionality offered by the OpenSSL engine requires a
reference to a key stored inside the Secure Element (exception is
RAND_Method). These keys are typically inserted into the Secure Element in a
secured environment during production.

OpenSSL requires a key pair, consisting of a private and a public key, to be
loaded before the cryptographic operations can be executed. This creates a
challenge when OpenSSL is used in combination with a secure element as the
private key cannot be extracted out from the Secure Element.

The solution is to populate the OpenSSL Key data structure with only a
reference to the Private Key inside the Secure Element instead of the actual
Private Key. The public key as read from the Secure Element can still be
inserted into the key structure.

OpenSSL crypto API’s are then invoked with these data structure objects as
parameters. When the crypto API is routed to the Engine, the OpenSSL engine
implementation decodes these key references and invokes the SSS API with
correct Key references for a cryptographic operation. If the input key is not
reference key, execution will roll back to openssl software implementation

.. _ec-reference-key-format:

EC Reference key format
~~~~~~~~~~~~~~~~~~~~~~~

The following provides an example of an EC reference key. The value reserved
for the private key has been used to contain:

-  a pattern of ``0x10..00`` to fill up the data structure MSB side to the
   desired key length
-  a 32 bit key identifier (in the example below ``0x7DCCBBAA``)
-  a 64 bit magic number (always ``0xA5A6B5B6A5A6B5B6``)
-  a byte to describe the key class (``0x10`` for Key pair and ``0x20`` for
   Public key)
-  a byte to describe the key index (use a reserved value ``0x00``)

.. code:: text

       Private-Key: (256 bit)
       priv:
           10:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
           00:00:00:7D:CC:BB:AA:A5:A6:B5:B6:A5:A6:B5:B6:
           kk:ii
       pub:
           04:1C:93:08:8B:26:27:BA:EA:03:D1:BE:DB:1B:DF:
           8E:CC:87:EF:95:D2:9D:FC:FC:3A:82:6F:C6:E1:70:
           A0:50:D4:B7:1F:F2:A3:EC:F8:92:17:41:60:48:74:
           F2:DB:3D:B4:BC:2B:F8:FA:E8:54:72:F6:72:74:8C:
           9E:5F:D3:D6:D4
       ASN1 OID: prime256v1

.. note::
    - The key identifier ``0x7DCCBBAA`` (stored in big-endian convention) is in
      front of the magic number ``0xA5A6B5B6A5A6B5B6``
    - The padding of the private key value and the magic number make it
      unlikely a normal private key value matches a reference key.
    - Ensure the value reserved for public key and ASN1 OID contain the values
      matching the stored key.

.. note::
    - For EC Montgomery curves, openssl allows only the private key to be set.
      So the reference key created will not have the valid public key.

.. _rsa-reference-key-format:

RSA Reference key format
~~~~~~~~~~~~~~~~~~~~~~~~

The following provides an example of an RSA reference key.

-  The value reserved for 'p' (aka 'prime1') is used as a magic number and is
   set to '1'
-  The value reserved for 'q' (aka 'prime2') is used to store the 32 bit key
   identifier (in the example below 0x6DCCBB11)
-  The value reserved for '(inverse of q) mod p' (aka 'IQMP' or 'coefficient')
   is used to store the magic number 0xA5A6B5B6

.. code:: text

       Private-Key: (2048 bit)
       modulus:
           00:b5:48:67:f8:84:ca:51:ac:a0:fb:d8:e0:c9:a7:
           72:2a:bc:cb:bc:93:3a:18:6a:0f:a1:ae:d4:73:e6:
           ...
       publicExponent: 65537 (0x10001)
       privateExponent:
           58:7a:24:39:90:f4:13:ff:bf:2c:00:11:eb:f5:38:
           b1:77:dd:3a:54:3c:f0:d5:27:35:0b:ab:8d:94:93:
           ...
       prime1: 1 (0x1)
       prime2: 1842133777(0x6DCCBB11)
       exponent1:
           00:c1:c9:0a:cc:9f:1a:c5:1c:53:e6:c1:3f:ab:09:
           db:fb:20:04:38:2a:26:d5:71:33:cd:17:a0:94:bd:
           ...
       exponent2:
           24:95:f0:0b:b0:78:a9:d9:f6:5c:4c:e0:67:d8:89:
           c1:eb:df:43:54:74:a0:1c:43:e3:6f:d5:97:88:55:
           ...
       coefficient: 2779166134 (0xA5A6B5B6)

.. note::
    - Ensure keylength, the value reserved for (private key) modulus and
      public exponent match the stored key.
    - The mathematical relation between the different key components is not
      preserved.
    - Setting prime1 to '1' makes it impossible that a normal private key
      matches a reference key.

Building the OpenSSL engine
------------------------------------------------------
The cmake build system will create an OpenSSL engine for supported platforms.
The resulting OpenSSL engine will be copied to the SW tree in directory
``simw-top/sss/plugin/openssl/bin``.

A subsequent ``make install`` will copy the
OpenSSL engine to a standard directory on the file system, in case of iMX Linux e.g.
``/usr/local/lib``.

.. note::
    Ensure the following flag is defined when building an application that will be linked against the engine:
    ``-DOPENSSL_LOAD_CONF``

Sample scripts to demo OpenSSL Engine
------------------------------------------------------
The directory ``simw-top/sss/plugin/openssl/scripts`` contains a set of python
scripts. These scripts use the OpenSSL Engine in the context of standard
OpenSSL utilities. They illustrate using the OpenSSL Engine for fetching
random data, EC or RSA crypto operations. The scripts that illustrate EC or
RSA crypto operations depend on prior provisioning of the secure element.

As an example, the following set of commands first creates and provisions EC key
material. Then it invokes the OpenSSL Engine for ECDSA sign / verify
operations and ECDH calculations. It assumes an SE050 is connected via I2C to
an iMX6UL-EVK board::

  python3 openssl_provisionEC.py --key_type prime256v1
  python3 openssl_EccSign.py --key_type prime256v1
  python3 openssl_Ecdh.py --key_type prime256v1

Further details on using these scripts can be found in the following:

openssl_rnd.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: doc/openssl_rnd.rst.txt

openssl_provisionEC.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: doc/openssl_provisionEC.rst.txt

openssl_EccSign.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: doc/openssl_EccSign.rst.txt

openssl_Ecdh.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: doc/openssl_Ecdh.rst.txt

ecc_all.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: doc/ecc_all.rst.txt

openssl_provisionRSA.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: doc/openssl_provisionRSA.rst.txt

openssl_RSA.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: doc/openssl_RSA.rst.txt

rsa_all.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: doc/rsa_all.rst.txt

openssl_provisionEC_mont.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: doc/openssl_provisionEC_mont.rst.txt

openssl_Ecdh_mont.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: doc/openssl_Ecdh_mont.rst.txt


.. only:: nxp

    .. warning::
        NXP Internal documentation.

    Generating the Documentation
    ---------------------------------

    Call this command from within venv::

        for %i in ( *.py ) do call python %i --help > doc\%~ni.rst.txt 2>&1

        OR

        for i in *.py; do python $i --help > doc/$(basename $i .py).rst.txt ; done


    Validating the OpenSSL engine
    -----------------------------

    The directory ``simw-top/sss/plugin/openssl/scripts`` contains validation/test scripts for the OpenSSL
    engine on windows and linux platforms. Before executing a validation
    script, the secure element must first be provisioned.
    The provisioning and validation scripts support multiple interconnects to the Secure Element.

    Provisioning
    ~~~~~~~~~~~~

    Assuming a SEO5X is connected on port ``COM1`` execute (from a
    Windows cmd prompt, ssscli is used under the hood) ::

       -- To provision ECC keys on curve prime256v1
       python openssl_provisionEC.py --key_type prime256v1 --connection_data COM1
       -- To provision EC montgomory keys on curve x25519
       python openssl_provisionEC_mont.py --key_type x25519 --connection_data COM1
       -- To provision RSA keys of 1024 bits
       python openssl_provisionRSA.py --key_type rsa1024 --connection_data COM1   --- To provision RSA keys

    Or, assuming an RJCT server is available on address ``192.168.2.75:8050``
    execute (from a cmd prompt, ssscli is used under the hood) ::

       python openssl_provisionEC.py --key_type prime256v1 --connection_data 192.168.2.75:8050 jrcpv2
       python openssl_provisionEC_mont.py --key_type x25519 --connection_data 192.168.2.75:8050 jrcpv2
       python openssl_provisionRSA.py --key_type rsa1024 --connection_data 192.168.2.75:8050 --connection_type jrcpv2

    Or, assuming the tests are run on the iMX platform and the SE050 secure element
    is connected via I2C ::

       python openssl_provisionEC.py --key_type prime256v1
       python openssl_provisionEC_mont.py --key_type x25519
       python openssl_provisionRSA.py --key_type rsa1024

    Validation
    ~~~~~~~~~~

    Run the following scripts for validation (choose an ip_address:port or COM-port argument as appropriate).

    To test random number generation ::

       python openssl_rnd.py --connection_data COM1
       Note: Will also work without first provisioning Secure Element

    To test ECC ::

       python openssl_EccSign.py --key_type prime256v1 --connection_data COM1
       python openssl_Ecdh.py --key_type prime256v1 --connection_data COM1
       python openssl_Ecdh_mont.py --key_type x25519 --connection_data COM1

    To test RSA ::

       python openssl_RSA.py --key_type rsa1024 --connection_data COM1
       OR
       python openssl_RSA.py --key_type rsa2048 --connection_data COM1

    For Negative tests ::

       python openssl_EcNegativeTest.py --key_type prime256v1


    OpenSSL Engine with Edwards Support
    ---------------------------------

    Refer :numref:`intro-opensslEngine-withEd` for openssl engine with edwards key support.

    Known Issue
    ---------------------------------

    Current simulator has issue with Montgomery curve 448. Following command works on IC but fails on simulator ::

      python openssl_Ecdh_mont.py --key_type x448 --connection_type jrcpv2 --connection_data 127.0.0.1:8050
