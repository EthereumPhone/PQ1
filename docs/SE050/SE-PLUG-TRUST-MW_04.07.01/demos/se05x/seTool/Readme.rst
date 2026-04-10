..
    Copyright 2019, 2023, 2025 NXP


.. highlight:: shell

.. _se-tool:

==========================================================
 Tool to create Reference key file
==========================================================

This tool is to demonstrate how to implement a command-line utility for native
systems.  This utility can be used to generate/inject keypairs (ECC and RSA) and create
reference key files.

This is beneficial for environments which do not have python installed.

.. note:: This example is implemented only for NIST-P256 curve in case of ECC keys.

Building the example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use the following CMake configurations to compile the example

- CMake configurations: ``SSS_HAVE_HOSTCRYPTO_OPENSSL``: ON

- Project: ``seTool``

How to use
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This example provides four command-line parameters to select the
operation to perform.

1)  To **generate** an ECC keypair, run the tool as::

        seTool genECC <keyId> <portname>

    Where:

    - *keyId* is the keypair index at which we want to generate the keypair.


#)  To **inject** an ECC keypair, run the tool as::

        seTool setECC <keyId> <filename> <portname>

    Where:

    - *keyId* is the keypair index at which we want to inject the keypair

    - *filename* is the path of the file in which keypair is stored in PEM
      format.


#)  To **retrieve the ECC public key**, run the tool as::

        seTool getECCPublic <keyId> <filename> <portname>

    Where:

    - *keyId* is the keypair index from which we want to retrieve the public
      key

    - *filename* is the path of the file in which we want to store the key in
      PEM format.


#)  To **create an ECC reference key** for an injected keypair, run the tool as::

        seTool getECCRef <keyId> <filename> <portname>

    Where:

    - *keyId* is the keypair index at which we keypair is stored and

    - *filename* is the path of the file in which we want to store the
      reference key in PEM format.

#)  To **generate** an RSA keypair, run the tool as::

        seTool genRSA <rsaKeySize> <keyId> <portname>

    Where:

    - *keyId* is the keypair index at which we want to generate the keypair.


#)  To **inject** an RSA keypair, run the tool as::

        seTool setRSA <rsaKeySize> <keyId> <filename> <portname>

    Where:

    - *keyId* is the keypair index at which we want to inject the keypair

    - *filename* is the path of the file in which keypair is stored in PEM
      format.


#)  To **retrieve the RSA public key**, run the tool as::

        seTool getRSAPublic <keyId> <filename> <portname>

    Where:

    - *keyId* is the keypair index from which we want to retrieve the public
      key

    - *filename* is the path of the file in which we want to store the key in
      PEM format.


#)  To **create an RSA reference key** for an injected keypair, run the tool as::

        seTool getRSARef <keyId> <filename> <portname>

    Where:

    - *keyId* is the keypair index at which we keypair is stored and

    - *filename* is the path of the file in which we want to store the
      reference key in PEM format.

The generated reference key can be used by OpenSSL Engine.
