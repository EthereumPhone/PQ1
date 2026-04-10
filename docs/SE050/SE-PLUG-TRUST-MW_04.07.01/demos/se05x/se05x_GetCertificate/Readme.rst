..
    Copyright 2019 NXP


.. highlight:: shell

.. _se-get-certificate:

==========================================================
  Get Certificate from the SE
==========================================================

This tool is to retrieve Trust provisioned certificates from the SE. It will
read the certificate and store it on the file system. It takes as argument,
the keyID at which certificate is stored and the file path where to save the
certificate on the file system.

.. note:: It can only be compiled when Host Crypto is mbedTLS.


Building the example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use the following CMake configurations to compile the example

- CMake configurations: ``SSS_HAVE_HOSTCRYPTO_MBEDTLS``: ON

- Project: ``se05x_GetCertificate``

How to use
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Run the tool as::

    se05x_GetCertificate <32-bit keyID> </path/to/file> <port>


- The keys ID has to be in HEX format.

- For systems connecting with T=1 over I2C, the port parameter can be skipped.

- The certificate will be stored in *PEM* format at the specified path on the
  file system.
