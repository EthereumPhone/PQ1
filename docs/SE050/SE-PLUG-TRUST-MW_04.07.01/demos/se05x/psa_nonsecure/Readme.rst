..
    Copyright 2020 NXP

.. _psa-example:

=================================================
 PSA Non Secure Example
=================================================

This example is to demonstrate how to use PSA library APIs
to perform a Sign/Verify operations.


Pre-requisites
=================================================

You need to build PSA-ALT library for TrustZone before compiling this
application code.

Refer to :numref:`psa-alt` :ref:`psa-alt`.


PSA Operation Examples
=================================================

- Generating asymmetric keys.

  .. literalinclude:: psa_nonsecure.c
     :language: c
     :dedent: 4
     :start-after: /* doc:start:psa-generate-key */
     :end-before: /* doc:end:psa-generate-key */

- Performing Sign-Verify operations.

  .. literalinclude:: psa_nonsecure.c
     :language: c
     :dedent: 4
     :start-after: /* doc:start:psa-sign-verify */
     :end-before: /* doc:end:psa-sign-verify */


Building Example
=================================================

This example would run in normal world and must link with
the secure world PSA library so that definitions for veneer
APIs can be found. Build this example with
the following CMake configurations:

- ``Host=lpcxpresso55s_ns``

- ``HostCrypto=MBEDTLS``

- ``mbedTLS_ALT=PSA``

- ``RTOS=Default``

- ``SMCOM=T1oI2C``

- ``PROJECT=psa_nonsecure``
