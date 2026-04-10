..
    Copyright 2019,2020 NXP


.. highlight:: bat

.. _ex-sss-ecc_attest_mont:

=======================================================================
 ECC MONTGOMERY-25519 Key Attestation Example
=======================================================================

This project demonstrates ecc montogomery25519 key attestation and verification
with ecc nist256 key using SSS API.
Signing on montgomery public key is done with key in the big endian format inside secure element.

Refer - :file:`simw-top/sss/ex/attest_mont/ex_sss_mont_attest.c`

.. note ::

  For twisted edward curve and montgomery 448 curve also the attestation signing
  is done with public key in big endian format.

Prerequisites
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)


About the Example
=======================================================================
This example reads a montgomery-25519 public key with attestation.

It uses the following APIs and data types:
  - :cpp:func:`sss_key_store_set_key()`
  - :cpp:func:`sss_key_store_generate_key()`
  - :cpp:func:`sss_se05x_key_store_get_key_attst()`
  - :cpp:enumerator:`kAlgorithm_SSS_ECDSA_SHA256` from :cpp:type:`sss_algorithm_t`
  - :cpp:enumerator:`kMode_SSS_Verify` from :cpp:type:`sss_mode_t`
  - :cpp:func:`sss_asymmetric_verify_digest()`


Console output
=======================================================================


If everything is successful, the output will be similar to:

.. literalinclude:: out_ex_mont_attest.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!


