..
    Copyright 2019,2020 NXP


.. highlight:: bat

.. _ex-sss-attest_ecc:

=======================================================================
 ECC NIST256 Key Attestation Example
=======================================================================

This project demonstrates ecc nist256 key attestation and verification
with another ecc nist256 key using SSS API

Refer - :file:`simw-top/sss/ex/attest_ecc/ex_sss_ecc_attest.c`

Prerequisites
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)


About the Example
=======================================================================
This example reads a nist256 public key with attestation.

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

.. literalinclude:: out_ex_ecc_attest.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!


