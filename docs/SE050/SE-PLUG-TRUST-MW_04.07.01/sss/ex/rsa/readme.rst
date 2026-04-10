..
    Copyright 2019,2020 NXP


.. highlight:: bat

.. _ex-sss-rsa:

=======================================================================
 RSA Example
=======================================================================

This project demonstrates RSA sign and verify operations using SSS APIs.

Refer - :file:`simw-top/sss/ex/rsa/ex_sss_rsa.c`

Prerequisites
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)


About the Example
=======================================================================
This example does a RSA signing and verify operation.

It uses the following APIs and data types:
  - :cpp:func:`sss_asymmetric_context_init()`
  - :cpp:enumerator:`kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256` from :cpp:type:`sss_algorithm_t`
  - :cpp:enumerator:`kMode_SSS_Sign` from :cpp:type:`sss_mode_t`
  - :cpp:enumerator:`kSSS_CipherType_RSA_CRT` from :cpp:enumerator: `sss_cipher_type_t`
  - :cpp:func:`sss_asymmetric_sign_digest()`
  - :cpp:enumerator:`kMode_SSS_Verify` from :cpp:type:`sss_mode_t`
  - :cpp:func:`sss_asymmetric_verify_digest()`

.. note::
    This example tries to delete key first. Deletion would be successful, if the key already exists.
    Otherwise it would return an error message which is perfectly alright and the example could be successfully executed.



Console output
=======================================================================


If everything is successful, the output will be similar to:

.. literalinclude:: out_ex_rsa.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!


