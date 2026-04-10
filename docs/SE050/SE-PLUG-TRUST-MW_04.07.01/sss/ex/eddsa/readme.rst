..
    Copyright 2021 NXP


.. highlight:: bat

.. _ex-sss-eddsa:

=======================================================================
 EDDSA Example
=======================================================================

This project demonstrates EDDSA sign and verify operation using SSS APIs.
Sign and Verify operations using edwards key should to be performed on plain data.
Use `sss_se05x_asymmetric_sign` and `sss_se05x_asymmetric_verify` apis.

Refer - :file:`simw-top/sss/ex/eddsa/ex_sss_eddsa.c`

Prerequisites
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)


About the Example
=======================================================================
This example does a elliptic curve cryptography signing and verify operation.

It uses the following APIs and data types:
  - :cpp:func:`sss_asymmetric_context_init()`
  - :cpp:enumerator:`kAlgorithm_SSS_SHA256` from :cpp:type:`sss_algorithm_t`
  - :cpp:enumerator:`kMode_SSS_Sign` from :cpp:type:`sss_mode_t`
  - :cpp:func:`sss_se05x_asymmetric_sign()`
  - :cpp:enumerator:`kMode_SSS_Verify` from :cpp:type:`sss_mode_t`
  - :cpp:func:`sss_se05x_asymmetric_verify()`


Console output
=======================================================================


If everything is successful, the output will be similar to:

.. literalinclude:: out_ex_eddsa.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!


