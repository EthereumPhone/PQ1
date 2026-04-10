..
    Copyright 2019,2020 NXP


.. highlight:: bat

.. _ex-sss-ecdh:

=======================================================================
 ECDH Example
=======================================================================

This project demonstrates generating a ECDH key using SSS APIs.

Refer - :file:`simw-top/sss/ex/ecdh/ex_sss_ecdh.c`

Prerequisites
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)


About the Example
=======================================================================
This example generates a ECDH key.

It uses the following APIs and data types:
  - :cpp:func:`sss_derive_key_context_init()`
  - :cpp:enumerator:`kAlgorithm_SSS_ECDH` from :cpp:type:`sss_algorithm_t`
  - :cpp:enumerator:`kMode_SSS_ComputeSharedSecret` from :cpp:type:`sss_mode_t`
  - :cpp:func:`sss_derive_key_dh()`


Console output
=======================================================================


If everything is successful, the output will be similar to:

.. literalinclude:: out_ex_ecdh.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!


