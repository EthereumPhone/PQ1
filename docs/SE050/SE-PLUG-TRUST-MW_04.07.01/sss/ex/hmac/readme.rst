..
    Copyright 2019,2020 NXP


.. highlight:: bat

.. _ex-sss-hmac:

=======================================================================
 HMAC Example
=======================================================================

This project demonstrates a HMAC operation on a message using SSS APIs.

Refer - :file:`simw-top/sss/ex/hmac/ex_sss_hmac.c`

Prerequisites
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)


About the Example
=======================================================================
This example does a HMAC operation on input data.

It uses the following APIs and data types:
  - :cpp:func:`sss_mac_context_init()`
  - :cpp:enumerator:`kAlgorithm_SSS_HMAC_SHA256` from :cpp:type:`sss_algorithm_t`
  - :cpp:enumerator:`kMode_SSS_Mac` from :cpp:type:`sss_mode_t`
  - :cpp:func:`sss_mac_one_go()`



Console output
=======================================================================


If everything is successful, the output will be similar to:

.. literalinclude:: out_ex_hmac.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!


