..
    Copyright 2019,2020 NXP



.. highlight:: bat

.. _ex-se05x-multiple-digest-crypto-obj:

=======================================================================
 se05x Multiple Digest Crypto Objects example
=======================================================================

This project demonstrates managing multiple crypto objects from application layer.
The example will create 2 digest crypto objects which will be used for SHA256 multi-step operations.
The example can be extended for AES, AEAD, MAC crypto objects also.

.. note:: Disable `SSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ` in cmake options to run this example.
	This will ensure crypto objects are not created at SSS layer.


Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se05x_MultipleDigestCryptoObj``


Running the Example
=======================================================================

If you have built a binary, flash the binary on to the board and reset
the board.

If you have built an *exe* to be run from Windows using VCOM, run as::

    se05x_MultipleDigestCryptoObj.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as::

    ./se05x_MultipleDigestCryptoObj


Console output
=======================================================================

If everything is successful, the output will be similar to:

.. literalinclude:: out_se05x_MultipleDigestCryptoObj.rst.txt
   :start-after: Opening connection to JRCP server on 127.0.0.1:8050
