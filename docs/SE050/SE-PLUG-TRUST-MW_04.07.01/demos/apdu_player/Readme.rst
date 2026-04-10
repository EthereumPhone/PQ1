..
    Copyright 2019 NXP


.. highlight:: shell

.. _apdu-player-demo:

==========================================================
 APDU Player Demo
==========================================================

This demo is to transceive raw APDUs to the SE. It takes a command line argument as the input file containing APDUs to be sent, followed by the response. An example of command to be in the file is
``/send 00A4040000 6F108408A000000151000000A5049F6501FF9000``


In this, the ``00A4040000`` is the command to be transmitted and ``6F108408A000000151000000A5049F6501FF9000`` is the expected response.

.. note ::
    Ensure that authentication with the SE is either plain or platform SCP
    This demo only supports only SE05x devices

How to use
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Run the demo as ``apdu_player_demo [Input-file] <Port>``
