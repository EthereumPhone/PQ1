..
    Copyright 2019,2020 NXP



.. highlight:: bat

.. _ex-se05x-mandate-scp:

=======================================================================
 SE05X Mandate SCP example
=======================================================================

This project demonstrates how to configure SE05X to mandate platform SCP. This
can be used if you always want the communication with SE05X to be encrypted.

.. note:: After this example runs successfully, further communication would require
  Platform SCP03 encryption.



Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se05x_MandatePlatformSCP``

  - CMake configuration

    ``SE05X_Auth``:``None``


Running the Example
=======================================================================

If you have built a binary, flash the binary on to the board and reset
the board.

If you have built an *exe* to be run from Windows using VCOM, run as::

    se05x_MandatePlatformSCP.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as::

    ./se05x_MandatePlatformSCP
