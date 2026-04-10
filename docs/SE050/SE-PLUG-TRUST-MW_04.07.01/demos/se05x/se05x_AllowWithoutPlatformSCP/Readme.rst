..
    Copyright 2019,2020 NXP



.. highlight:: bat

.. _ex-se05x-allow-without-plat-scp:

=======================================================================
 SE05X Allow Without SCP example
=======================================================================

This project demonstrates how to configure SE05X to allow without platform SCP.


Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se05x_AllowWithoutPlatformSCP``

  - CMake configuration

    ``SE05X_Auth``:``PlatfSCP03``



Running the Example
=======================================================================

If you have built a binary, flash the binary on to the board and reset
the board.

If you have built an *exe* to be run from Windows using VCOM, run as::

    se05x_AllowWithoutPlatformSCP.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as::

    ./se05x_AllowWithoutPlatformSCP


