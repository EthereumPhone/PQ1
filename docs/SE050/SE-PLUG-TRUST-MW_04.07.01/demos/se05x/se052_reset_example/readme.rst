..
    Copyright 2019,2020 NXP



.. highlight:: bat

.. _se052_reset_example:

=======================================================================
 SE052 Reset Example
=======================================================================

This project is used to demonstrate the reset of secure element on
receiving the APDU throughput error.

The example will send the get random number APDU command in loop to trigger
the APDU throughput error. After the error is received, T=1oI2C Chip reset
command is invoked using API 'phNxpEse_reset'.


Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se052_reset_example``


Running the Example
=======================================================================

If you have built a binary, flash the binary on to the board and reset
the board.

If you have built an *exe* to be run from Windows using VCOM, run as::

    se052_reset_example.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as::

    ./se052_reset_example
