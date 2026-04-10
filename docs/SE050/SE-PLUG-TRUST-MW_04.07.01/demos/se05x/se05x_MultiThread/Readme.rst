..
    Copyright 2020 NXP



.. highlight:: bat

.. _se05x_MultiThread_demo:

=======================================================================
 SE05X MultiThread demo
=======================================================================

This project demonstrates two threads, opening two sessions with the
se05x using tunneling api's. Each thread performing ecc sign and verify operations.

If we use user sessions then at least two authentication objects need to be provisioned
in se05x using the ``delete and test provision`` utility before running the demo:

- For an overview of authentication objects refer to :ref:`Auth_objects`
- For a provisioning example refer to :ref:`delete-and-test-provision`

In Multi-step operations the concurrent execution with same cipher mode is not allowed.
(Refer :ref:`limitations`)

.. note:: This demo can be build for FreeRTOS on embedded
 platforms or for pthread on POSIX systems (e.g. Linux).

Prerequisites
=====================
- Micro USB cable
- FRDM-K64F/imx-RT1060/Raspberry-Pi/iMX board
- Personal Computer
- SE05x Arduino shield


Building the Demo
=======================================================================
- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se05x_MultiThread``


Running the Example
=======================================================================

If you have built a binary, flash the binary on to the board and reset
the board.

If you have built an *exe* to be run from Windows using VCOM, run as::

    se05x_Multithread.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as::

    ./se05x_Multithread


Console output
=======================================================================

If everything is successful, the output will be similar to:

.. literalinclude:: out_se05x_multithreaded_demo.rst.txt
   :start-after: sss   :INFO :atr (Len=0)