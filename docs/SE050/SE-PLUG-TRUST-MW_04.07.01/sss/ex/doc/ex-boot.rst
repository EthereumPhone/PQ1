..
    Copyright 2020 NXP

    This software is owned or controlled by NXP and may only be used
    strictly in accordance with the applicable license terms.  By expressly
    accepting such terms or by downloading, installing, activating and/or
    otherwise using the software, you are agreeing that you have read, and
    that you agree to comply with and are bound by, such license terms.  If
    you do not agree to be bound by the applicable license terms, then you
    may not retain, install, activate or otherwise use the software.



==================================================================
 Example Boot-Up
==================================================================

The Examples and use cases based on SSS APIs are them selves *(more
or less)* Cryptosystem agnostic, how ever the platforms where they
run and how they run would be very specific.

e.g. While running from PC with a Secure Element, you may need to
choose and connect to specific COM Port / Socket.  On the other hand,
when running from different embedded platforms like FREEDOM K64F, iMX RT 1050,
etc., few board specific steps are needed.

To simplify examples, them selves, the files in :file:`sss/ex/inc` and
:file:`sss/ex/src` try to isolate such details.

Some of the scenarios of boot up are:

Booting from Windows / Linux
==================================================================

In such a system, many decisions are taken at run time.
e.g. COM Port for interface to the secure element, etc.

In such a system, examples also have access to command line arguments
and environment variables.

Such a setup is mostly for testing and early prototyping.

.. image:: /ex-boot-windows.jpeg
		:width: 270px

.. _boot-embedded-no-rtos:

Booting from an embedded system, without any RTOS
==================================================================


In such a system, the example is pre-compiled for specific platform/combination.
There are very less decisions to be taken at run time, and most decisions
are pre-selected during build/compile time.

.. image:: /ex-boot-no-rtos-embedded.jpeg
		:width: 270px



Booting from an embedded system, with RTOS
==================================================================

In such a system, the example uses RTOS.  And the example itself is
to be run from an RTOS Thread context.

.. image:: /ex-boot-with-rtos-embedded.jpeg
		:width: 270px

