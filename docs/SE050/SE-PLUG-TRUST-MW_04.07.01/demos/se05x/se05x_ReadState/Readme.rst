..
    Copyright 2019,2020 NXP



.. highlight:: bat

.. _ex-se05x-ReadState:

=======================================================================
 SE05X Read State example
=======================================================================

This project can be used to get SE05X state information.
The state information is w.r.t

1) LockState
#) Restriction on Object Creation
#) Platform SCP mandate state

Refer to :cpp:type:`SE05x_LockState_t`
Refer to :cpp:type:`SE05x_RestrictMode_t`
Refer to :cpp:type:`SE05x_PlatformSCPRequest_t`

.. literalinclude:: se05x_ReadState.c
   :language: c
   :dedent: 4
   :start-after: /* doc:start:read state variables */
   :end-before: /* doc:end:read state variables*/


Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se05x_ReadState``


Running the Example
=======================================================================

If you have built a binary, flash the binary on to the board and reset
the board.

If you have built an *exe* to be run from Windows using VCOM, run as::

    se05x_ReadState.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as::

    ./se05x_ReadState


Console output
=======================================================================

If everything is successful, the output will be similar to:

.. literalinclude:: out_se05x_ReadState.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!
