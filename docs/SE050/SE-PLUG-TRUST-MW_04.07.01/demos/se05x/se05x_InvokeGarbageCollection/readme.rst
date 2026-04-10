..
    Copyright 2019,2020 NXP



.. highlight:: bat

.. _ex-se05x-invoke-garbage-collection:

=======================================================================
 SE05X Invoke Garbage Collection Example
=======================================================================

The example will trigger the garbage collection in SE05X.
Invoking ``CM_InvokeGarbageCollection`` api will close the existing session to SE05X. To use SE05X, open session again.

.. warning::
  Excessive calls to ``CM_InvokeGarbageCollection`` API will impact the device durability


Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se05x_InvokeGarbageCollection``


Running the Example
=======================================================================

If you have built a binary, flash the binary on to the board and reset
the board.

If you have built an *exe* to be run from Windows using VCOM, run as::

    se05x_InvokeGarbageCollection.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as::

    ./se05x_InvokeGarbageCollection


Console output
=======================================================================

If everything is successful, the output will be similar to:

.. literalinclude:: out_se05x_InvokeGarbageCollection.rst.txt
   :start-after: smCom :INFO :Opening connection to JRCP server on 127.0.0.1:8050
