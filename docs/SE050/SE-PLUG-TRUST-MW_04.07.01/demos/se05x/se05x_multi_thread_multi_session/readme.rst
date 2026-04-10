..
    Copyright 2019,2020 NXP



.. highlight:: bat

.. _se05x_multi_thread_multi_session:

=======================================================================
 SE05X Multi Thread and Multi session example
=======================================================================

This example is used to demonstrate accessing secure element with
multiple threads and each thread with its own session.


Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se05x_multi_thread_multi_session``


Running the Example
=======================================================================

On Raspberry-Pi or iMX board, run as::

    ./se05x_multi_thread_multi_session <PORT_FOR_THREAD1> <PORT_FOR_THREAD2>


The example will accept two communication ports used by 2 threads as input arguments.
When using the example with access manager, pass the access manager address (default - 127.0.0.1:8040)
as both arguments.

Example ::

    ./se05x_multi_thread_multi_session  127.0.0.1:8040  127.0.0.1:8040
