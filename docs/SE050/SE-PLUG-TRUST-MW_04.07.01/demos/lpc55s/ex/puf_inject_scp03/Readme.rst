..
    Copyright 2019 NXP

.. highlight:: shell

.. _puf-inject-scp03:

==========================================================
 Key Injection to PUF
==========================================================

This example demonstrates how to enroll PUF on LPC55S, inject 
PlatformSCP keys into PUF and retrieve key codes.
This example can be used as a starting point to inject default 
SCP03 keys into PUF. 

.. note:: After running this example, update :file:`ex_scp03_puf.h` 
    file with the new Activation code and keyCodes.

Pre-requisites
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- :numref:`platform-lpc55s69` :ref:`platform-lpc55s69`
- :numref:`logging-on-console` :ref:`logging-on-console`
- Build Plug & Trust middleware stack. (Refer :ref:`building`)


How to build
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Replace the following keys with the keys to be provisioned 
  into PUF:

  .. literalinclude:: puf_inject_scp03.c
      :language: c
      :start-after: /* doc:start:old-scp03-keys */
      :end-before: /* doc:end:old-scp03-keys */


  For information on PUF, refer :ref:`puf-scp03`.

- Compile and run the example with the following CMake options:

  - ``Host=lpcxpresso55s``

  - Project:``puf_inject_scp03``


How to use
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Flash the binary on the device.
- On successful execution, you will be able to see the ActivationCode 
  and KeyCodes printed out on the console.


.. _injecting-keys-into-puf:

Injecting keys into PUF
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Refer to the below implementation on how to implement a simple 
function to inject SCP03 keys into PUF.

.. literalinclude:: puf_inject_scp03.c
    :language: c
    :start-after: /* doc:start:puf-insert-scp03-keys */
    :end-before: /* doc:end:puf-insert-scp03-keys */

