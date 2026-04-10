..
    Copyright 2019 NXP



.. highlight:: bat

.. _se05x-rotate-keys:

=======================================================================
 SE05X Rotate PlatformSCP Keys Demo
=======================================================================

This project is to demonstrate rotation of Platform SCP03 keys for IOT SSD.
The Platform SCP03 keys used during initial authentication can be replaced
using this example. In this example, we will rotate existing SCP03 keys to new
keys and then revert back to the old keys.

Once the key rotation is successful on the IC a file is created
``plain_scp.txt``.  This file contains updated key values written to IC. For
the next  authentication if the above file is available, the keys are taken
from the file. If the file is not present, the keys which are pre-compiled are
picked up for authentication.

.. Note ::
    SCP03 uses 3 sets of AES keys ENC MAC and DEK.
    After first rotation user can delete DEK key from file/code for security purpose.

Following are the file paths for different platforms:

**For Android**

.. literalinclude:: ../../../sss/ex/inc/ex_sss_scp03_keys.h
   :language: c
   :start-after: /* doc:start:android-scp03-path */
   :end-before: /* doc:end:android-scp03-path */

**For Linux**

.. literalinclude:: ../../../sss/ex/inc/ex_sss_scp03_keys.h
   :language: c
   :start-after: /* doc:start:linux-scp03-path */
   :end-before: /* doc:end:linux-scp03-path */


**For Windows**

.. literalinclude:: ../../../sss/ex/inc/ex_sss_scp03_keys.h
   :language: c
   :start-after: /* doc:start:windows-scp03-path */
   :end-before: /* doc:end:windows-scp03-path */


.. note:: For Android based platforms, it is important that the keymaster service
  has access to the PlatfSCP03 keys file while system boot. Be sure to update se policy
  accordingly.


Prerequisites
=====================

Since this example is portable across various platforms,
the needs are different.

See Build Plug & Trust middleware stack. (Refer :ref:`building`)


Configuring the Demo
=======================================================================

New Platform SCP03 keys are defined as following. Update your keys here.

.. literalinclude:: se05x_TP_PlatformSCP03keys.c
   :language: c
   :start-after: /* doc:start:new-scp03-keys */
   :end-before: /* doc:end:new-scp03-keys */

.. note:: We have hard-coded new PlatformSCP03 keys for demonstration purpose.
   The user can either modify these to their own keys or use a random number generator
   for randomized keys.

Old Platform SCP03 keys are defined as following. Make sure these match
the ones in SE05X.

.. literalinclude:: se05x_TP_PlatformSCP03keys.c
   :language: c
   :start-after: /* doc:start:old-scp03-keys */
   :end-before: /* doc:end:old-scp03-keys */

**The following code reverts to old Platform SCP03 keys.** If you
do not wish to revert to old keys and want to use the new keys,
comment out the following line from the example.
For development testing, we rollback to original keys.
It is left to customer to comment out this line.

.. literalinclude:: se05x_TP_PlatformSCP03keys.c
   :language: c
   :start-after: /* doc:start:revert-scp03-keys */
   :end-before: /* doc:end:revert-scp03-keys */

**Configuring Key Length For Rotation**

The ``ROTATE_PLATFORMSCP03_128BITLEN`` macro determines the key length during rotation:

• Set to 1 to rotate to 16-byte keys.
• Set to 0 to rotate to 32-byte keys.

By default, it is set to 1, meaning the keys will be rotated to 16 bytes.

Building the Demo
=======================================================================

Use the following configurations in CMake:

- ``SE05X_Auth_PlatfSCP03``: ON

Build project: ``se05x_RotatePlatformSCP03Keys``

Running the Example
=======================================================================

If you have built a binary, flash the ``se05x_RotatePlatformSCP03Keys``
binary on to the board and reset the board.

If you have built an *exe* to be run from PC using VCOM, run as::

    se05x_RotatePlatformSCP03Keys.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as::

    ./se05x_RotatePlatformSCP03Keys


Console output
=======================================================================

If everything is setup correctly the output would be as follows ::

       App:INFO :Congratulations !!! Key Rotation Successful!!!!
       App:INFO :Congratulations !!! Key Rotation Successful!!!!
       App:INFO :ex_sss Finished
