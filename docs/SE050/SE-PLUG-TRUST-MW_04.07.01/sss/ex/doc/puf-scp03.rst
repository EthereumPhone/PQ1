..
    Copyright 2020 NXP


.. highlight:: shell

.. _puf-scp03:

==========================================================
 SCP03 with PUF
==========================================================

To keep Platform SCP03 keys secure, on the LPC55S e.g. PUF can be used. PUF will have the actual keys stored and we can perform cryptographic operations with it using HashCrypt block.


Activation Code
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Activation Code (AC) is a 1192-byte code used to start 
PUF. The AC is generated during ``PUF_Enroll`` operation. 
This must be generated once for the lifetime of the device 
and stored in PFR region of flash.

Each PUF has a different AC and cannot be used with any 
other device.

.. note:: For testing, we use pre-compiled activation code from 
    :file:`ex_scp03_puf.h` instead of reading from PFR. In actual 
    use case, it **MUST** be stored and read from PFR.

Key Code
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For every key stored in PUF, we get a Key Code (KC) which 
is used to access the key. Hardware keys stored in PUF 
cannot be exported. SCP03 keys must be stored as hardware 
keys.


Using with LPC55S
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PUF is integrated with :cpp:func:`sss_session_open` in the supplied LPC55S example.
Use the following CMake configurations to compile with PUF 
on LPC55S:

- ``Host=lpcxpresso55s_s``

- ``SCP=SCP03_SSS``

- ``SE05X_Auth=PlatfSCP03``


When we compile any application on LPC55S secure zone, it will 
try to read HW keys provisioned in PUF. If in case the keys are 
not provisioned in PUF, the implementation will fallback on software 
implementation. 

.. note:: You need to pass keyCodes in connectionData to ``sss_session_open`` 
    instead of actual keys provisioned in PUF.

Only the static SCP03 keys are injected inside the PUF. Dynamic keys 
are derived from the static keys using CMAC operations with Hashcrypt 
module.

For example on how to enroll PUF and store SCP03 keys, refer :ref:`puf-inject-scp03`.

