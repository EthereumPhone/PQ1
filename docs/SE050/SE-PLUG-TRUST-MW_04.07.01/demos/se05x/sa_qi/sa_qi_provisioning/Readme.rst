..
    Copyright 2022 NXP

.. highlight:: bat

.. _ex-se05x-qi-provisioning:

=======================================================================
 Secure Authenticator (Qi) Provisioning demo
=======================================================================

This project is used to provision Qi credentials (ECDSA Key pair and Device certificate chain) inside 
the secure element.

.. warning:: This example is only for demonstration purpose. Maintaining 
    and provisioning the credentials should be done in a secure way.

The user should update the credentials ``qi_ec_priv_key``
and ``qi_certificate_chain`` in :file:`demos/se05x/sa_qi_provisioning/sa_qi_credentials.c`

By default the demo will provision the credentials for Slot ID 0. The user can update the macro ``QI_PROVISIONING_SLOT_ID``
in :file:`demos/se05x/sa_qi_provisioning/sa_qi_provisioning.h` to provision for a different slot:

.. literalinclude:: sa_qi_provisioning.h
    :language: c
    :start-after: /* doc:start:qi-slot-id */
    :end-before: /* doc:end:qi-slot-id */

This demo requires the credentials to be provisioned using a management credential. 
In this example we use the demo key provisioned at ``kEX_SSS_ObjID_APPLETSCP03_Auth`` 
(:file:`sss/ex/inc/ex_sss_objid.h`) to open an AESKey session and provision the 
credentials. The user is expected to provision their own authentication key and use 
that for provisioning the Qi credentials by updating the macro 
``EX_SSS_AUTH_SE05X_APPLETSCP_VALUE`` in :file:`sss/ex/inc/ex_sss_auth.h`:

.. literalinclude:: /sss/ex/inc/ex_sss_auth.h
    :language: c
    :start-after: /* doc:start:auth-key-applet-scp */
    :end-before: /* doc:end:auth-key-applet-scp */

Also see example :numref:`delete-and-test-provision` :ref:`delete-and-test-provision` for 
details on how to provision an authentication object.

Pre-requisites
=======================================================================

- Example :numref:`delete-and-test-provision` :ref:`delete-and-test-provision` 
  must be run to provision the AESKey for establishing the session.

Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)

Select CMake options:

- ``PTMW_SCP=SCP03_SSS``
- ``PTMW_SE05X_Auth=AESKey``
- ``PTMW_SE05X_Ver=07_02``

Build project:

- Project: ``sa_qi_provisioning``

Running the Example
=======================================================================

If you have built a binary, flash the binary on to the board and reset
the board.

If you have built an *exe* to be run from Windows using VCOM, run as::

    sa_qi_provisioning.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On successful execution you should be able to see logs as::

    App :INFO :PlugAndTrust_v04.01.01_20220112
    sss :INFO :atr (Len=35)
    01 A0 00 00 03 96 04 03 E8 00 FE 02 0B 03 E8 00
    01 00 00 00 00 64 13 88 0A 00 65 53 45 30 35 31
    00 00 00
    App :INFO :Qi Provisioning successful
    App :INFO :Qi Provisioning Example Finished
    App :INFO :ex_sss Finished
