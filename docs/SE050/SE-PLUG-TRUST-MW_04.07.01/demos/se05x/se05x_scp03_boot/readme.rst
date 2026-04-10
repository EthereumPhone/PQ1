..
    Copyright 2021 NXP



.. highlight:: bat

.. _se05x-scp03-boot:

=======================================================================
 SE05X SCP03 BOOT Example
=======================================================================

This project demonstrates that the HostOS does NOT need to know the SCP03 Base Keys to establish an SCP03 session.
Provided the boot loader has established the SCP03 session and saved the SCP03 session state.

Refer - :file:`simw-top/demos/se05x/se05x_scp03_boot/se05x_scp03_boot.c`

Prerequisites
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se05x_scp03_boot``
- Required build settings ::

    cmake -DPTMW_SCP:STRING=SCP03_SSS -DPTMW_SE05X_Auth:STRING=PlatfSCP03 -DPTMW_SMCOM:STRING=T1oI2C
    make se05x_scp03_boot


Running the Example
=======================================================================

Create ``/tmp/SE05X`` directory (if not exists) to store the session keys.

If you have built on Raspberry-Pi or iMX board, run as::

    ./se05x_scp03_boot BOOTLOADER_ROLE
    ./se05x_scp03_boot HOST_OS_RESUME