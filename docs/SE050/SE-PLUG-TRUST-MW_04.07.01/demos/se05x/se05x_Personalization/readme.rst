..
    Copyright 2019 NXP


.. _se05x-personalization:

=================================================
 DEMO for Personalization of SE051
=================================================


This demo can be used to personalize some of the
parameters for SE051.


The demo is self explanatory::

    se05x_Personalization.exe <operation> [operation] <port_name>

    Where, 'operation': one or sequence of the following:

                               HELP : Prints list of APIs
         I2C_DisableClockStretching : I2C: Disables clock stretching
          I2C_EnableCLockStretching : I2C: Enables clock stretching
                     I2C_ProtocolGP : I2C: Use GP Mode for I2C
                     I2C_ProtocolUM : I2C: Use UM Mode like SE050 for I2C
             I2C_ProtocolAutoDetect : I2C: Automatically detect I2C Protocol
                 I2C_ProtocolManual : I2C: Manually use fixed Protocol
                I2C_EnablePowerSave : I2C: Go to power save after last APDU
               I2C_DisablePowerSave : I2C: DO not go to power save after last APDU
                   I2C_SemiBlocking : I2C: SEMI Blocking I2C
                    I2C_NonBlocking : I2C: Non Blocking I2C
                RM_MOD_IOT_EXTENDED : Delete: Extension to Elliptic Curve Cryptography.
                    RM_MOD_IOT_BASE : Delete: Collection of crypto algorithms often used in IoT devices.
           RM_MODX_EGOVACCELERATORS : Delete: Secure Messaging Accelerators for eGovernment applications and modular arithmetic math API.
                   RM_MOD_RSAKEYGEN : On chip generation of RSA keys.

For further details, please see product user manual.

.. note:: You can add more operations in a single command.

.. warning:: These values are effective only after IC Reset.


Compatible settings from host and SE
=================================================

Some parameters need compatible settings at
both sides, from host and SE.  Else it leaves
system in a non-operable state.

e.g. If the SE is configured to be in ``ProtocolGP``,
and host is using ``ProtocolUM``, there can't be any
further communication with the SE without re-compiling
the middleware/demo at the host.   And since the communication
between Host and SE is not function, there is no direct/easy
way to re-configure the SE Back.
