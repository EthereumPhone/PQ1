..
    Copyright 2019,2020 NXP



.. highlight:: bat

.. _se052_deep_power_down_example:

=======================================================================
 SE052 Deep Power down example
=======================================================================

This project is used to demonstrate the deep power down on SE052 using
T=1oI2C command.

The example will send a proprietary deep power down command
(as described in the Datasheet) via I2C link to bring the device into the
deep power down mode. The example will wait for 10 seconds before reopening
the session which will also make the secure element wakeup from deep power down mode.


.. note ::

	Prerequisites for using deep power down is that the IC core is
	supplied via Vout like described in AN13904 SE052F - User Guidelines section
	"Application Circuit I2C Controller (with Deep Power Down)",
	as implemented on SE052 demoboard OM-SE052PCB


Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se052_deep_pwr_down``


Running the Example
=======================================================================

If you have built a binary, flash the binary on to the board and reset
the board.

If you have built an *exe* to be run from Windows using VCOM, run as::

    se052_deep_pwr_down.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as::

    ./se052_deep_pwr_down
