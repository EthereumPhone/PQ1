..

    Copyright 2019,2020,2024 NXP

.. highlight:: bat

.. _ex-sems-lite-agent-demo:

=======================================================================
 SEMS Lite Agent Demo (sems_lite_ex_update)
=======================================================================

This application will update Applet through SEMS Lite agent.

In this demo, an update package, is pre-compiled into the example binary.  See :file:`SEMS_Lite_UpgradeTo_iotDev-7_3_0_A8FA.h`.   This file contans a byte array that is encoded in protobuf format. This demo will call API :cpp:type:`sems_lite_agent_load_package()` which will decode the stream and send update commands command to SE.

Note: This demo is used for OEF A8FA. If you use it for another OEF, you should update the header file with correct one.


.. only:: nxp

    .. note:: NXP internal section


    **Generate Request Packages**

    The request packages to be loaded is coded in SEMS_Lite_UpgradeTo_iotDev-7_3_0_A8FA.h. It's generated from SEMS Lite generator script which has been provided in semslite/tools/sems-lite-generator for this process :ref:`sems-lite-generator`.


Prerequisites
=====================
- Micro USB cable
- Kinetis FRDM-K64F/imx-RT1050 board
- Personal Computer
- SE051 Board
- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Build Project: ``sems_lite_ex_update``


Running the Example
=======================================================================

- In case the a new update package is available or the IC is a new OEF, replace :file:`SEMS_Lite_UpgradeTo_iotDev-7_3_0_A8FA.h`
- Recompile the example for your platform
- If you have built a binary for an embedded target,
  flash the ``sems_lite_ex_update`` binary on to the
  board and reset the board.

- If you have built an *exe* to be run from PC using VCOM, run as::

        sems_lite_ex_update.exe <PORT NAME>

  Where **<PORT NAME>** is the VCOM COM port.


