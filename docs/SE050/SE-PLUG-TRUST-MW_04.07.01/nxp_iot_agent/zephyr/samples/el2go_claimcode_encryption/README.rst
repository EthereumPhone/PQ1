.. _el2go_claimcode_encryption:

EL2GO Claimcode Encryption Application
######################################

Overview
********

This sample application shows how to create and store an encrypted claim code blob on MCU devices. It is meant to be used
together with the EdgeLock 2GO Agent sample, which needs to be downloaded afterwards. It will read the claim code blob
and provide it to the EdgeLock 2GO service during device connection; the EdgeLock 2GO service will then decrypt and validate
the blob and claim the device if the corresponding claim code is found in one of the device groups.

The source code for this sample application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/ex/src/apps/el2go_claimcode_encryption.c`.

Requirements
************

- FRDM-RW612 or RD-RW61X-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW61X-BGA) cable
- Personal Computer

Prerequisites
*************

- Active EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
- Any serial communicator

Setup of the EdgeLock 2GO platform
**********************************

The documentation which explains how to setup an EdgeLock 2GO account to
- Create a device group
- Create and copy a claim code for the device group
- Get the EdgeLock 2GO claim code public key (RW61x_Claiming_Public_Key)
can be found on the Edgelock 2GO web interface under the "Documentation" tab.

Prepare the Demo
****************

1.  Provide the plain claim code string as created on the EdgeLock 2GO service:

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/inc/iot_agent_demo_config.h`
    ``#define IOT_AGENT_CLAIMCODE_STRING "insert_claimcode_from_el2go";``

2.  Provide the EdgeLock 2GO claim code public key as read from EdgeLock 2GO service
    (in the format of a hexadecimal byte array): 

    in :zephyr_file:`modules/lib/nxp_iot_agent/inc/nxp_iot_agent_config_credentials.h`
    ``#define NXP_IOT_AGENT_CLAIMCODE_KEY_AGREEMENT_PUBLIC_KEY_PROD
    #define NXP_IOT_AGENT_CLAIMCODE_KEY_AGREEMENT_PUBLIC_KEY_PROD_SIZE``

3.  [Optional] The flash address where the claim code will be written to is set to 0x084A000 by default.
    The location can be changed by altering the following variable (make sure to keep it aligned with
    the address configured in the EL2GO Agent sample):

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/apps/el2go_claimcode_encryption.c`
    ``#define CLAIM_CODE_INFO_ADDRESS``

4.  [Optional] In case the example will be used in a device with secure boot mode enabled, the bootheader
    needs to be removed from the image and the resulting binary must be signed with the OEM key.
    Additionaly, if the example is supposed to run in the OEM CLOSED life cycle, the image needs to be encrypted with
    the OEM FW encryption key and loaded as an SB3.1 container.
    Details on how to execute these steps can be found in the Application note AN13813 "Secure boot on RW61x", downloadable from
    https://www.nxp.com/products/wireless-connectivity/wi-fi-plus-bluetooth-plus-802-15-4/wireless-mcu-with-integrated-tri-radio-1x1-wi-fi-6-plus-bluetooth-low-energy-5-3-802-15-4:RW612
    in the "Secure Files" section.

5.  Build the application.

6.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW61X-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW61X-BGA]) on the board.

7.  Open a serial terminal with the following settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

8.  Flash the application to the board. In case the image is signed, the base address needs to be adjusted
    to 0x08001000.

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_claimcode_encryption
   :board: <board>
   :goals: build flash
   :compact:

Sample Output
=============

.. code-block:: console

    Enabling ELS... done
    Generating random ECC keypair... done
    Calculating shared secret... done
    Creating claimcode blob... done
    claimcode (*): *** dynamic data ***
    claimcode (*): *** dynamic data ***
    claimcode (*): *** dynamic data ***
    claimcode information written to flash at address 0x84a0000
