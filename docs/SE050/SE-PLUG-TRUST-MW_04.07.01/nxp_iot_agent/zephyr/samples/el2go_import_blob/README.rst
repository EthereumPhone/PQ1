.. _el2go_import_blob:

EL2GO Import Blob Application
#############################

Overview
********

This sample application shows how to import encrypted EdgeLock 2GO secure object blobs from flash to the
ITS storage. The imported objects can then be validated by executing crypto operations.

The application requires to have encrypted EdgeLock 2GO secure object blobs loaded in flash. This can be achieved
using offline provisioning with the el2go_host application.

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/ex/src/apps/psa_examples/el2go_import_blob`.

Requirements
************

- FRDM-RW612 or RD-RW61X-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW61X-BGA) cable
- Personal Computer

Prerequisites
*************

- Active EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
- Any serial communicator

Prepare the Demo
****************

1.  [Optional] By default the validation of the blobs is disabled. It can be enabled with the corresponding macro:

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/apps/psa_examples/el2go_import_blob/el2go_import_blob.h`
    ``#define VALIDATE_PSA_IMPORT_OPERATION 1`

    This value can optionally also be set in the prj.conf like this:
    ``CONFIG_VALIDATE_PSA_IMPORT_OPERATION=y``
    If its set in the prj.conf to true, then it will override the value of define
    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/apps/psa_examples/el2go_import_blob/el2go_import_blob.h`.
    
    This provides an example on how the imported blobs can be used. Specifically, the example demonstrates:
    - AES-ECB message encryption with a 256-bit key.
    - ECDSA SHA 256 message signing.

2.  [Optional] In order to maximize the TF-M ITS performance, the maximum supported blob size is set to 2908 bytes. In case
    you want to support bigger blobs (8K is the maximum size supported by PSA), you need to change the following three variables:

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/config_tfm_target.h`
    ``#define CRYPTO_ENGINE_BUF_SIZE 0x8000``
    ``#define ITS_MAX_ASSET_SIZE     3 * 0xC00``

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/partition/flash_layout.h`
    ``#define TFM_HAL_ITS_SECTORS_PER_BLOCK (3)``

3.  To correctly run the example, the secure boot mode on the device needs to be enabled. The bootheader needs to be removed
    from the SPE image, it has to be merged with the NSPE image and the resulting image must be signed with the OEM key.
    Optionally, it is possible to automate the signing and merging process by setting the following variables in the prj.conf file:
    
    ``CONFIG_EL2GO_SIGN_USING_NXPIMAGE=y``
    ``CONFIG_EL2GO_PRIVATE_KEY="PATH_TO_YOUR_KEY_PEM_FILE"``
    ``CONFIG_EL2GO_CERT_BLOCK="PATH_TO_YOUR_CERTIFICATE_YML_FILE"``
    
    With this configuration the SPE and NSPE images will automatically get merged and signed using SPSDK nxpimage tool after 
    the build is done. Furthermore, there are 2 ways to specify these variables:
    1. In prj.conf file, like stated above (has most precedence).
    2. If not set in prj.conf file, then set as environment variable using the same names: 
       CONFIG_EL2GO_PRIVATE_KEY,CONFIG_EL2GO_CERT_BLOCK,CONFIG_EL2GO_SIGN_USING_NXPIMAGE.
       Please set them to same value as you would in prj.conf file.
    Important Note: Please make sure SPSDK is set in the PATH for automated signing.

    Additionaly, if the example is supposed to run in the OEM CLOSED life cycle, the image needs to be encrypted with
    the OEM FW encryption key and loaded as an SB3.1 container.
    Details on how to execute these steps can be found in the Application note AN13813 "Secure boot on RW61x", downloadable from
    https://www.nxp.com/products/wireless-connectivity/wi-fi-plus-bluetooth-plus-802-15-4/wireless-mcu-with-integrated-tri-radio-1x1-wi-fi-6-plus-bluetooth-low-energy-5-3-802-15-4:RW612
    in the "Secure Files" section.

4.  Build the application.

5.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW61X-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW61X-BGA]) on the board.

6.  Open a serial terminal with the following settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

7.  Flash the application to the board. In case the image is signed, the base address needs to be adjusted
    to 0x08001000.

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_import_blob
   :board: <board>
   :goals: build flash
   :compact:

Sample Output
=============

.. code-block:: console

    [WRN] This device was provisioned with dummy keys. This device is NOT SECURE
    [Sec Thread] Secure image initializing!
    Booting TF-M v2.0.0
    [INF][Crypto] Provisioning entropy seed... complete.
    *** Booting Zephyr OS build RW-v3.6.0-502-g01bce12e50d6 ***
    2 blob(s) imported from flash successfully

    Validate imported blobs

     Cipher encrypt passed!

     ECC sign passed!
