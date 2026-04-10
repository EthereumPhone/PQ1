.. _el2go_blob_test:

EL2GO Blob Test
###############

Overview
********

This is a test suite which imports and validates EL2GO blobs and their usage with PSA.
You will first need to replace the placeholder blobs with real ones from EL2GO.

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent/tst/el2go_blob_test`.

Requirements
************

- FRDM-RW612 or RD-RW61X-BGA board
- USB-C (FRDM-RW612) or Micro-USB (RD-RW61X-BGA) cable
- Personal Computer

Prerequisites
*************

- Any serial communicator
- EdgeLock 2GO blobs for your board

Prepare the Tests
*****************

1.  Obtain a RTP JSON file from EdgeLock 2GO containing the desired blobs for your board.

    ATTENTION: Make sure the lifecycle and RKTH of your blobs match the one of the board.

2.  Run the file trough the preprocessor:
    :zephyr_file:`modules/lib/nxp_iot_agent/tst/el2go_blob_test/scripts/el2go_blob_test_pre.py` [RTP_JSON_PATH]

    Optionally, it is possible to automate this before the build by setting:
     ``CONFIG_RTP_JSON="YOUR_PATH"``
    in the prj.conf file. It first takes the Python executable from the virtual environment, if one is present.
    Furthermore, this value can be set as environment variable, but the value in prj.conf has
    most precedence. Set as environment variable using same name CONFIG_RTP_JSON.

    NOTE: Python >= 3.10 with packages from :zephyr_file:`modules/lib/nxp_iot_agent/tst/el2go_blob_test/scripts/requirements.txt` required

3.  [Optional] In order to maximize the TF-M ITS performance, the maximum supported blob size is set to 2908 bytes. In case
    you want to support bigger blobs (8K is the maximum size supported by PSA), you need to change the following three variables:

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/config_tfm_target.h`
    ``#define CRYPTO_ENGINE_BUF_SIZE 0x8000``
    ``#define ITS_MAX_ASSET_SIZE     3 * 0xC00``

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/partition/flash_layout.h`
    ``#define TFM_HAL_ITS_SECTORS_PER_BLOCK (3)``

    Afterwards, you can set ``CONFIG_LARGE_BLOBS_ENABLED=y`` in proj.conf.

4.  To correctly run the example, the secure boot mode on the device needs to be enabled. The bootheader needs to be removed
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

9.  [Optional] If you capure the console output of the test application, you can feed it into the postprocessor to recieve the results in the JUnit format:
    :zephyr_file:`modules/lib/nxp_iot_agent/tst/el2go_blob_test/scripts/el2go_blob_test_post.py` [CONSOLE_OUTPUT_PATH] [JUNIT_OUT_PATH]

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/tests/el2go_blob_test
   :board: <board>
   :goals: build flash
   :compact:

Test Output
===========

.. code-block:: console

    [WRN] This device was provisioned with dummy keys. This device is NOT SECURE
    [Sec Thread] Secure image initializing!
    Booting TF-M v1.8.0
    [INF][Crypto] Provisioning entropy seed... complete.
    *** Booting Zephyr OS build zephyr-v3.5.0-5365-g9d2cefa7fd2f ***
    
    #### Start EL2GO blob tests ####
    Running test suite INTERNAL (EL2GO_BLOB_TEST_INTERNAL_10XX)
    > Executing test EL2GO_BLOB_TEST_INTERNAL_1000 
      Description: 'Internal AES128 CIPHER CTR'
      Placeholder blob
      Test EL2GO_BLOB_TEST_INTERNAL_1000 - SKIPPED
    [...]
    > Executing test EL2GO_BLOB_TEST_INTERNAL_1031 
      Description: 'Internal HMAC256 KDF HKDFSHA256'
      Placeholder blob
      Test EL2GO_BLOB_TEST_INTERNAL_1031 - SKIPPED
    15 of 15 SKIPPED
    Test suite INTERNAL (EL2GO_BLOB_TEST_INTERNAL_10XX) - PASSED
    Running test suite EXTERNAL (EL2GO_BLOB_TEST_EXTERNAL_2XXX)
    > Executing test EL2GO_BLOB_TEST_EXTERNAL_2000 
      Description: 'External BIN1B EXPORT NONE'
      Placeholder blob
      Test EL2GO_BLOB_TEST_EXTERNAL_2000 - SKIPPED
    [...]
    > Executing test EL2GO_BLOB_TEST_EXTERNAL_219D 
      Description: 'External RSA4096 NONE NONE'
      Placeholder blob
      Test EL2GO_BLOB_TEST_EXTERNAL_219D - SKIPPED
    190 of 190 SKIPPED
    Test suite EXTERNAL (EL2GO_BLOB_TEST_EXTERNAL_2XXX) - PASSED
    
    #### Summary ####
    Test suite INTERNAL (EL2GO_BLOB_TEST_INTERNAL_10XX) - PASSED
    Test suite EXTERNAL (EL2GO_BLOB_TEST_EXTERNAL_2XXX) - PASSED
    
    #### EL2GO blob tests finished ####
