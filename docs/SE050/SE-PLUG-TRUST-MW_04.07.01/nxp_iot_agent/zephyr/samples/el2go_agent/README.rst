.. _el2go_agent:

EL2GO Agent Application
#######################

Overview
********

This sample application shows how to use the EdgeLock 2GO service to provisioning keys and certificates to an MCU device.
Those keys and certificates can then be used to establish mutual-authenticated TLS connections to cloud services such as AWS or Azure.

It supports two modes for registering a device at the EdgeLock 2GO service:
- UUID registration: At startup, the demo prints the UUID which can be used for manual registration
- Claiming: The EL2GO Claimcode Encryption sample must be run before, which will store a claim code blob
in the flash memory. The EL2GO Agent sample will present the claim code to the EdgeLock 2GO service
and automatically register the device.

The device on which the example is run must have secure boot enabled, otherwise the blob verification and
decryption keys can't be derived.

The source code for this application can be found at:
:zephyr_file:`modules/lib/nxp_iot_agent`.

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

The documentation which explains how to setup the EdgeLock 2GO Account to
- Create a device group and whitelist the device UUID
- Create and copy a claim code for the device group
- Create secure objects
- Assign the secure objects to the device group
can be found on the Edgelock 2GO web interface under the "Documentation" tab.

Prepare the Demo
****************
1.  Provide the EdgeLock 2GO URL for the account (can be found in the "Admin" section):

    in :zephyr_file:`modules/lib/nxp_iot_agent/inc/nxp_iot_agent_config.h`
    ``#define EDGELOCK2GO_HOSTNAME``

    This value can optionally also be set in the prj.conf like this:
    ``CONFIG_EDGELOCK2GO_HOSTNAME="YOUR_HOSTNAME"``
    If it's set in the prj.conf, then it will override the value of define
    in :zephyr_file:`modules/lib/nxp_iot_agent/inc/nxp_iot_agent_config.h`.
    Furthermore, this value can be set as environment variables, but the value in prj.conf has
    most precedence. Set as environment variable using same name CONFIG_EDGELOCK2GO_HOSTNAME.

2.  Provide the Wi-Fi access point credentials:

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/network/iot_agent_network_zephyr_wifi.c`
    ``#define AP_SSID``
    ``#define AP_PASSWORD``
    
    These values can optionally also be set in the prj.conf like this:
    ``CONFIG_AP_SSID="YOUR_SSID"``
    ``CONFIG_AP_PASSWORD="YOUR_PASSWORD"``
    If these are set in the prj.conf, then it will override the value of defines
    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/network/iot_agent_network_zephyr_wifi.c`.
    Furthermore, these values can be set as environment variables, but the values in prj.conf have
    most precedence. Set as environment variable using same names CONFIG_AP_SSID and CONFIG_AP_PASSWORD.

3.  [Optional] In case you want to use the "Claiming" registration method, enable the corresponding macro:

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/inc/iot_agent_demo_config.h`
    ``#define IOT_AGENT_CLAIMCODE_INJECT_ENABLE 1``

    This value can optionally also be set in the prj.conf like this:
    ``CONFIG_IOT_AGENT_CLAIMCODE_INJECT_ENABLE=y``
    If it's set in the prj.conf, then it will override the value of define
    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/inc/iot_agent_demo_config.h`.

    The flash address where the claim code will be written to is set to 0x084A000 by default.
    The location can be changed by altering the following variable (make sure to keep it aligned with
    the address configured in the EL2GO Claimcode Encryption sample):

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/src/utils/iot_agent_claimcode_inject.c`
    ``#define CLAIM_CODE_INFO_ADDRESS``

4.  [Optional] In case you want to use provisioned ECC key pairs and corresponding X.509 certificates
    to execute TLS mutual-authentication and MQTT message exchange with AWS and/or Azure clouds, enable the corresponding macro:

    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/inc/iot_agent_demo_config.h`
    ``#define IOT_AGENT_MQTT_ENABLE 1``

    In the same file, the following macros should be set to the object ID as defined at EdgeLock 2GO service:
    ``#define $SERVER$_SERVICE_KEY_PAIR_ID``
    ``#define $SERVER$_SERVICE_DEVICE_CERT_ID``

    These values can optionally also be set in the prj.conf like this:
    ``CONFIG_IOT_AGENT_MQTT_ENABLE=y``
    ``CONFIG_$SERVER$_SERVICE_KEY_PAIR_ID=0x081000``
    ``CONFIG_$SERVER$_SERVICE_DEVICE_CERT_ID=0x080100``
    If these are set in the prj.conf, then it will override the value of defines
    in :zephyr_file:`modules/lib/nxp_iot_agent/ex/inc/iot_agent_demo_config.h`.

    The settings of other macros are server dependent and their meaning can be found in the AWS/Azure documentation.
    By default, the demo is executing a connection to both clouds when IOT_AGENT_MQTT_ENABLE is enabled;
    To enable or disable them individually, use the AWS_ENABLE and AZURE_ENABLE macros respectively.

5.  [Optional] In order to maximize the TF-M ITS performance, the maximum supported blob size is set to 2908 bytes. In case
    you want to support bigger blobs (8K is the maximum size supported by PSA), you need to change the following three variables:

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/config_tfm_target.h`
    ``#define CRYPTO_ENGINE_BUF_SIZE 0x8000``
    ``#define ITS_MAX_ASSET_SIZE     3 * 0xC00``

    in :zephyr_file:`modules/tee/tf-m/trusted-firmware-m/platform/ext/target/nxp/<board>/partition/flash_layout.h`
    ``#define TFM_HAL_ITS_SECTORS_PER_BLOCK (3)``

6.  To correctly run the example, the secure boot mode on the device needs to be enabled. The bootheader needs to be removed
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

7.  Build the application.

8.  Connect the USB-C (FRDM-RW612) or Micro-USB (RD-RW61X-BGA) cable to the PC host and the MCU-Link USB port
    (J10 [FRDM-RW612] or J7 [RD-RW61X-BGA]) on the board.

9.  Open a serial terminal with the following settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control

10. Flash the application to the board. In case the image is signed, the base address needs to be adjusted
    to 0x08001000.

Building, Flashing and Running
******************************

.. zephyr-app-commands::
   :zephyr-app: modules/lib/nxp_iot_agent/zephyr/samples/el2go_agent
   :board: <board>
   :goals: build flash
   :compact:

Sample Output
=============

.. code-block:: console

    Booting TF-M v2.1.0
    [WRN] This device was provisioned with dummy keys. This device is NOT SECURE
    [Sec Thread] Secure image initializing!
    [INF][PS] Encryption alg: 0x5500200
    [INF][Crypto] Provision entropy seed...
    [INF][Crypto] Provision entropy seed... complete.
    Wi-Fi cau temperature : 27
    MAC Address: MY_MAC_ADDRESS
    PKG_TYPE: BGA
    Set BGA tx power table data 
    *** Booting Zephyr OS build b9f5bf039849 ***
    Connecting to SSID 'WIFI SSID' ...
    PKG_TYPE: BGA
    Set BGA tx power table data 
    Using WIFI 4 (802.11n/HT) @ 2.4GHz (Channel 6, -66 dBm)
    Using IPv4 address 172.20.10.4 @ Gateway 172.20.10.1 (DHCP)
    Successfully connected to WIFI
    Performance timing: DEVICE_INIT_TIME : 11950ms
    Start
    UID in hex format: MY_UUID
    UID in decimal format: MY_DECIMAL_UUID
    Updating device configuration from [MY_EL2GO_ID.device-link.staging.edgelock2go.com]:[443].
    Update status report:
      The device update was successful (0x0001: SUCCESS)
      The correlation-id for this update is 80c501f1-c13d-4eb5-8229-45e55f014c39.
      Status for remote trust provisioning: 0x0001: SUCCESS.
        On endpoint 0x70000010, for object 0x00004000, status: 0x0002: SUCCESS_NO_CHANGE.
        On endpoint 0x70000010, for object 0x00004001, status: 0x0002: SUCCESS_NO_CHANGE.
        On endpoint 0x70000010, for object 0x00004100, status: 0x0002: SUCCESS_NO_CHANGE.
        On endpoint 0x70000010, for object 0x00004101, status: 0x0002: SUCCESS_NO_CHANGE.
    Found configuration data for 0 services.
    Performance timing: ENTIRE_SESSION_TIME : 3872ms
            Performance timing: AGENT_INIT_TIME : 124ms
            Performance timing: TLS_PREP_TIME : 126ms
            Performance timing: NETWORK_CONNECT_TIME : 1305ms
            Performance timing: PROCESS_PROVISION_TIME : 2260ms
            CRL_TIME : [56ms] and COMMAND_TXRX_TIME : [0ms] included in PROCESS_PROVISION_TIME
