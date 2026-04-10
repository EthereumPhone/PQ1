..
    Copyright 2019,2020,2025 NXP



.. highlight:: batch

.. _ksdk-demos-aws:

=======================================================================
 AWS Demo for MCU-SDK
=======================================================================

This demo demonstrates connection to AWS IoT Console using pre-provisioned
device credentials and publish/subscribe procedure using MQTT.

The example demonstrates standard flow of AWS cloud connectivity (Not JITR flow).

Prerequisites
=======================================================================
- Active AWS account
- MCUXpresso  installed (for running aws demo on K64F)
- Any Serial communicator
- Flash VCOM binary on the device. VCOM binary can found under :file:`simw-top/binaries/MCU` folder.
- Refer to :ref:`cli-tool` for ssscli tool setup
- Build Plug & Trust middleware stack. (Refer :ref:`building`)


Using WiFi with LPC55S
=======================================================================

WiFi shield CMWC1ZZABR-107-EVB by muRata is supported with LPC55S. Mount the WiFi shield on to the
mikroBUS stackable headers.

**Connection of muRata with LPC55s**

Refer - https://www.murata.com/en-sg/products/connectivitymodule/wi-fi-bluetooth/overview/lineup/typeabr

Update ``clientcredentialWIFI_SSID`` and ``clientcredentialWIFI_PASSWORD``
in ``simw-top/demos/ksdk/common/wifi_config.h`` with your wifi credentials.


.. _prepare-aws-cloud:

Creating a device on AWS account
===========================================================================

Refer - https://docs.aws.amazon.com/iot/latest/developerguide/iot-gs-first-thing.html

Refer - https://aws.amazon.com/blogs/mobile/use-your-own-certificate-with-aws-iot/#:~:text=In%20the%20AWS%20Console%2C%20navigate%20to%20AWS%20IoT%2C,to%20upload%20your%20device%20certificate%20into%20AWS%20IoT.

Refer - https://www.nxp.com/docs/en/application-note/AN12404.pdf


Creating  and updating device keys and certificates to SE
===========================================================================

1) To generate AWS credentials, refer `AWS IoT Credentials <https://aws.amazon.com/blogs/mobile/use-your-own-certificate-with-aws-iot/#:~:text=In%20the%20AWS%20Console%2C%20navigate%20to%20AWS%20IoT%2C,to%20upload%20your%20device%20certificate%20into%20AWS%20IoT.>`_ Ensure that the appropriate Root CA, Root Ca Verification Certificate and device certificate are uploaded to AWS.

#) Complete :numref:`cli-doc-pre-steps` :ref:`cli-doc-pre-steps`

#) Flash the vcom binary from `simw-top/binaries/MCU` and check the vcom port number

#) Provision the generated device key in SE050 using ssscli.

::

    ssscli connect SE05X <connection method> <port name>

    ssscli set ecc pair <key-id> <device-key>

    ssscli set cert <cert-id> <device-certificate>

#) Update the SSS_CERTIFICATE_INDEX_CLIENT and SSS_KEYPAIR_INDEX_CLIENT_PRIVATE in aws_iot_config.h

Building the Demo
=======================================================================
1) Open cmake project found under :file:`SIMW-TOP/projects` in MCUXPRESSO IDE

#) To get the AWS IoT MQTT broker endpoint for your account, go to the AWS IoT console and in the left navigation pane choose Settings. Copy the endpoint listed under the "Device data endpoint"

#) In the `simw-top/demos/ksdk/common/aws_client_credential_keys.h` file, update the endpoint in the macro "clientcredentialMQTT_BROKER_ENDPOINT" and thing name in the macro "clientcredentialIOT_THING_NAME"

#) In the `simw-top/demos/ksdk/common/aws_client_credential_keys.h` file, update the endpoint in the macro
   "clientcredentialMQTT_BROKER_ENDPOINT" and thing name in the macro "clientcredentialIOT_THING_NAME"

#) Update cmake options::
    - ``RTOS=FreeRTOS``
    - ``mbedTLS_ALT=SSS``

#) Update cmake options for Host MCXN947::
    - ``RTOS=FreeRTOS``
    - ``mbedTLS=3_X``

#) Update the build target in make file
    - Project:``cloud_aws``


Running the Demo
=======================================================================

1) Open a serial terminal on PC for OpenSDA serial device with these settings::

    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control
    - change Setup->Terminal->New-line->Receive->AUTO

#) Connect the boards's RJ45 to network with Internet access (IP address to the
   board is assigned by the DHCP server). Make sure the connection on port 8883
   is not blocked.

#) Download the program to the target board.

#) Either press the reset button on your board or launch the debugger in your IDE to begin running the demo.

#) The BLUE LED is turned ON during boot

#) Persistent RED LED ON indicates error

#) First time during connection, the device certificate needs to be
    - Activated
    - Attached with a policy that allows usage of this certificate

#) All lights off along with the following message indicates readiness to
   subscribe messages from AWS::

        Subscribing...
        -->sleep
        -->sleep
        Publish done

   In AWS IOT shadow, the following indicates the state of the LED::

        {
            "desired": {
            "COLOR": "RED",
            "MODE": "OFF"
            }
        }

   MODE can be ON or OFF and COLOR can be RED, GREEN or BLUE
