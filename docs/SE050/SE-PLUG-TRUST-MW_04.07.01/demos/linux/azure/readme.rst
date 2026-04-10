..
    Copyright 2019,2020 NXP


.. highlight:: shell

.. _linux-demos-azure:

Azure Demo for iMX Linux / Raspberry Pi
========================================================================

This demo demonstrates connection to Azure IoTHub using pre-provisioned
device credentials and demonstrates publish/subscribe procedure using MQTT.

The example is last tested with Plug and Trust Middleware version 4.5.1.

Prerequisites
----------------------------------

-  Azure account
-  SD Card image with SE050 Middleware pre-installed. The application is
   built on the iMX platform.
-  IMX6UL-EVK platform or Raspberry pi connected to the Internet
-  On Raspberry Pi, use the commands to ensure that the setup is comeplete.

   1) sudo apt-get update
   #) sudo apt-get install autoreconf
   #) sudo apt-get install libtool
   #) sudo apt-get install build-essential gcc make cmake cmake-gui cmake-curses-gui

Preparing the credentials and Provisioning the secure element
-------------------------------------------------------------------------

Use ssscli tool from iMX/Rpi platform

1) Complete :numref:`cli-doc-pre-steps` :ref:`cli-doc-pre-steps`

#)  To create certificates on imx and Raspberry Pi, call::

        cd simw-top/pycli/Provisioning
        python3 GenerateAZURECredentials.py
        python3 ResetAndUpdate_AZURE.py

    .. note::
            Provisioning of the keys is done with default policies.
            Refer - :numref:`cli-object-policy` to change the scripts to add required policies.

#) Certificates and Keys are generated at ``simw-top/pycli/Provisioning/azure``


Registering Device
-------------------------------------------------------------

To register the device onto the IoT Hub portal, we can either upload Root credentials manually
or we can register an individual device using ``azure_imx_register`` application. If you wish
to upload Root credentials, skip the next steps and proceed to :ref:`azure-imx-upload-root`.


.. _azure-register-device:

Create device enrollment in azure IoT Hub portal
-------------------------------------------------------------
**This step is only for individual device enrollment.**

Prerequisite: Azure IOT hub and Azure IOT HUB DPS account which are linked.

Refer: https://docs.microsoft.com/en-us/azure/iot-dps/tutorial-set-up-cloud

https://docs.microsoft.com/en-us/azure/iot-dps/quick-setup-auto-provision

Once required accounts exist we can enroll the devices.
For this we only need device certificate which we created in above steps.

Follow the steps to enroll the device: https://docs.microsoft.com/en-us/azure/iot-dps/tutorial-provision-device-to-hub

.. note:: When creating device certificates be sure to use only lower-case alphanumerics and hyphens in your device name.

Run ``azure_imx_register`` application to register the device onto your IoT Hub.

``azure_imx_register`` application can take parameters either via JSON file or via command line.
The required parameters are:

- registerid: Registration id of the device (common name of device certificate)
- keypath:  Path to reference key pem file
- devcert: Path to device certificate
- rootpath: Path to azure root CA certificate
- idscope: IDScope (can found in Azure IoT-DPS account - Overview)

Run via command line as::

  ./azure_imx_register --registerid test-device --keypath keyref.pem --rootpath azureRootCA.pem --devcert cert.pem --idscope 0ne00068F95

Or pass JSON file as::

  ./azure_imx_register --json json_register_config.json

Sample JSON file::

  {
    "devcert": "cert.pem",
    "keypath": "keyref.pem",
    "id_scope": "0ne00068F95",
    "registration_id": "test-device",
    "rootpath": "azureRootCA.pem"
  }

Upon successful registration, "DeviceID".txt file is created with DeviceID, assigned hub along with keyref, device certificate and root certificate path.
This file can be given as input to connect to device and send messages.

The device is now registered and appears on IoT Azure hub under devices tab

We can pass this JSON file to ``azure_imx_connect`` application to connect to IoT Hub. You can skip the next step and proceed to :ref:`azure-openssl-build`.


.. _azure-imx-upload-root:

Uploading root certificates to IoT Hub
-------------------------------------------------------------

1) On Azure IoT Hub portal, Navigate to ``Dashboard --> <Your IoT Hub> --> Certificates``. Click on Add

#) Enter a friendly name and upload the root certificate created in the previous step. Location -  ``simw-top/pycli/Provisioning/azure/RootCA.cer`` -> Save

#) Your certificate will show in the Certificate Explorer list. Click on certificate added

#) In Certificate Details, click Generate Verification Code

#) The provisioning service creates a Verification Code that you can use to validate the certificate ownership. Copy the code to your clipboard

#) Use the verification_certificate.py to generate a verify certificate (verifyCert4.cer) ::

        cd simw-top/pycli/Provisioning
        python verification_certificate.py <RootCA_Certificate> <RootCA_Keypair> <Verification Code>

#) On ``Azure portal -> Certificate Details``, upload the verifyCert4.cer file generated and click Verify.

   STATUS of your certificate should change to ``Verified`` in the Certificate Explorer list


.. _azure-openssl-build:


Build the OpenSSL engine [Optional]
-------------------------------------------------------------

.. note::
    This step is optional in case you are using a prepared
    SD card image from NXP.

The OpenSSL engine uses the sss abstraction layer to access the crypto
services of the secure element, the implementation remains dependent on
the secure element attached. The following illustrates compiling the
OpenSSL engine for SE050 connected over I2C.

::

   cd simw-top
   python scripts/create_cmake_projects.py
   cd ../simw-top_build/imx_native_se050_t1oi2c
   cmake --build .
   make install
   ldconfig /usr/local/lib

.. note::
    Replace ``imx_native_se050_t1oi2c`` with ``raspbian_native_se050_t1oi2c``
    when building for Raspberry Pi.

Build the OpenSSL provider [Optional]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
    This step is optional in case you are using a prepared SD card
    image from NXP.

The OpenSSL provider uses the sss abstraction layer to access the crypto
services of the secure element, the implementation remains dependent on
the secure element attached. The following illustrates compiling the
OpenSSL provider for SE050 connected over I2C.

::

   cd simw-top
   python scripts/create_cmake_projects.py
   cd ../simw-top_build/imx_native_se050_t1oi2c
   cmake -DPTMW_OpenSSL:STRING=3_0 -DPTMW_HostCrypto:STRING=OPENSSL .
   cmake --build .
   make install
   ldconfig /usr/local/lib


.. note::
    Replace ``imx_native_se050_t1oi2c`` with ``raspbian_native_se050_t1oi2c``
    when building for Raspberry Pi.

Run the example
---------------

1) Use 'buildScript.sh' script at simw-top/demos/linux/azure/ to download all dependencies and build the mqtt application for azure call::

    cd /simw-top/demos/linux/azure
    ./buildScript.sh

#) Search for `provider_sect` in ``/simw-top/demos/linux/common/openssl30_sss_se050.cnf`` file and set the nxp provider with high priority.

        nxp_prov = nxp_prov_sec
        default = default_sect

#) Based on OpenSSL version and applicable Secure Element, select the appropriate configuration file in
   ``<MW_SRC_DIR>/simw-top/demos/linux/common`` directory::

        openssl11_sss_se050.cnf   ----- OpenSSL 1.1.1 and SE050
        openssl_sss_se050.cnf     ----- OpenSSL 1.0.0 and SE050
        openssl30_sss_se050.cnf   ----- OpenSSL 3.x and SE050

#) Set the openssl config path as call::

    $ export OPENSSL_CONF=/simw-top/demos/linux/common/<appropriate-cnf-file>

#) To run the application, call::

    $ ./azure_imx_connect --deviceid "<devive_name>" --keypath simw-top/pycli/Provisioning/azure/<UID>_device_reference_key.pem --rootpath simw-top/demos/linux/azure/azureRootCA.pem --devcert simw-top/pycli/Provisioning/azure/<UID>_device_certificate.cer --hubname <IotHubName>.azure-devices.net --username <IotHubName> --payload "<MESSAGE>"


   Or pass JSON file as::

    ./azure_imx_connect --json json_connect_config.json

   Sample json_connect_config.json::

    {
      "assignedHub": "ABCD.azure-devices.net",
      "deviceId": "test-device",
      "registration_id": "test-device",
      "status": "assigned",
      "keypath": "keyref.pem",
      "devcert": "cert.pem",
      "rootpath": "azureRootCA.pem",
      "payload": "hello message from device test-device"
    }

   .. note:: If you have used ``azure_imx_register`` application, ``json_connect_config.json`` is same as ``"DeviceID".txt``


.. note::
    1) Export the OpenSSL conf path to the exact location of the file. The above example is for illustrative purpose
    2) While executing the application, use the appropriate values for device cert, Device id, Path, hubname and username
