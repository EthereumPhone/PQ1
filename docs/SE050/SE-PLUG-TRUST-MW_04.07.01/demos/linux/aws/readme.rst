..
    Copyright 2019,2020,2025 NXP


.. highlight:: shell

.. _linux-demos-aws:

AWS Demo for iMX Linux / RaspberryPi
==================================================

This demo demonstrates connection to AWS IoT Console using pre-provisioned
device credentials and publish/subscribe procedure using MQTT.

Prerequisites
-------------

-  AWS account
-  SD Card image with SE050 Middleware pre-installed. The application is
   built on the iMX platform.
-  IMX6UL-EVK platform or Raspberry pi connected to the Internet

Preparing the credentials and Provisioning the secure element
-------------------------------------------------------------

1)  To generate AWS credentials, refer `AWS IoT Credentials <https://aws.amazon.com/blogs/mobile/use-your-own-certificate-with-aws-iot/#:~:text=In%20the%20AWS%20Console%2C%20navigate%20to%20AWS%20IoT%2C,to%20upload%20your%20device%20certificate%20into%20AWS%20IoT.>`_ Ensure that the appropriate Root CA, Root Ca Verification Certificate and device certificate are uploaded to AWS.

#) Complete :numref:`cli-doc-pre-steps` :ref:`cli-doc-pre-steps`

#) Provision the generated device key in SE050 using ssscli.

::

    ssscli connect se05x <connection method> <port name>

    ssscli set ecc pair <key-id> <device-key>

#) Generate the reference key

::

    ssscli refpem ecc pair <key-id> <output-ref-key>


Build the OpenSSL engine [Optional]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
    This step is optional in case you are using a prepared SD card
    image from NXP.

The OpenSSL engine uses the sss abstraction layer to access the crypto
services of the secure element, the implementation remains dependent on
the secure element attached. The following illustrates compiling the
OpenSSL engine for SE050 connected over I2C.

::

   cd simw-top
   python scripts/create_cmake_projects.py
   cd ../simw-top_build/imx_native_se050_t1oi2c
   cmake -DPTMW_OpenSSL:STRING=1_0 -DPTMW_HostCrypto:STRING=OPENSSL .
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

1)  Clone the Code ::

       cd /simw-top/demos/linux/aws/
       git clone https://github.com/aws/aws-iot-device-sdk-cpp.git

#) For the demo to build with openssl 3.0 and to use sssProvider apply the patch to repo aws-iot-device-sdk-cpp::

        cd /simw-top/demos/linux/aws/aws-iot-device-sdk-cpp
        patch -p1 < ../sssProvider_Updates.patch

    .. note:: If curl is not installed - run ``sudo apt-get install libcurl4-openssl-dev``

#) Modify the ``CMakeLists.txt`` file under ``samples/PubSub`` so it ensures ``OPENSSL_LOAD_CONF`` is defined (see excerpt below)::

        if (UNIX AND NOT APPLE)
            ADD_DEFINITIONS(-DOPENSSL_LOAD_CONF)
            # Prefer pthread if found
            set(THREADS_PREFER_PTHREAD_FLAG ON)
            set(CUSTOM_COMPILER_FLAGS "-fno-exceptions -Wall -Werror")
        elseif (APPLE)
            set(CUSTOM_COMPILER_FLAGS "-fno-exceptions -Wall -Werror")
        elseif (WIN32)
            set(CUSTOM_COMPILER_FLAGS "/W4")
        endif ()

#) Convert the `buildScript.sh` file from DOS (or Windows) format to Unix format and set the permissions::

        chmod 777 buildScript.sh

        dos2unix buildScript.sh


#) Now run 'buildScript.sh' script at simw-top/demos/linux/aws/ to build the mqtt application for aws call::

        ./buildScript.sh

#) Adapt the PubSub example specific configuration file so that it refers to the reference key and the device certificate.
    - Update the endpoint to match your AWS account
    - Ensure the AmazonRootCA1.pem certificate is in place (it is used by the iMX/rpi to validate the AWS IoT counterpart\
    - Update the configuration file (/simw-top/demos/linux/aws/aws-iot-device-sdk-cpp/build/bin/config/SampleConfig.json) with endpoint, device_certificate_relative_path, device_private_key_relative_path  (Ensure the value for "endpoint" matches your setup, you must replace "xxxxiukfoyyyy-ats.iot.eu-central-1.amazonaws.com")
    - Sample Json file ::

            {
              "endpoint": "xxxxiukfoyyyy-ats.iot.eu-central-1.amazonaws.com",
              "mqtt_port": 8883,
              "https_port": 443,
              "greengrass_discovery_port": 8443,
              "root_ca_relative_path": "certs/AmazonRootCA1.pem",
              "device_certificate_relative_path": "<UID>_device_certificate.crt",
              "device_private_key_relative_path": "<UID>_device_reference_key.pem",
              "tls_handshake_timeout_msecs": 60000,
              "tls_read_timeout_msecs": 2000,
              "tls_write_timeout_msecs": 2000,
              "aws_region": "",
              "aws_access_key_id": "",
              "aws_secret_access_key": "",
              "aws_session_token": "",
              "client_id": "CppSDKTesting",
              "thing_name": "CppSDKTesting",
              "is_clean_session": true,
              "mqtt_command_timeout_msecs": 20000,
              "keepalive_interval_secs": 600,
              "minimum_reconnect_interval_secs": 1,
              "maximum_reconnect_interval_secs": 128,
              "maximum_acks_to_wait_for": 32,
              "action_processing_rate_hz": 5,
              "maximum_outgoing_action_queue_length": 32,
              "discover_action_timeout_msecs": 300000
            }

#) For OpenSSL 1.x, search for `default_algorithms` in ``/simw-top/demos/linux/common/openssl_sss_se050.cnf`` file and set it as ::

        default_algorithms = RSA,RAND,ECDSA,ECDH    ----- For OpenSSL 1.0.0
        default_algorithms = RSA,RAND,EC            ----- For OpenSSL 1.1.1

#) For OpenSSL 3.x, search for `provider_sect` in ``/simw-top/demos/linux/common/openssl30_sss_se050.cnf`` file and set the nxp provider with high priority. ::

        nxp_prov = nxp_prov_sec
        default = default_sect

#) Based on OpenSSL version and applicable Secure Element, select the appropriate configuration file in
   ``<MW_SRC_DIR>/simw-top/demos/linux/common`` directory::

        openssl11_sss_se050.cnf   ----- OpenSSL 1.1.1 and SE050
        openssl_sss_se050.cnf     ----- OpenSSL 1.0.0 and SE050
        openssl30_sss_se050.cnf   ----- OpenSSL 3.x and SE050

#)  Set the openssl config path as call::

    $ export OPENSSL_CONF=/simw-top/demos/linux/common/<appropriate-cnf-file>


#)  Run the application::

        cd /simw-top/demos/linux/aws/aws-iot-device-sdk-cpp/build/bin
        ./pub-sub-sample


.. note::
    1) Export the OpenSSL conf path to the exact location of the file. The above example is for illustrative purpose
