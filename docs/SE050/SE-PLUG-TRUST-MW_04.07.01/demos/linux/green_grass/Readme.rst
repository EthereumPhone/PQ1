..
    Copyright 2019 NXP



.. _linux-demos-greengrass:

==================================================
Greengrass Demo for Linux
==================================================

AWS IoT Greengrass is a software provided by AWS to extend cloud capabilities
to locally connected devices. This allows local devices to publish/subscribe
to a topic even if there is no connectivity with AWS IoT console. A Greengrass
group consists of a Greengrass core, multiple Greengrass devices connected to
that core, and lambda functions and other services running on that core. In
this, the Greengrass core performs the functions of AWS IoT console.

The example is last tested with Plug and Trust Middleware version 4.0.0.

Also see `What Is AWS IoT Greengrass`_
for more details about AWS IoT Greengrass.

This demo is to demonstrate how to integrate SE050 with AWS IoT Greengrass
core and RaspberryPi as hardware security to store core specific credentials
for IoT client and MQTT server.

.. note:: Hardware security feature is available only for AWS IoT Greengrass
    Core v1.7 and later. We have used Greengrass core v1.10.0 for integration

Prerequisites
==================================================

- AWS Greengrass account (Also see supported regions for Greengrass)
- RaspberryPi 3 Model B+ or Model B. The architecture of your Pi must be
  armv7l or later
- Raspbian Buster operating system
- Python 2.7
- ssscli Tool. Refer to :ref:`cli-tool`


.. _prepare-greengrass:

Preparing the Greengrass group
==================================================

1)  Follow the modules 1 and 2 as described in `Environment Setup for Greengrass`_
    to set up Greengrass group and Greengrass core.

    .. note:: In Module 2, if you choose Easy Group Creation, AWS will create credentials
        for Greengrass IoT core and provision in the registry. Skip the next step
        if you choose Easy Group Creation. You could otherwise create your
        own credentials and provision AWS registry as explained in the next step.


#)  If you wish to use your own credentials, upload the your RootCA
    and verification certificate in ``Secure->CAs`` tab under IoT Core.

    - While creating Greengrass group, choose ``Advanced group creation``.
    - You can either assign IAM role or skip it for later.
    - Under Set up your security, choose ``Advanced setup`` and then
      choose ``Use my certificate``.
    - Select your active RootCA certificate and upload corresponding
      device certificate


#)  If you used your own credentials, download sample :file:`config.json` file
    for greengrass available at `AWS IoT Greengrass Core Configuration File`_

    After completing Module 2, store your device certificate under certs
    directory where you have extracted AWS IoT Greengrass core software (by
    default :file:`/greengrass` directory) and the downloaded
    :file:`config.json` under config directory.


#)  Do **NOT** run the daemon yet.


Provisioning SE050 and Building PKCS#11 library
==================================================

1)  Before running the Greengrass daemon, you would need to
    provision your SE050 and build PKCS#11 library.

#)  Complete :numref:`cli-doc-pre-steps` :ref:`cli-doc-pre-steps` for ssscli tool setup

#)  Run the following steps to provision your SE050 with Greengrass core keypair::

        ssscli connect se050 t1oi2c none
        ssscli se05x reset
        ssscli set ecc pair 0x20181001 <path-to-core-keypair>
        ssscli disconnect

    .. note:: Greengrass uses labels to address objects on tokens. To make the PKCS#11 library
        use a specific keyID, the label should start with ``sss:`` followed by 32-bit keyID in
        hexadecimal format (little endian). For example, the label for the command used above would be
        ``sss:01101820``.

#)  Build and install PKCS#11 library for Greengrass core.
    Refer to :numref:`pkcs11-standalone` :ref:`pkcs11-standalone`
    .. note:: Disable cmake option ``WithSharedLIB`` while building the PKCS#11 library


Updating Greengrass configuration
==================================================

If you have successfully completed :ref:`prepare-greengrass`, you would have
:file:`config.json` under config directory of AWS IoT Greengrass core software
(by default as :file:`/greengrass` directory). A sample of :file:`config.json`
is::

    {
      "coreThing" : {
        "caPath" : "root.ca.pem",
        "certPath" : "hash.cert.pem",
        "keyPath" : "hash.private.key",
        "thingArn" : "arn:partition:iot:region:account-id:thing/core-thing-name",
        "iotHost" : "host-prefix-ats.iot.region.amazonaws.com",
        "ggHost" : "greengrass-ats.iot.region.amazonaws.com",
        "keepAlive" : 600
      },
      "runtime" : {
        "cgroup" : {
          "useSystemd" : "yes"
        }
      },
      "managedRespawn" : false,
      "crypto" : {
        "principals" : {
          "SecretsManager" : {
            "privateKeyPath" : "file:///greengrass/certs/hash.private.key"
          },
          "IoTCertificate" : {
            "privateKeyPath" : "file:///greengrass/certs/hash.private.key",
            "certificatePath" : "file:///greengrass/certs/hash.cert.pem"
          }
        },
        "caPath" : "file:///greengrass/certs/root.ca.pem"
      }
    }

Remove the ``caPath``, ``certPath``, and ``keyPath`` values from the ``coreThing`` object.

Update the ``certificatePath`` property of ``IoTCertificate`` object to the path of device certificate.

.. note:: Currently AWS IoT Greengrass core does not support loading certificates from hardware.
        These have to be provided as a path to a file on filesystem.

Update the values of ``privateKeyPath`` under ``SecretsManager`` and ``IoTCertificate`` objects
with *pkcs11:object=sss:01101820;type=private*.

Add the following ``MQTTServerCertificate`` object under ``principals`` object::

    "MQTTServerCertificate": {
        "privateKeyPath": "pkcs11:object=sss:01101820;type=private"
    }

Add the following ``PKCS11`` object under ``crypto`` object::

    "PKCS11": {
        "P11Provider": "/path/to/libsss_pkcs11.so",
        "slotLabel": "SSS_PKCS11",
        "slotUserPin": "1234"
    }

Add commas where needed to create a valid JSON document.

In this file, we have used a shared key for ``MQTTServerCertificate``,
``IoTCertificate`` and ``SecretsManager`` components. In ``PKCS11`` object, we
specify which PKCS#11 module to load and which slot to use in that module. All
PKCS#11 objects specified for different components will refer to the same
token.


Running Greengrass Core
==================================================

Start the Greengrass daemon by running the following command in
:file:`ggc/core` directory under AWS IoT Greengrass core software directory::

    sudo ./greengrassd start

The Daemon should start successfully. If you face any problem while starting
the Greengrass daemon, refer to Troubleshooting section below. Also see
runtime logs under :file:`/greengrass/ggc/var/log/system` directory.


Connecting Devices to Greengrass Core
==================================================

Follow steps mentioned from Module 3 to test Greengrass connectivity:
`Lambda Functions on AWS IoT Greengrass`_

.. _ota-greengrass:

Over-The-Air (OTA) Updates
==================================================

To configure your device for OTA updates, you also need additional
PKCS#11 engine for OpenSSL. You can use OpenSC's ``libp11`` as
the engine. It is recommended that you build the engine manually.

Run the following commands::

    git clone https://github.com/OpenSC/libp11.git
    cd libp11
    sudo apt install pkgconf libssl-dev libtool
    autoreconf --verbose --install --force
    ./configure && make && sudo make install

This will build the PKCS#11 engine for OpenSSL. Next, you have to
specify the paths to the engine in your OpenSSL configuration file.
Instead of editing default OpenSSL configuration file, you can
maintain two separate files.

Place this line at the top, before any sections are defined::

    openssl_conf = openssl_init

At the end of the file add the following configuration::

    [openssl_init]
    engines=engine_section

    [engine_section]
    pkcs11 = pkcs11_section

    [pkcs11_section]
    engine_id = pkcs11
    dynamic_path = /usr/lib/arm-linux-gnueabihf/engines-1.1/pkcs11.so
    MODULE_PATH = /usr/local/lib/libsss_pkcs11.so
    init = 0

Here, ``dynamic_path`` is the path to PKCS#11 engine *.so* file.
This is installed in :file:`/usr/lib/arm-linux-gnueabihf/` directory.
This path will also be printed out while installing ``libp11`` library.

``MODULE_PATH`` is the path to the PKCS#11 library installed in
:numref:`pkcs11-standalone` :ref:`pkcs11-standalone`.

You can also test if OpenSSL is able to load the PKCS#11 library
by executing the following command::

    openssl engine dynamic -pre SO_PATH:/usr/lib/arm-linux-gnueabihf/engines-1.1/pkcs11.so -pre ID:pkcs11 -pre LOAD -pre MODULE_PATH:/usr/local/lib/libsss_pkcs11.so

You should be able to see the following output::

    (dynamic) Dynamic engine loading support
    [Success]: SO_PATH:/usr/lib/arm-linux-gnueabihf/engines-1.1/pkcs11.so
    [Success]: ID:pkcs11
    [Success]: LOAD
    [Success]: MODULE_PATH:/usr/local/lib/libsss_pkcs11.so
    Loaded: (pkcs11) pkcs11 engine

Follow the steps listed in `OTA Updates of AWS IoT Greengrass Core Software`_
to configure the backend for OTA updates.


Troubleshooting
==================================================

1)  Error message **greengrass deployment failed too many levels of symbolic links**

    Check if your linux supports OverlayFS. Also confirm that the Raspberry Pi
    image version matches the version specified in `Setting Up a Raspberry Pi`_.
    Currently, AWS IoT Greengrass Core has been tested on
    **2019-07-10-raspbian-buster** image. Greengrass core might not work with
    other images like Raspbian Stretch.

#)  Error message **connection reset by peer**.

    Add properties ``iotHttpPort`` and ``ggHttpPort`` to ``coreThing`` object as::

        "iotHttpPort" : 443,
        "ggHttpPort" : 443


If you face any other issue, refer to `Troubleshooting AWS IoT Greengrass`_.



.. _OTA Updates of AWS IoT Greengrass Core Software: https://docs.aws.amazon.com/greengrass/latest/developerguide/core-ota-update.html
.. _Setting Up a Raspberry Pi: https://docs.aws.amazon.com/greengrass/latest/developerguide/setup-filter.rpi.html
.. _Troubleshooting AWS IoT Greengrass: https://docs.aws.amazon.com/greengrass/latest/developerguide/gg-troubleshooting.html
.. _Lambda Functions on AWS IoT Greengrass: https://docs.aws.amazon.com/greengrass/latest/developerguide/module3-I.html
.. _AWS IoT Greengrass Core Configuration File: https://docs.aws.amazon.com/greengrass/latest/developerguide/gg-core.html#config-json
.. _Environment Setup for Greengrass: https://docs.aws.amazon.com/greengrass/latest/developerguide/module1.html
.. _What Is AWS IoT Greengrass: https://docs.aws.amazon.com/greengrass/latest/developerguide/what-is-gg.html
