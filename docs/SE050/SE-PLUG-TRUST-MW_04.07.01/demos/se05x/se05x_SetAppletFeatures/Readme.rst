..
    Copyright 2020 NXP



.. highlight::shell

.. _set-applet-features:

==========================================================
 Configuring Applet Features
==========================================================

This tool is used to configure the applet for different variants, i.e. Variant A, Variant B and Variant C.
Note that this tool only enables or disables the features according to the configured variant, it **does not
alter the variant itself**.
The tool should be compiled with ECKey encryption, and optionally PlatfSCP03 encryption also.
You would need to provide a command line parameter for ECKey key to be used, and an environment variable for your
own Platform SCP03 keys, if required.


.. _configure-eckey-file:

Configuring ECKey key for command line
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This example takes as a command-line input, the filename in which ECDSA key is stored.
The key should be stored in *.der* (binary) format only. If the available key is in *.pem* format,
it can be converted into binary format using OpenSSL command-line utility. Refer to `OpenSSL Commands
<https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations#EC_Private_Key_File_Formats/>`_
for more information on how to convert *.pem* formatted file to *.der* formatted file.


.. _configure-env-for-platfscp:

Configuring Environment for PlatfSCP03 Keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**If you do not wish to use Platform SCP03 encryption, skip to the next step**.

To use your own platform SCP03 keys, refer to :numref:`platfscp-file` :ref:`platfscp-file`
on details on setting up your environment.


Using with PC as host
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1)  Flash the VCOM binary present in :file:`binaries` directory on to the target board.
#)  Note the VCOM *COMPORT* from device manager.
#)  Build the project ``se05x_setAppletFearures``. Configure the tool with ``SE050_A``, ``SE050_B`` or ``SE050_C``,
    to enable the applet specific features.
#)  Run the executable for desired variant as::

        cd tools
        set EX_SSS_BOOT_SCP03_PATH_ENV=\path\to\platfscp03\keys
        se05x_setAppletFearures.exe -file <filename> <COMPORT>

    Where ``EX_SSS_BOOT_SCP03_PATH_ENV`` is set to the path of file containing Platform SCP03 keys as described in :ref:`configure-env-for-platfscp`.

    *COMPORT* is the port obtained from step 2.

    *filename* is the path to file containing ECDSA keypair provisioned at **RESERVED_ID_FEATURE** in binary format as described in :ref:`configure-eckey-file`


Using with iMX-6 as host
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1)  Build the project ``se05x_setAppletFearures``. Configure the tool with ``SE050_A``, ``SE050_B`` or ``SE050_C``,
    to enable the applet specific features.
#)  Run the executable for desired variant as::

        cd tools
        export EX_SSS_BOOT_SCP03_PATH_ENV=\path\to\platfscp03\keys
        ./se05x_setAppletFearures -file <filename>

    Where ``EX_SSS_BOOT_SCP03_PATH_ENV`` is set to the path of file containing Platform SCP03 keys as described in :ref:`configure-env-for-platfscp`.

    *filename* is the path to file containing ECDSA keypair provisioned at **RESERVED_ID_FEATURE** in binary format as described in :ref:`configure-eckey-file`
