..
    Copyright 2019,2020 NXP


.. _cli-tool-provisioning:

======================================================================
 CLI Provisioning
======================================================================

Generating keys and certificates
======================================================================

For generating keys and certificates, following scripts generates using openssl.

- ``GenerateAWSCredentials.py``
- ``GenerateAZURECredentials.py``

The generated keys and certificates shall be available in
``pycli/Provisioning/azure``
and ``pycli/Provisioning/aws`` directories.

Provisioning for the demo
======================================================================

Generated keys and certificates are used to provision the secure element using ``ResetAndUpdate_AZURE.py`` and ``ResetAndUpdate_AWS.py`` scripts for azure and aws cloud demo respectively.

.. note:: Default auth type in provisoning script is always ``None``

Steps to provision your device for demo on Windows
======================================================================

Provisioning on windows can be done in two ways.

- Using precompiled binaries
- Using python scripts

Using precompiled binaries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Precompiled binaries available in ``binaries/PCWindows/ssscli`` directory.
Can generate certificates and provision the secure element by simply running these binaries.

1) For AWS, create certificate and provision, call::

    Provision_AWS.exe <COM_PORT>

#) For AZURE, create certificate and provision, call::

    Provision_AZURE.exe <COM_PORT>

The generated keys and certificates shall be available in ``binaries/PCWindows/ssscli/aws``
and ``binaries/PCWindows/ssscli/azure`` directories.

Using Python scripts
^^^^^^^^^^^^^^^^^^^^^^^^^

1) Complete :numref:`cli-doc-pre-steps` :ref:`cli-doc-pre-steps`

#)  from ``pycli`` directory, run::

        call venv\Scripts\activate.bat
        cd Provisioning

#)  Check the vcom port number

#)  For AWS, create certificate and provision, call::

        python GenerateAWSCredentials.py <COM_PORT>
        python verification_certificate.py <interCA_Certificate> <interCA_Keypair> <verification_code>
        python ResetAndUpdate_AWS.py <COM_PORT>

#)  For AZURE, create certificate and provision, call::

        python GenerateAZURECredentials.py <COM_PORT>
        python verification_certificate.py <interCA_Certificate> <interCA_Keypair> <verification_code>
        python ResetAndUpdate_AZURE.py <COM_PORT>

#)  Flash the demo on to the board


Steps to provision your device for demo on iMX or Raspberry Pi
======================================================================

1) Complete :numref:`cli-doc-pre-steps` :ref:`cli-doc-pre-steps`

#)  from ``pycli`` directory, run::

        cd Provisioning

#)  For AWS, create certificate and provision, call::

        python3 GenerateAWSCredentials.py
        python3 verification_certificate.py <interCA_Certificate> <interCA_Keypair> <verification_code>
        python3 ResetAndUpdate_AWS.py

#)  For AZURE, create certificate and provision, call::

        python3 GenerateAZURECredentials.py
        python3 verification_certificate.py <interCA_Certificate> <interCA_Keypair> <verification_code>
        python3 ResetAndUpdate_AZURE.py

#)  Flash the demo on to the board
