..
    Copyright 2019 NXP



.. _opc-ua-open62541:

Introduction on Open62541 (OPC UA stack)
========================================

Open62541 is an open source C implementation of OPC UA stack. Open62541 supports binary encoding of messages with the following security profiles and modes.

Security Profiles

1) None
#) Basic256
#) Basic256SHA256

Security Modes

1) None
#) Sign
#) Sign and Encrypt


Integrating SE050 in Open62541
-------------------------------------------------------------

Open62541 stack uses mbedtls for all crypto operations in security profile plugins by default.
For integrating with SE050, in the security profile plugins of Open62541 (``simw-top\ext\open62541\plugins\securityPolicies``), 
specific mbedtls functions used for private key operations, are replaced by calls to SSS APIs.
Only the ``Basic256SHA256`` security profile (uses RSA2048 keys) has been updated to support SE050 integration:
private key operations - RSA Sign and RSA Decrypt - are now performed using SE050. 
The modified security profile plugin files are placed at ``simw-top\sss\plugin\open62541``.

For the server application, a reference key file is used to pass the key id information to the security profile plugins layer.



.. note::
    Please refer to the demonstrator built on top of the Open62541 OPC UA stack for further details (:ref:`opc-ua-open62541-demo`)

