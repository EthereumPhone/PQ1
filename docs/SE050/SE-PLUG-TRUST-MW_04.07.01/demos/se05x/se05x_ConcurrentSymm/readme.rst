..
    Copyright 2019,2020 NXP


.. highlight:: bat

.. _se05x_ConcurrentSymm:

=======================================================================
 Symmetric Multi Step Concurrent Example
=======================================================================

This project demonstrates Symmetric Multi step operations.
using SSS APIs. On a multiprocess OS it can be run as multiple instances.
Before running an instance ensure the secure element.is properly provisioned.
The block cipher mode to apply (ECB or CBC) can be chosen by the user.
The utility :ref:`delete-and-test-provision` can be used to provision the authentication
objects used by this example. Invoke ``se05x_Delete_and_test_provision`` once during
the preparation of the demo.
The authentication objects are required for user sessions of
type UserID/AESKey/ECKey.

Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- When used in combination with Access Manager compile for SMCOM = JRCPv1

Restrictions
=======================================================================

- Each user session needs to have a different authentication object
- The same block cipher mode cannot be used for two concurrent client processes.
  If one process uses ECB the other must use CBC.
  This is a restriction from the SSS layer.

Running the Example in combination with the Access Manager
=======================================================================

For additional information on the AccessManager refer to :ref:`accessManager`.

.. _se05x_ConcurrentSymm-usage:

Usage
========================================================

The client process opens an authenticated user session (None/UserID/AESkey/ECkey) configured at build time.
The user session must be without platform SCP03. Platform SCP03 is handled by the Access Manager.

The client process connects to the AccessManager over JRCPv1.

Two concurrent client processes (establishing a user session) can connect to the AccessManager.

This program takes 5 command line arguments:

- authid: Authentication object id with which the session can be opened. It can be of type UserID/AESkey/ECkey (or authentication type 'None').
  In case the user session authentication is of type 'None' pass '0' as argument
- keyid: The id at which the symmetric key has to be stored, use a unique value per process.
- algo: Block cipher mode, use 1 for ECB and 2. for CBC
- count (optional argument): Number of times the crypto operation will be repeated.
- port: Connection port to AccessManager. e.g. 127.0.0.1:8040


An example invocation of the program is::

  ./se05x_ConcurrentSymm -authid 0x7DA00001 -keyid 0xEF002234 -algo 1 -cnt 100 -port 127.0.0.1:8040



Concurrent Usage
==========================================================

The following command invocations illustrate how two processes connect to the AccessManger using different
Authentication Id's and (functional) key Id's.

The following Authentication Id's are provisioned in SE using the "delete & provision" utility

======  ========== ==========
AuthId  1          2
======  ========== ==========
UserID  0x7DA00001 0x7DA00011
------  ---------- ----------
AESkey  0x7DA00002 0x7DA00012
------  ---------- ----------
ECKey   0x7DA00003 0x7DA00013
======  ========== ==========


KeyId can be anything above 0xEF000000, choose a different value for each client process.

- ECB Enc/Dec  CBC Enc/Dec  Auth=ID Auth=AES

  - ./se05x_ConcurrentSymm -authid 0x7DA00001 -keyid 0xEF002234 -algo 1 -cnt 100 -port 127.0.0.1:8040
  - ./se05x_ConcurrentSymm -authid 0x7DA00002 -keyid 0xEF002235 -algo 2 -cnt 100 -port 127.0.0.1:8040

- ECB Enc/Dec  CBC Enc/Dec  Auth=ID_1 Auth=ID_2

  - ./se05x_ConcurrentSymm -authid 0x7DA00001 -keyid 0xEF002236 -algo 1 -cnt 100 -port 127.0.0.1:8040
  - ./se05x_ConcurrentSymm -authid 0x7DA00011 -keyid 0xEF002237 -algo 2 -cnt 100 -port 127.0.0.1:8040

- ECB Enc/Dec; CBC Enc/Dec  Auth=EC Auth=AES

  - ./se05x_ConcurrentSymm -authid 0x7DA00003 -keyid 0xEF002238 -algo 1 -cnt 100 -port 127.0.0.1:8040
  - ./se05x_ConcurrentSymm -authid 0x7DA00002 -keyid 0xEF002239 -algo 2 -cnt 100 -port 127.0.0.1:8040