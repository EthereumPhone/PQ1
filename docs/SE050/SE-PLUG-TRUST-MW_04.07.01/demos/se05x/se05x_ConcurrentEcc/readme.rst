..
    Copyright 2019,2020 NXP


.. highlight:: bat

.. _se05x_ConcurrentEcc:

=======================================================================
 ECC Concurrent Example
=======================================================================

This project demonstrates Elliptic Curve Cryptography sign and verify operations
using SSS APIs. On a multiprocess OS it can be run as multiple instances.
Before running an instance ensure the secure element is properly provisioned.
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


Running the Example in combination with the Access Manager
=======================================================================

For additional information on the AccessManager refer to :ref:`accessManager`.

.. _se05x_ConcurrentEcc-usage:

Usage
========================================================

The client process opens an authenticated user session (None/UserID/AESkey/ECkey) configured at build time.
The user session must be without platform SCP03. Platform SCP03 is handled by the Access Manager.

The client process connects to the AccessManager over JRCPv1.

Two concurrent client processes (establishing a user session) can connect to the AccessManager.

This program takes 4 command line arguments:

- authid: Authentication object id with which the session can be opened. It can be of type UserID/AESkey/ECkey (or authentication type 'None').
  In case the user session authentication is of type 'None' pass '0' as argument
- keyid: The id at which the functional Ec key pair will be stored, use a unique value per process.
- count (optional argument): Number of times the Ec Sign Verify operation will be repeated
- port: Connection port to AccessManager. e.g. 127.0.0.1:8040


An example invocation of the program (passing the Authentication Id of a UserID object) is::

  ./se05x_ConcurrentEcc -authid 0x7DA00001 -keyid 0xEF001234 -cnt 100 -port 127.0.0.1:8040



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

- Ec Sign / Verify  Auth=ID_1	Auth=ID_2

  - ./se05x_ConcurrentEcc -authid 0x7DA00001 -keyid 0xEF001234 -cnt 100 -port 127.0.0.1:8040
  - ./se05x_ConcurrentEcc -authid 0x7DA00011 -keyid 0xEF001244 -cnt 100 -port 127.0.0.1:8040

- Ec Sign / Verify  Auth=None	Auth=EC

  - ./se05x_ConcurrentEcc -authid 0 -keyid 0xEF001236 -cnt 100 -port 127.0.0.1:8040
  - ./se05x_ConcurrentEcc -authid 0x7DA00003 -keyid 0xEF001246 -cnt 100 -port 127.0.0.1:8040

- Ec Sign / Verify  Auth=AES_1	Auth=AES_2

  - ./se05x_ConcurrentEcc -authid 0x7DA00002 -keyid 0xEF001238 -cnt 100 -port 127.0.0.1:8040
  - ./se05x_ConcurrentEcc -authid 0x7DA00012 -keyid 0xEF001248 -cnt 100 -port 127.0.0.1:8040