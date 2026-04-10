..
    Copyright 2020 NXP


.. highlight:: bat

.. _delete-and-test-provision:

=======================================================================
 Delete and Test Provision
=======================================================================

'Delete and Test Provision' is a utility that deletes a subset of the crypto objects stored on the secure element.
Next it provisions different types of key objects (as documented in the table below).
These key objects enable various use cases with the secure element.
As an example: the authentication objects for session based authentication (UserID/AESkey/ECKey)
are provisioned through this utility.

To enable concurrent (up to the maximum of two) authenticated user sessions, two authentication objects of
each type (UserID/AESkey/ECKey) are provisioned.

.. note:: Authentication objects - of the same object type - are provisioned on Ids with an offset of +0x10.

.. warning:: This utility provisions the same value for both authentication object type instances. 
    In a product deployment different
    values must be used, do not re-use any of the values provisioned by this test utility in a
    product deployment.


Object IDs provisioned
=======================================================================

=========== ============= ==========================================================================
Object ID    Object Type                 Usage
=========== ============= ==========================================================================
0x7DA00001  User ID        Allows the user to Open User ID Auth Session to SE.
----------- ------------- --------------------------------------------------------------------------
0x7DA00002  Symm Key       Allows the user to Open AES Key Auth Session to SE.
----------- ------------- --------------------------------------------------------------------------
0x7DA00003  EC Key         Allows the user to Open EC Key Auth Session to SE.
----------- ------------- --------------------------------------------------------------------------
0x7DA00011  User ID        Allows the user to Open additional User ID Auth Session to SE.
----------- ------------- --------------------------------------------------------------------------
0x7DA00012  Symm Key       Allows the user to Open additional AES Key Auth Session to SE.
----------- ------------- --------------------------------------------------------------------------
0x7DA00013  EC Key         Allows the user to Open additional EC Key Auth Session to SE.
----------- ------------- --------------------------------------------------------------------------
0x7FFF0200  Symm Key       Allows the user to switch transport LockState of the SE.
----------- ------------- --------------------------------------------------------------------------
0x7FFF0201  EC Key         Provisions ECKA pair at SE for EC key Session Authentication.
----------- ------------- --------------------------------------------------------------------------
0x7FFF0202  EC Key         Provisions ECKA pair at SE for EC key Session Authentication.
----------- ------------- --------------------------------------------------------------------------
0x7FFF0203  EC Key         Provisions ECKA pair at SE for EC key Session Authentication.
----------- ------------- --------------------------------------------------------------------------
0x7FFF0204  EC Key         Used for applet personalization.
----------- ------------- --------------------------------------------------------------------------
0x7FFF0205  User ID        Allows the user to delete all objects. Except those provisioned by NXP.
----------- ------------- --------------------------------------------------------------------------
0x7FFF0206  Binary         Holds the device unique ID.
----------- ------------- --------------------------------------------------------------------------
0x7FFF0207  User ID        Allows the user to make platform SCP mandatory or not.
=========== ============= ==========================================================================

.. warning:: Some of the object Ids here are provisioned with same values. This is for
    test, example and demo purpose only.


Authentication Keys
=======================================================================

.. warning:: These values are just for demonstration. The user **MUST**
    modify these values in the secure element and the application for real world
    use cases.

**User ID**

.. literalinclude:: ../../../sss/ex/inc/ex_sss_auth.h
    :language: c
    :start-after: /* doc:start:auth-key-user-id */
    :end-before: /* doc:end:auth-key-user-id */

**Applet SCP**

.. literalinclude:: ../../../sss/ex/inc/ex_sss_auth.h
    :language: c
    :start-after: /* doc:start:auth-key-applet-scp */
    :end-before: /* doc:end:auth-key-applet-scp */

**EC Key**

.. literalinclude:: ../../../sss/ex/inc/ex_sss_auth.h
    :language: c
    :start-after: /* doc:start:auth-key-fast-scp-ecdsa */
    :end-before: /* doc:end:auth-key-fast-scp-ecdsa */


Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- ``SE05X_Auth=None``
- Project: ``se05x_Delete_and_test_provision``