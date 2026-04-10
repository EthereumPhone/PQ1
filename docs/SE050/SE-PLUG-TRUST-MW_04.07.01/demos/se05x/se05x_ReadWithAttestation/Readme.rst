..
    Copyright 2020, 2021 NXP


.. highlight::shell

.. _read-with-attestation:

=================================================
 Read object with Attestation
=================================================

This example demonstrates how to read an object with
attestation and parse the attested data to check
various object attributes.

In this example, we use pre-provisioned EC/RSA keypair as the
attestation key and a binary object which will be attested.
The pre-provisioned attestation key for Se05x `A & C EC keypair
is at 0xF0000012` and for Se05x `B RSA keypair is at 0xF0000010`

.. note:: The maximum size of a binary object that can be attested
  at a time is 500 bytes. The API available will only work on
  binary objects with size up to 500 bytes. To perform attestation
  on an object of greater size, we need to call corresponding
  ``Se05x`` API in a loop, verifying the obtained signature every time.

  A reference implementation is available at :ref:`read-large-bin-obj`

Building
=================================================

Build the project with the following configurations.

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se05x_ReadWithAttestation``


Running
=================================================

On running the example, you would be able to see object attributes
logged on the screen like::

  App   :INFO :Key att data (Len=28)
        00 F5 EF FA    0B 01 00 00    00 00 00 00    00 00 08 00
        00 00 00 00    34 00 00 01    00 00 00 00
  App   :INFO :Object Id 0xF5EFFA
  App   :INFO :Object Type  0xB
  App   :INFO :Type:
  App   :INFO :   BINARY_FILE
  App   :INFO :Object Auth Attribute  0x1
  App   :INFO :Auth:
  App   :INFO :   Not Set
  App   :INFO :Auth Object:
  App   :INFO :   No authentication required
  App   :INFO :Policies:
  App   :INFO :   POLICY_OBJ_ALLOW_READ
  App   :INFO :   POLICY_OBJ_ALLOW_WRITE
  App   :INFO :   POLICY_OBJ_ALLOW_DELETE
  App   :INFO :tagLen for AEAD:0x00
  App   :INFO :RFU bytes:0x00
  App   :INFO :Owner:0x0000
  App   :INFO :Object origin : 0x1
  App   :INFO :Origin:
  App   :INFO :   EXTERNAL
  App   :INFO :Object Version : 0x0000
  App   :INFO :se05x_ReadWithAttestation Example Success !!!
  App   :INFO :ex_sss Finished

You can see the various attributes associated with the object such
as object type, authentication mechanism, origin and policies.

An example of how to perform read with attestation is given below

.. literalinclude:: se05x_ReadWithAttestation.c
   :language: c
   :start-after: /* doc:start:read-w-attestation */
   :end-before: /* doc:end:read-w-attestation */
   :dedent: 4

The data received in ``att_data`` variable can be parsed to
read the object attributes.


.. _read-large-bin-obj:

Reading large binary objects with attestation
=================================================

Following is an example code on how to read a large binary file
with attestation.

.. note:: This is required only when reading binary objects of size larger
  than 500 bytes. For any other case, you should use SSS API as above

.. literalinclude:: se05x_ReadWithAttestation.c
   :language: c
   :start-after: /* doc:start:read-large-binary-obj-w-attestation */
   :end-before: /* doc:end:read-large-binary-obj-w-attestation */
