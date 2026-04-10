..
    Copyright 2020 NXP


.. highlight::shell

.. _se05x-time-stamp:

=================================================
 SE05X Timestamp
=================================================

The timestamp is a 12-byte value. The most significant
4 bytes are persistent and the least significant 8
bytes are transient. The persistent value is
incremented at every session open and the transient
8 bytes are incremented every 100ms and reset at
every session open.

So every time the timestamp is read, the newer value
will always be greater than the previous value.

This example demonstrates that the timestamp value
is incremented internally. Timestamp is used by the
applet during attestation. We initially read the
timestamp value and then perform attestation
operation. We compare the initial timestamp with
the timestamp received during attestation. The newer
value must be greater than the older value.


Building
=================================================

Build the project with the following configuration.

- ``Applet=SE05X_C``
- ``Project = se05x_TimeStamp``

Running
=================================================

On successful execution, you would be able to see
the timestamp printed out::

    App   :INFO :timestamp.ts (Len=12)
          00 00 00 08    00 00 00 00    00 1F BD 00
    App   :INFO :new_timestamp.ts (Len=12)
          00 00 00 08    00 00 00 00    00 20 B7 00
    App   :INFO :ex_sss Finished

As you can see in the above logs, the timestamp value
received during attestation operation is larger than
the previous value.
