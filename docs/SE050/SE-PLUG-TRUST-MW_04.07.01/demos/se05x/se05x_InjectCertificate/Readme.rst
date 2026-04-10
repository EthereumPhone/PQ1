..
    Copyright 2020 NXP


.. highlight:: shell

.. _se-inject-certificate:

==========================================================
 Inject Certificate into SE
==========================================================

This tool is to demonstrate how to inject certificates into
the SE. The keyIDs where certificates are injected are defined
in :file:`se05x_InjectCertificate.h`:

.. literalinclude:: se05x_InjectCertificate.h
	:language: c
	:start-after: /* doc:start:keyIDs */
	:end-before: /* doc:end:keyIDs */

.. note:: Certificates to be injected are also defined in
	:file:`se05x_InjectCertificate.h` file. These can be
	changed as required.

Building the example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use the following CMake configurations to compile the example

- Project: ``se05x_InjectCertificate``


How to use
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Run the tool as::

    se05x_InjectCertificate <port>

- For systems connecting with T=1 over I2C, the port parameter can be skipped.

