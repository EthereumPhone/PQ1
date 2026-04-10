..
    Copyright 2020 NXP




.. _se05x-export-transient-objects:

=======================================================================
 SE05X Export Transient objects
=======================================================================

This example does following steps:

- Generate a Transient ECC Key

- Export that to a blob

- Sign some dummy data with that key

- Store the signature in local file for future use.

After running this example, you can run :numref:`se05x-import-transient-objects` :ref:`se05x-import-transient-objects`


.. note::

    This example needs File system access and hence it is not applicable for
    embedded platforms.

    The exported files are current working directory.


Visual Studio - Debug settings
=======================================================================

Kindly set debug ``Working Directory`` to ``$(TargetDir)`` in project's debug settings.
This ensures that the examples :ref:`se05x-export-transient-objects` and
:ref:`se05x-import-transient-objects` work seamlessly.

Console output
=======================================================================

If everything is successful, the output will be similar to:

.. literalinclude:: out_se05x_ex_export_se_to_host.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!
