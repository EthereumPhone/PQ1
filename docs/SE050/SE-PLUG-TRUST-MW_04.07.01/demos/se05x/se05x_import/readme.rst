..
    Copyright 2020 NXP




.. _se05x-import-transient-objects:

=======================================================================
 SE05X Import Transient objects
=======================================================================

Before running this example, please run :numref:`se05x-export-transient-objects` :ref:`se05x-export-transient-objects`

This example does following steps:

- Re-Generates a Transient ECC Key at the same location as created by :ref:`se05x-export-transient-objects`

- Tries to verify previously signed data. (This must fail, because key is over-written)

- Imports previously exported key inside the SE.

- Tries to verify previously signed data. (This must be successful, because it is the same key)

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

.. literalinclude:: out_se05x_ex_import_host_to_se.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!
