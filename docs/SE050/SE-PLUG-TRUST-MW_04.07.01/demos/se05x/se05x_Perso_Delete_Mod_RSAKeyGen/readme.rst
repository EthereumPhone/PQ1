..
    Copyright 2019,2020 NXP



.. highlight:: bat

.. _ex-se05x_Perso_Delete_Mod_RSAKeyGen:

=======================================================================
 SE05X Personalization Remove RSA Key Generation Module
=======================================================================

This project permanently deletes rsa key generation module from secure element. Running
this example will restrict the generation of rsa keys inside the secure element.


Building the Demo
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- Project: ``se05x_Perso_Delete_Mod_RSAKeyGen``


Running the Example
=======================================================================

If you have built a binary, flash the binary on to the board and reset
the board.

If you have built an *exe* to be run from Windows using VCOM, run as::

    se05x_Perso_Delete_Mod_RSAKeyGen.exe <PORT NAME>

Where **<PORT NAME>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as::

    ./se05x_Perso_Delete_Mod_RSAKeyGen


Console output
=======================================================================

If everything is successful, the output will be similar to:

.. literalinclude:: out_se05x_Perso_Delete_Mod_RSAKeyGen.rst.txt
   :start-after: smCom :INFO :Opening connection to JRCP server on 127.0.0.1:8050