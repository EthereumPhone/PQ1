..
    Copyright 2020 NXP





.. highlight:: bat

.. _cli-data-format:


CLI Data formats
====================================================


DER
^^^^^^^^^^^^^^^^^^^^^^^^^
DER or  `Distinguished Encoding Rules <https://en.wikipedia.org/wiki/X.690#DER_encoding>`_ files are digital certificates in binary format, instead of the ASCII PEM format.
DER files may end with .der or .cer, so to differentiate between DER.cer and PEM.cer files, you may need to use a text editor to read the file.
A DER file should not have any BEGIN/END statements and will show garbled binary content.

The file as seen in *hexl-mode* of emacs would look as below::

    00000000: 3081 8702 0100 3013 0607 2a86 48ce 3d02  0.....0...*.H.=.
    00000010: 0106 082a 8648 ce3d 0301 0704 6d30 6b02  ...*.H.=....m0k.
    00000020: 0101 0420 084f 2d70 eee4 09b9 5546 462e  ... .O-p....UFF.
    00000030: 2cca 12e0 a046 90a3 3bea 8252 eeb5 4ff5  ,....F..;..R..O.
    00000040: a4e9 b2d6 a144 0342 0004 633e 938a 67a7  .....D.B..c>..g.
    00000050: a9e6 f35f c369 3b51 3c88 6a0d c260 16f3  ..._.i;Q<.j..`..
    00000060: 5e8c 2c0b 491b 2392 7af0 371d 28b1 1bfb  ^.,.I.#.z.7.(...
    00000070: e8f4 2e9c 5b0f 2897 c516 ec3e 7d62 97e4  ....[.(....>}b..
    00000080: c06f 936d ba9d ac8a bcd8                 .o.m......
    -UU=:----F1  ecc_NIST_P256_prv_pkcs8.der   All L1     (Hexl) ---------------


PEM
^^^^^^^^^^^^^^^^^^^^^^^^^
PEM or `Privacy Enhanced Mail <https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail>`_ is a Base64 encoded DER certificate.
PEM certificates are frequently used for web servers as they can easily be translated into readable data using a simple text editor.
PEM file extension may contain .pem or .cer, so to differentiate when a PEM encoded file is opened in a text editor, it contains very distinct headers and footers.

Example::

    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCE8tcO7kCblVRkYu
    LMoS4KBGkKM76oJS7rVP9aTpstahRANCAARjPpOKZ6ep5vNfw2k7UTyIag3CYBbz
    XowsC0kbI5J68DcdKLEb++j0LpxbDyiXxRbsPn1il+TAb5Ntup2sirzY
    -----END PRIVATE KEY-----

HEX
^^^^^^^^^^^^^^^^^^^^^^^^^
Hex or `Hexadecimal <https://en.wikipedia.org/wiki/Hexadecimal>`_ (base 16) is a positional system that represents numbers using a base of 16.

Example::

    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02
    01010420084f2d70eee409b95546462e2cca12e0a04690a33bea8252eeb54ff5
    a4e9b2d6a14403420004633e938a67a7a9e6f35fc3693b513c886a0dc26016f3
    5e8c2c0b491b23927af0371d28b11bfbe8f42e9c5b0f2897c516ec3e7d6297e4
    c06f936dba9dac8abcd8


REFERENCE KEY
^^^^^^^^^^^^^^^^^^^^^^^^^
- Refer to :numref:`ec-reference-key-format` :ref:`ec-reference-key-format` for EC reference key format.
- Refer to :numref:`rsa-reference-key-format` :ref:`rsa-reference-key-format` for RSA reference key format.
