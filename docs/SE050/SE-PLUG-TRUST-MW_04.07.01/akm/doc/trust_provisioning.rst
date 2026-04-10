..
    Copyright 2019,2020 NXP

.. highlight::shell

==========================================================
Trust Provisioned keys
==========================================================

The trust provisioned SE contains ECC-256 and RSA-2048 keys. These keys are provisioned at specific keyIDs. In order to use these keys, we need to pass a magic number along with the corresponding keyID of the key to the keymaster ``import_key`` API. Only when the ``import_key`` parses the key and finds the magic as a part of the key, it returns the key blob of the trust provisioned key.

Using TP RSA key
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To use trust provisioned RSA key, pass the key in the following format::

	modulus:
	    a5:a6:b5:b6:a5:a6:b5:b6:xx:xx:xx:xx:xx:xx:xx:
	    xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:....
	publicExponent: 65537 (0x10001)
	privateExponent:
	    A5:23:00:67:02:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:
	    xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:....
	prime1:
	    xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:....
	prime2:
	    xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:....
	exponent1:
	    xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:....
	exponent2:
	    xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:....
	coefficient:
	    xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:....


Note here that the key modulus starts with the magic ``A5:A6:B5:B6:A5:A6:B5:B6`` and the privateExponent starts with ``A5`` followed by the 32-bit keyID (here, 0x23006702) of the trust provisioned RSA keypair. When an RSA key with modulus starting with the magic and privateExponent starting with ``A5`` is passed to ``import_key``, the RSA key stored at the corresponding keyID (0x23006702) is returned. An example of java code to import RSA keypair in this format is:

.. literalinclude:: trust_provisioning_example.java
   :language: java
   :start-after: /* doc:start:RSA-TP-example */
   :end-before: /* doc:end:RSA-TP-example */


Using TP EC key
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To use trust provisioned EC key, pass the key in the following format::

	priv:
	    a5:a6:b5:b6:a5:a6:b5:b6:c3:02:00:01:xx:xx:xx:
	    xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:....
	pub:
	    xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:....


Note here that the private component of the EC keypair contains the magic ``A5:A6:B5:B6:A5:A6:B5:B6`` followed by the 32-bit keyID (here, 0xC3020001) of the trust provisioned EC keypair. When an EC key with private component starting with the magic is passed to ``import_key``, the EC keypair stored at the corresponding keyID (0xC3020001) is returned. An example of java code to import EC keypair in this format is:

.. literalinclude:: trust_provisioning_example.java
   :language: java
   :start-after: /* doc:start:EC-TP-example */
   :end-before: /* doc:end:EC-TP-example */
