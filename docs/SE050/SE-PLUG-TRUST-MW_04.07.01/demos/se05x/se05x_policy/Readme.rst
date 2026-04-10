..
    Copyright 2019,2020 NXP


.. highlight:: shell

.. _se05x-policy-demo:

==========================================================
 Using policies for secure objects
==========================================================

This demo is to demonstrate the use of policies for secure objects. Object policies such as ``can_Sign`` or ``can_Encrypt`` can be used to restrict operations other than the given policies. Objects inside the secure element are linked to a particular authentication object, based on communication authentication type selected. Objects inside the secure element linked with one authentication object cannot be used when session is open with another authentication type.

Authentication Object ID to be linked with secure object can be selected as

.. literalinclude:: ex_policy.c
    :language: c
    :start-after: /* doc:start:auth-obj */
    :end-before: /* doc:end:auth-obj */

.. note ::
    Ensure that the authentication object ID in policy set matches the authentication type.

Sign Policy
=======================================================================

Create a policy set using the authentication object ID

.. literalinclude:: ex_policy.c
   :language: c
   :dedent: 4
   :start-after: /* doc:start:allow-policy-sign */
   :end-before: /* doc:end:allow-policy-sign */

Using PCR Object
=======================================================================

PCR is a special secure object which stores 32-byte data. A PCR object can be used to ensure that secure objects inside the SE cannot be used if the PCR object value is altered.

We can assign a PCR policy to a secure object as given in the following sample code

.. literalinclude:: ../../../tst/sss/policyobject/test_policyobject.c
   :language: c
   :start-after: /* doc:start:pcr-policy */
   :end-before: /* doc:end:pcr-policy */

.. note ::
    Ensure that the ``pcrObjID`` in PCR policy is the same object ID at which the PCR is stored.



Console output
=======================================================================

If everything is successful, the output will be similar to:

.. literalinclude:: out_ex_policy.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!
