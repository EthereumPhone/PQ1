..
    Copyright 2019 NXP

.. highlight:: shell

.. _puf-rotate-scp03:

==========================================================
 Key Rotation using PUF
==========================================================

This example demonstrates how to use PUF to manage PlatformSCP 
keys and rotate the keys using PUF. For details on PUF and usage 
with LPC55S, refer to :ref:`puf-scp03`. 

Before running this example, be sure that correct PlatformSCP 
keys are already provisioned in PUF. For details on how to provision 
keys in PUF, refer :numref:`puf-inject-scp03` :ref:`puf-inject-scp03`.

In this example, we first open a session with default PlatformSCP 
keys and perform an RNG operation, then we rotate the keys in SE 
and PUF, reopen session with new keys and perform RNG operation again 
to demonstrate that the keys have been rotated. 
Finally, we revert to the old keys.

.. warning:: We are using randomized keys for key rotation. 
   Make sure that the demo runs completely without any power interruptions.
   In case of failure, SE050 could be using the new keys and re-running the demo 
   will fail.

Pre-requisites
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- :numref:`platform-lpc55s69` :ref:`platform-lpc55s69`
- :numref:`logging-on-console` :ref:`logging-on-console`
- Build Plug & Trust middleware stack. (Refer :ref:`building`)
- PUF must be enrolled first and original SCP03 keys must be 
  provisioned and ActivationCode and KeyCodes must be updated in 
  :file:`ex_scp03_puf.h`. SBL and secure app should be 
  compiled with the correct AC and KCs.
  See :numref:`puf-inject-scp03` :ref:`puf-inject-scp03` on how to 
  provision PUF with PlatformSCP03 keys.

How to build
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Make sure that you compile the secure example first. 
The non-secure example links to the secure example.

Compile the secure example with the following CMake options:

- ``Host=lpcxpresso55s_s``

- ``SCP=SCP03_SSS``

- ``SE05X_Auth=PlatfSCP03``

- Project:``puf_rotate_scp03_s``


Compile the non-secure example with the following CMake options:

- ``Host=lpcxpresso55s_ns``

- ``SCP=SCP03_SSS``

- ``SE05X_Auth=PlatfSCP03``

- Project:``puf_rotate_scp03_ns``


How to run
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Follow the steps given below to flash secure and non-secure 
binaries on LPC55S board.


1) Import secure and non-secure projects into MCUXpresso IDE
    
   .. image:: /img/import_projects.jpeg
          :align: center
          :width: 270px

#) Update :file:`Makefile` target for both projects

   .. image:: /img/update_makefile.jpeg

#) Build the projects.

   .. image:: /img/build_project.jpeg
          :align: center
          :width: 270px

   .. note:: Be sure that you build the secure project first 
    and then the non-secure project.

#) Start ``GUI Flash Tool``
   
   .. note:: You can program the binary by debugging the project also. 
      If you want to debug, go to step 6.
   
   .. image:: /img/gui_flash_tool.jpeg

#) On successful operation you should see the following message

   .. image:: /img/flashed.jpeg
          :align: center
          :width: 270px


#) To start debugging into the project, simply select the project that 
   you want to debug and press the ``Debug`` button in QuickStart Menu.

   .. image:: /img/start_debug.jpeg
          :align: center
          :width: 270px

#) Make sure that in the ``Debug Configuration`` under ``GUI Flash Tool`` tab, 
   you have selected **Program**.

   .. image:: /img/program_only.jpeg
          :align: center
          :width: 270px


Perform the last two steps for both the projects (order does not matter). 
While debugging, flash the program that you want to debug second.

When you have flashed both the projects, reset the board. On 
successful execution you would be able to see the following log 
in terminal

.. literalinclude:: output_log.rst.txt

