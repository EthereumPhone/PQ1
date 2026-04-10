..
    Copyright 2019,2020 NXP


=================================================
 SEMS Lite Overview (Only for SE051)
=================================================

SEMSLite enables the deployment and update of applets on SE in the field.
When the applets are being upgraded, the data of previous/new applet
remains inside the secure element only.
Thus it securely preserves the device applet data.

Note: SEMS Lite is only supported for SE051.

.. image:: Overview.jpeg
      :align: center
      :width: 270px

Update Manager (from customer)
======================================================================

The role of update manager is as under:

* Securely downloading *update package* from its back-end
* Defining right time for update (depending on context: battery status, IoT
  device usage profile, etc.)
* Managing switching between current and new applet
* Optionally reporting update status to back-end

We provide some examples for update manager (:numref:`demo-list-sems-lite` :ref:`demo-list-sems-lite`)


SEMS Lite Agent (from NXP)
======================================================================

The role of SEMS Lite Agent is an under:

* Provide functional APIs to Update Manager
* It is a library/module that helps the *Update Manager* to query/know the
  state of the system
* Use the *update package*  as received by the *Update Manager*, and update
  the Applet
* Track the update progress / interrupted updates
* Optionally retrieve loading receipt from the secure element.
