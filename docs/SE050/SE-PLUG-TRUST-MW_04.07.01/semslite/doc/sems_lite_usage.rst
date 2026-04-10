..
    Copyright 2019,2020,2024 NXP


=================================================
SEMS Lite Agent Usage
=================================================

.. _case-1-basic-usage:

Case 1: Basic Usage
^^^^^^^^^^^^^^^^^^^^^^^^^

Basic API usage documentation for using SEMS Lite agent is as under.

1. Call :cpp:type:`sems_lite_agent_init_context()` to do context initialization.

2. Call :cpp:type:`sems_lite_agent_session_open()` to open channel to SE and select SEMS Lite applet.

3. Call :cpp:type:`sems_lite_agent_load_package()` to load upgrade script.

4. SEMS Lite agent would internally query the tear status from SE051, if there was a power interrupt during upgradation(tearing event).

5. SEMS Lite agent load the script from package to SE051 and get response from SE051.

6. SEMS Lite agent checking the response and return "Success" to user.

7. User call :cpp:type:`sems_lite_agent_session_close()` to close channel.

.. image:: /0022_flow_api_success.jpeg

.. _case-2-check-tearing:

Case 2: In case there was a tearing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In case of tear which is due to system power off during uploading, user would receive return code "DoRerun" when he try to load new package. Use must load the torn again.

1. Call :cpp:type:`sems_lite_agent_init_context()`, :cpp:type:`sems_lite_agent_session_open()` and :cpp:type:`sems_lite_agent_load_package()` as those in :ref:`case-1-basic-usage`.

2. SEMS Lite agent would query tear status from SE.

3. In case tear happens, SEMS Lite agent would get signature of tear script from SE and compare it to the signature of loaded script.

4. If these 2 signatures are same, it means the loaded script is the re-run script. SEMS Lite agent load it to SE.

5. If the signatures are different, SEMS Lite agent would inform user by printing a warning message "SEMS Lite signature not match!!!". It will also output "Current package signature" and "Expected signature" which can be used in next step.

6. User must find the correct script by signature and load it again if signature mismatch warning message is printed.

.. image:: /0020_flow_with_signature.jpeg

Case 3: Doing a recovery after a failed update
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In case the upgrade can not complete, user would receive return code "Do Recovery". User must load recovery script to resume SE to old Applet.

1. Call :cpp:type:`sems_lite_agent_init_context()`, :cpp:type:`sems_lite_agent_session_open()` and :cpp:type:`sems_lite_agent_load_package()` as those in :ref:`case-1-basic-usage`.

2. SEMS Lite agent would query tear status from SE as in :ref:`case-2-check-tearing`.

3. SEMS Lite agent load the script from package to SE. SE can't complete upgrade and inform SEMS Lite agent to do recovery by response.

4. SEMS Lite agent checking the response and return "DoRecovery" to user.

5. User must find the recovery script which is used to load the old Applet.

6. User load the recovery script and get response from SEMS Lite agent.

.. image:: /0025_flow_api_recovery.jpeg

Details for SE to report "Do Recovery" can be found in following:

.. image:: /0030_flow_apis_recovery_detection_scenario1.jpeg

.. image:: /0030_flow_apis_recovery_detection_scenario2.jpeg


Case 4: Tearing during recovery
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Case 4: In case tear happens when loading recovery package, User should re-run the script in the same way described in :ref:`case-2-check-tearing`.

.. image:: /0041_flow_recovery_tear.jpeg


Case 5: Load Key rotate script encounter SE unexpected power off
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In case the SE is powered off unexpectedly during uploading key rotate script, user would receive return code "COM_FAILURE" which means communication failure. User has 2 choices:

1. Load next script. SEMS Lite agent will check tear status and inform user if it's required to re-run last script. It's same to :ref:`case-2-check-tearing`.

2. User software checks tear status and then decides whether to re-load the broken script as following:

i) Call :cpp:type:`sems_lite_agent_init_context()` and :cpp:type:`sems_lite_agent_session_open()` as those in :ref:`case-1-basic-usage`.

ii) Call :cpp:type:`sems_lite_check_Tear()` to decide if tear happens for last upgrade.

iii) In case tear happens, call :cpp:type:`sems_lite_get_SignatureofLastScript()` to get last script signature

iv) Find the correct script by signature and load the tear script again with :cpp:type:`sems_lite_agent_load_package()`.


.. image:: /0050_flow_unexpected_power_off.jpeg


API Calls for Usage of SEMS Lite Agent
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: ../../semslite/ex/sems_lite_ex_update/sems_lite_ex_update.c
   :language: c
   :start-after: /* doc:start:SEMS-Lite-include-files */
   :end-before: /* doc:end:SEMS-Lite-include-files */


Declare a SEMS Lite input buffer:
SEMS Lite input buffer is hex file converted from protobuf file


.. literalinclude:: ../../semslite/ex/sems_lite_ex_update/sems_lite_ex_update.c
   :language: c
   :start-after: /* doc:start:SEMS-Lite-protobuf-declare */
   :end-before: /* doc:end:SEMS-Lite-protobuf-declare */


Declare SEMS Lite context:
SEMS Lite context holds flags and variables used through the whole loading process


.. literalinclude:: ../../semslite/ex/sems_lite_ex_update/sems_lite_ex_update.c
   :language: c
   :start-after: /* doc:start:SEMS-Lite-context-declare */
   :end-before: /* doc:end:SEMS-Lite-context-declare */
   :dedent: 4


Initilize the context:

.. literalinclude:: ../../semslite/ex/sems_lite_ex_update/sems_lite_ex_update.c
   :language: c
   :start-after: /* doc:start:SEMS-Lite-api-usage-init */
   :end-before: /* doc:end:SEMS-Lite-api-usage-init */
   :dedent: 4

Open session:

.. literalinclude:: ../../semslite/ex/sems_lite_ex_update/sems_lite_ex_update.c
   :language: c
   :start-after: /* doc:start:SEMS-Lite-api-usage-open */
   :end-before: /* doc:end:SEMS-Lite-api-usage-open */
   :dedent: 4


Load Package:

.. literalinclude:: ../../semslite/ex/sems_lite_ex_update/sems_lite_ex_update.c
   :language: c
   :start-after: /* doc:start:SEMS-Lite-api-usage-load-pkg */
   :end-before: /* doc:end:SEMS-Lite-api-usage-load-pkg */
   :dedent: 4


Close the session:

.. literalinclude:: ../../semslite/ex/sems_lite_ex_update/sems_lite_ex_update.c
   :language: c
   :start-after: /* doc:start:SEMS-Lite-api-close */
   :end-before: /* doc:end:SEMS-Lite-api-close */
   :dedent: 4






