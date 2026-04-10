..
    Copyright 2019,2020 NXP


=================================================
 SEMS Lite Agent Package Load Process
=================================================


When SE update package is loaded to SEMS Lite agent, SEMS Lite agent executes following steps to load package (offline) to the SE.

1. Check if target entity ID match.

2. Check tear status which indicate if last load operation succeed. If not, SEMS Lite agent will indicate user to re-run the tear script.

3. Check if recovery has started and record flag accordingly. This flag is used later in error code handling.

4. Check if meet minimum previous version and version request.

5. Decode the protobuf stream to find valid SEMS Lite agent package.

6. If the package includes host command, take relative actions (reset SE, etc).

7. If the package includes APDU command, send the APDU command to SE.

8. Get the status word from SE. Tranlate the status word to customer friendly return value.

9. Check tear status which indicate if this load operation succeed. If not, SEMS Lite agent will indicate user to re-run the tear script.

Refer to following flowchart for detail:

- **Flowchart Part 1:**

.. image:: /flow_chart1.jpeg
      :align: center
      :width: 220px


- **Flowchart Part 2:**

.. image:: /flow_chart2.jpeg
      :align: center
      :width: 220px


- **Flowchart Part 3:**

.. image:: /flow_chart3.jpeg
      :align: center
      :width: 220px


- **Flowchart Part 4:**

.. image:: /flow_chart4.jpeg
      :align: center
      :width: 220px


- **Flowchart Part 5:**

.. image:: /flow_chart5.jpeg
      :align: center
      :width: 220px

Note 1: SEMS Lite agent and iot hub module share protobuf stream processing function. In this function, several keystore endpoints could attach to the dispatcher. But in SEMS Lite agent case, there is only one keystore endpoint which is sems lite agent.
