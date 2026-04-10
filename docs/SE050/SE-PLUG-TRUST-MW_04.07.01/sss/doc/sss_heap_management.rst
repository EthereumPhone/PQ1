..
    Copyright 2020 NXP

    SPDX-License-Identifier: Apache-2.0


.. highlight:: c

.. _sss-malloc-macros:

=================================================
 SSS Heap Management
=================================================

For effective heap management, macros ``SSS_MALLOC``, ``SSS_CALLOC`` 
and ``SSS_FREE`` are available in :file:`sss/port/ksdk/fsl_sss_types.h` 
for embedded build and in :file:`sss/port/default/fsl_sss_types.h` 
for PC/Linux build.

.. literalinclude:: ../port/ksdk/fsl_sss_types.h
   :language: c
   :start-after: /* doc:start:sss-heap_mgmt */
   :end-before: /* doc:end:sss-heap_mgmt */

These macros are used for heap management 
operations in middleware and examples. All malloc/calloc/free calls should redirect to the same implementation.
The same macro is also used for mbedTLS so that we are consistent across 
all malloc/free calls.
In case of CMake configuration ``RTOS=FreeRTOS``, we 
define the macros to use FreeRTOS implementation. 

.. warning:: Not using same implementation across the solution could lead to 
             memory corruption.

It is recommended that these macros should be used for all applications.
The user can also define their own implementation of heap APIs as platform dependent 
calls to malloc, calloc and free.
