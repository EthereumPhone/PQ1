/*
 * FreeRTOS FreeRTOS LTS Qualification Tests preview
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file qualification_test.c
 * @brief Implements the entry function for LTS qualification test.
 */

#include "test_execution_config.h"
#include "platform_function.h"

#if ( DEVICE_ADVISOR_TEST_ENABLED == 1)
    extern int RunDeviceAdvisorDemo( void );
#endif

#if ( OTA_E2E_TEST_ENABLED == 1)
    extern int RunOtaE2eDemo( void );
#endif

#if ( TRANSPORT_INTERFACE_TEST_ENABLED == 1 )
    #include "transport_interface_test.h"
#endif

#if ( MQTT_TEST_ENABLED == 1 )
    #include "mqtt_test.h"
#endif

#if ( OTA_PAL_TEST_ENABLED == 1 )
    #include "ota_pal_test.h"
#endif

#if ( CORE_PKCS11_TEST_ENABLED == 1 )
    #include "core_pkcs11_test.h"
#endif

#ifndef TEST_START_DELAY_MS
    #define TEST_START_DELAY_MS  5000
#endif

/*-----------------------------------------------------------*/

void RunQualificationTest( void )
{
    FRTest_TimeDelay( TEST_START_DELAY_MS );

    #if ( DEVICE_ADVISOR_TEST_ENABLED == 1)
        RunDeviceAdvisorDemo();
    #endif

    #if ( OTA_E2E_TEST_ENABLED == 1)
        RunOtaE2eDemo();
    #endif

    #if ( TRANSPORT_INTERFACE_TEST_ENABLED == 1 )
        RunTransportInterfaceTest();
    #endif

    #if ( MQTT_TEST_ENABLED == 1 )
        RunMqttTest();
    #endif

    #if ( OTA_PAL_TEST_ENABLED == 1 )
        RunOtaPalTest();
    #endif

    #if ( CORE_PKCS11_TEST_ENABLED == 1 )
        RunPkcs11Test();
    #endif
}

/*-----------------------------------------------------------*/
