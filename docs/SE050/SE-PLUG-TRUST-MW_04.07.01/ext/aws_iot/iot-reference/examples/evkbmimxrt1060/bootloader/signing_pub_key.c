/*
 * Copyright (C) 2017 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
 *
 * http://www.FreeRTOS.org
 * http://aws.amazon.com/freertos
 *
 * 1 tab == 4 spaces!
 */

#include "mcuboot_config.h"

#if defined( MCUBOOT_SIGN_RSA )

#error Please use MCUBoot imgtool.py to generate an RSA signing key \
    and replace this file with the output of the tool.

const unsigned char rsa_pub_key[] = { 0x00 };
const unsigned int rsa_pub_key_len = 0;

#elif defined( MCUBOOT_SIGN_EC256 )

#error Please use MCUBoot imgtool.py to generate an EC signing key \
    and replace this file with the output of the tool.

const unsigned char ecdsa_pub_key[] = { 0x00 };
const unsigned int ecdsa_pub_key_len = 0;

#endif /* if defined( MCUBOOT_SIGN_RSA ) */
