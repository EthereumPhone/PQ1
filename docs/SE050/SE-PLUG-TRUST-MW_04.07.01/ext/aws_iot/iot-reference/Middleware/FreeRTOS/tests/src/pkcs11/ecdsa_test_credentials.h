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
 * @file ecdsa_test_credentials.h
 * @brief ECDSA test credentials include header file.
 */
#ifndef ECDSA_TEST_CREDENTIALS_H
#define ECDSA_TEST_CREDENTIALS_H

/* Valid ECDSA private key. */
#define ECDSA_TEST_VALID_PRIVATE_KEY                                     \
    "-----BEGIN EC PRIVATE KEY-----\n"                                   \
    "MHcCAQEEIACZbHljxOFuBeEKRcMijfbVcDzBxa8M4T5jElsElFQ5oAoGCCqGSM49\n" \
    "AwEHoUQDQgAEzghp+QstUhOmzKBGEL7uBjsaBbyaNTMLXKLSW78+bdoP9bKTOrqi\n" \
    "Kk9GzFk9ChthHFsx+T7UFithbYWtRf0Zww==\n"                             \
    "-----END EC PRIVATE KEY-----"

/* Valid ECDSA public key. */
#define ECDSA_TEST_VALID_PUBLIC_KEY                                      \
    "-----BEGIN PUBLIC KEY-----\n"                                       \
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzghp+QstUhOmzKBGEL7uBjsaBbya\n" \
    "NTMLXKLSW78+bdoP9bKTOrqiKk9GzFk9ChthHFsx+T7UFithbYWtRf0Zww==\n"     \
    "-----END PUBLIC KEY-----"

/* Valid ECDSA certificate. */
#define ECDSA_TEST_VALID_CERTIFICATE                                     \
    "-----BEGIN CERTIFICATE-----\n"                                      \
    "MIICbjCCAhQCCQDqQDa2NeYOhTAKBggqhkjOPQQDAjCBvjELMAkGA1UEBhMCVVMx\n" \
    "EzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxGDAWBgNVBAoM\n" \
    "D0FtYXpvbiBGcmVlUlRPUzEhMB8GA1UECwwYUEtDUyAjMTEgVGVzdCBDcmVkZW50\n" \
    "aWFsMSgwJgYDVQQDDB9ET05UX1VTRV9USElTX0tFWV9JTl9BX1JFQUxfQVBQMSEw\n" \
    "HwYJKoZIhvcNAQkBFhJub2JvZHlAbm93aGVyZS5jb20wHhcNMTkwNTI5MjE1NjAw\n" \
    "WhcNMjkwNTI2MjE1NjAwWjCBvjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hp\n" \
    "bmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxGDAWBgNVBAoMD0FtYXpvbiBGcmVlUlRP\n" \
    "UzEhMB8GA1UECwwYUEtDUyAjMTEgVGVzdCBDcmVkZW50aWFsMSgwJgYDVQQDDB9E\n" \
    "T05UX1VTRV9USElTX0tFWV9JTl9BX1JFQUxfQVBQMSEwHwYJKoZIhvcNAQkBFhJu\n" \
    "b2JvZHlAbm93aGVyZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATOCGn5\n" \
    "Cy1SE6bMoEYQvu4GOxoFvJo1MwtcotJbvz5t2g/1spM6uqIqT0bMWT0KG2EcWzH5\n" \
    "PtQWK2Ftha1F/RnDMAoGCCqGSM49BAMCA0gAMEUCIQCs1n3p+fOZxjZT+fnm3MQf\n" \
    "IhxppLKnUggV42SAMpSneQIgdufH9clHZgrd9HVpRlIumy3sIMNEu9fzC9XZsSu8\n" \
    "yQ8=\n"                                                             \
    "-----END CERTIFICATE-----"

#endif /* ifndef ECDSA_TEST_CREDENTIALS_H */
