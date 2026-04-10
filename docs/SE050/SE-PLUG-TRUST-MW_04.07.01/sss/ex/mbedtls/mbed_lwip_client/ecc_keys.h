/*
* Copyright 2024 NXP
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdint.h>
#include <string.h>

#if ECC_KEY_TYPE

/* Root CA Certficate */
const char rootca_file[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICHzCCAcWgAwIBAgIUViOm0G5pR+0IDHuD9quFAVGFDkcwCgYIKoZIzj0EAwIw\r\n"
    "ZTELMAkGA1UEBhMCQUIxCzAJBgNVBAgMAlhZMQswCQYDVQQHDAJMSDEUMBIGA1UE\r\n"
    "CgwLTlhQLURlbW8tQ0ExEjAQBgNVBAsMCURlbW8tVW5pdDESMBAGA1UEAwwJbG9j\r\n"
    "YWxob3N0MB4XDTI0MDEwODA5NTIyNFoXDTMxMDkwODA5NTIyNFowZTELMAkGA1UE\r\n"
    "BhMCQUIxCzAJBgNVBAgMAlhZMQswCQYDVQQHDAJMSDEUMBIGA1UECgwLTlhQLURl\r\n"
    "bW8tQ0ExEjAQBgNVBAsMCURlbW8tVW5pdDESMBAGA1UEAwwJbG9jYWxob3N0MFkw\r\n"
    "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEspRLZwwppAmKP8fJxE7fzWqPMDkBD35X\r\n"
    "fcHNkx5ajejOOpJeeXYEffyhwKeJgc+QcnB/GjBUjFiaGmCkkEK266NTMFEwHQYD\r\n"
    "VR0OBBYEFNpK5KttisxWDER8W9C5UG+3Y+0nMB8GA1UdIwQYMBaAFNpK5KttisxW\r\n"
    "DER8W9C5UG+3Y+0nMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIg\r\n"
    "AR7Efpffo8Z+xpBwO20QDEmKV/3lnowX/TIbnzvzEVECIQDUreiuJuY6cXiakVV/\r\n"
    "4W7NkfhRy1cTpCNXUlntz9cHJw==\r\n"
    "-----END CERTIFICATE-----\r\n";
int rootca_file_len = sizeof(rootca_file);

#if WITH_SE05X
/* Read keys from SE */
const char devkey_file[]  = "";
int devkey_file_len       = sizeof(devkey_file);
const char devcert_file[] = "";
int devcert_file_len      = sizeof(devcert_file);

#else

const char devkey_file[] =
    "-----BEGIN EC PARAMETERS-----\r\n"
    "BggqhkjOPQMBBw==\r\n"
    "-----END EC PARAMETERS-----\r\n"
    "-----BEGIN EC PRIVATE KEY-----\r\n"
    "MHcCAQEEIGniTOqcUSAHx4MaKnWXTfv/UMkF3z4zAII21KD9JDsUoAoGCCqGSM49\r\n"
    "AwEHoUQDQgAEuG4fd7qNTnGTjjs04HGBTVEpiLpqJVofqW6SqHIyXOiZD2WOsR7H\r\n"
    "d7DhifjIt7tdRm42uoed10wV7V2uZKd5nA==\r\n"
    "-----END EC PRIVATE KEY-----\r\n";
int devkey_file_len = sizeof(devkey_file);

const char devcert_file[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIBxDCCAWsCFCb9ILUbKQetAJG6S5vI7ToA1FeLMAoGCCqGSM49BAMCMGUxCzAJ\r\n"
    "BgNVBAYTAkFCMQswCQYDVQQIDAJYWTELMAkGA1UEBwwCTEgxFDASBgNVBAoMC05Y\r\n"
    "UC1EZW1vLUNBMRIwEAYDVQQLDAlEZW1vLVVuaXQxEjAQBgNVBAMMCWxvY2FsaG9z\r\n"
    "dDAeFw0yNDAxMDgwOTUyMjVaFw0zMTA5MDgwOTUyMjVaMGUxCzAJBgNVBAYTAkFC\r\n"
    "MQswCQYDVQQIDAJYWTELMAkGA1UEBwwCTEgxFDASBgNVBAoMC05YUC1EZW1vLUNB\r\n"
    "MRIwEAYDVQQLDAlEZW1vLVVuaXQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqG\r\n"
    "SM49AgEGCCqGSM49AwEHA0IABLhuH3e6jU5xk447NOBxgU1RKYi6aiVaH6lukqhy\r\n"
    "MlzomQ9ljrEex3ew4Yn4yLe7XUZuNrqHnddMFe1drmSneZwwCgYIKoZIzj0EAwID\r\n"
    "RwAwRAIgM4LC2v3lc0GMT8LvTzKZR9mS/+Fu3TBSPZITi/EsUOwCIBro3xuNgA29\r\n"
    "FfW7gLxUUnI1v3hcYne/bJVmQtIg+ZTA\r\n"
    "-----END CERTIFICATE-----\r\n";
int devcert_file_len = sizeof(devcert_file);

#endif //#if WITH_SE05X
#endif //#if ECC_KEY_TYPE