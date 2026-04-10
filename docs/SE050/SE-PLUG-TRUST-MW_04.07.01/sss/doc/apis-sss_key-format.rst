..
    Copyright 2019,2020 NXP

    SPDX-License-Identifier: Apache-2.0

.. _apis-sss_key-format:

======================================================================
 SSS api key format (asymmetric keys)
======================================================================


NIST-P, NIST-K and BRAINPOOL ECC Keys
======================================================================

When passing the key pair / public key, the key should be passed DER encoded using PKCS #8 or traditional OpenSSL format.
When passing the private key alone, do not include the key header.

Example key formats for some keys are shown below -

NIST-P 256 Key pair (Traditional OpenSSL format)::

  $ dumpasn1 ecc_256R_1_prv_openssl.der
  0 119: SEQUENCE {
  2   1:   INTEGER 1
  5  32:   OCTET STRING
       :     2B 30 F6 68 F3 98 83 75 28 26 05 E2 EE 97 65 3A
       :     41 2A 97 F8 0A 87 BC 7E 5F DD 5B D2 5C 5F 40 8E
 39  10:   [0] {
 41   8:     OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
       :     }
 51  68:   [1] {
 53  66:     BIT STRING
       :       04 87 02 B7 5B 01 73 8A F0 5F 2D FF 17 85 37 1A
       :       62 ED 6F C5 FD 7D BA 6F 14 45 05 43 23 3B 1B 06
       :       59 46 2B B6 25 DD 7D D6 77 BB 35 F9 72 99 A3 6A
       :       D4 33 B8 54 F6 93 3A CB 9F F6 47 DE D0 B6 9E 01
       :       5D
       :     }
       :   }


NIST-P 256 Key pair (PKCS8 format)::

  $  dumpasn1 ecc_256R_1_prv_pkcs8.der
  0 135: SEQUENCE {
  3   1:   INTEGER 0
  6  19:   SEQUENCE {
  8   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
 17   8:     OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
       :     }
 27 109:   OCTET STRING, encapsulates {
 29 107:     SEQUENCE {
 31   1:       INTEGER 1
 34  32:       OCTET STRING
       :         2B 30 F6 68 F3 98 83 75 28 26 05 E2 EE 97 65 3A
       :         41 2A 97 F8 0A 87 BC 7E 5F DD 5B D2 5C 5F 40 8E
 68  68:       [1] {
 70  66:         BIT STRING
       :           04 87 02 B7 5B 01 73 8A F0 5F 2D FF 17 85 37 1A
       :           62 ED 6F C5 FD 7D BA 6F 14 45 05 43 23 3B 1B 06
       :           59 46 2B B6 25 DD 7D D6 77 BB 35 F9 72 99 A3 6A
       :           D4 33 B8 54 F6 93 3A CB 9F F6 47 DE D0 B6 9E 01
       :           5D
       :         }
       :       }
       :     }
       :   }


NIST-P 256 Public key ::

  $  dumpasn1 ecc_256R_1_pub.der
  0  89: SEQUENCE {
  2  19:   SEQUENCE {
  4   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
 13   8:     OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
       :     }
 23  66:   BIT STRING
       :     04 B9 46 AA E7 08 69 DA 27 2F 55 55 0A FA D9 42
       :     F1 90 A4 0C 64 14 D3 78 94 74 AC 07 D5 F8 2C C9
       :     53 05 F5 B1 4C 3E F7 0A 23 9A 3D 50 0D 90 92 D7
       :     3B AB EA 12 23 FA A4 46 20 6F 22 4C CC E1 A5 1C
       :     70
       :   }


NIST-K 256 Key pair (Traditional OpenSSL format)::

  $  dumpasn1 ecc_256K_1_prv_openssl.der
  0 116: SEQUENCE {
  2   1:   INTEGER 1
  5  32:   OCTET STRING
       :     3F 0F 98 81 29 82 A7 6A AA 8A BA F1 7C 9C DC 7A
       :     D8 9E 20 8A 5B 86 DB 58 AD 9C 1B 32 43 4A 26 4D
 39   7:   [0] {
 41   5:     OBJECT IDENTIFIER secp256k1 (1 3 132 0 10)
       :     }
 48  68:   [1] {
 50  66:     BIT STRING
       :       04 63 AF AF 56 B8 D2 84 CA 92 BE 88 97 E8 EA B5
       :       EA A7 AC 30 94 CF 4A 5A 4B 97 67 1B B1 3A B2 85
       :       8C 95 FE 2C D9 4D 00 C7 EF FF 29 B5 CD A2 46 2D
       :       4C CD BD D1 CB 14 49 A2 10 26 C4 35 B9 ED DD 37
       :       D7
       :     }
       :   }


NIST-K 256 Key pair (PKCS8 format)::

  $  dumpasn1 ecc_256K_1_prv_pkcs8.der
  0 132: SEQUENCE {
  3   1:   INTEGER 0
  6  16:   SEQUENCE {
  8   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
 17   5:     OBJECT IDENTIFIER secp256k1 (1 3 132 0 10)
       :     }
 24 109:   OCTET STRING, encapsulates {
 26 107:     SEQUENCE {
 28   1:       INTEGER 1
 31  32:       OCTET STRING
       :         3F 0F 98 81 29 82 A7 6A AA 8A BA F1 7C 9C DC 7A
       :         D8 9E 20 8A 5B 86 DB 58 AD 9C 1B 32 43 4A 26 4D
 65  68:       [1] {
 67  66:         BIT STRING
       :           04 63 AF AF 56 B8 D2 84 CA 92 BE 88 97 E8 EA B5
       :           EA A7 AC 30 94 CF 4A 5A 4B 97 67 1B B1 3A B2 85
       :           8C 95 FE 2C D9 4D 00 C7 EF FF 29 B5 CD A2 46 2D
       :           4C CD BD D1 CB 14 49 A2 10 26 C4 35 B9 ED DD 37
       :           D7
       :         }
       :       }
       :     }
       :   }


NIST-K 256 Public key ::

  $  dumpasn1 ecc_256K_1_pub.der
  0  86: SEQUENCE {
  2  16:   SEQUENCE {
  4   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
 13   5:     OBJECT IDENTIFIER secp256k1 (1 3 132 0 10)
       :     }
 20  66:   BIT STRING
       :     04 3B 98 11 47 B9 7C 9B 39 62 2B 54 42 F6 0E 16
       :     B1 57 5E 17 23 08 DE 16 02 55 D7 EB 09 53 24 15
       :     9C B0 6A 49 EB 59 EF 5C AE 2A 31 48 CD 88 F5 ED
       :     EF 12 24 3C 36 EF C2 3F DA B1 AE EC E3 EE DD EA
       :     DB
       :   }


BrainPool 256 Key pair (Traditional OpenSSL format)::

  $  dumpasn1 ecc_256B_1_prv_openssl.der
  0 120: SEQUENCE {
  2   1:   INTEGER 1
  5  32:   OCTET STRING
       :     55 27 E9 FA 47 E8 58 B3 B0 CF D1 0C 4C 03 2A 80
       :     1E AB 3F C4 68 A7 2B B3 F8 E4 DC BD 47 E7 4E C1
 39  11:   [0] {
 41   9:     OBJECT IDENTIFIER brainpoolP256r1 (1 3 36 3 3 2 8 1 1 7)
       :     }
 52  68:   [1] {
 54  66:     BIT STRING
       :       04 7D A6 C9 C2 CC 5A 4A 18 C5 7B 92 1F A1 96 3B
       :       49 3D 2A 97 BB B5 3B 1D 09 ED F9 51 85 61 A4 F9
       :       C7 19 7F 00 6D A3 9B 61 C2 09 AA 65 EF 65 1D 2E
       :       B4 38 C6 F0 29 D3 5D DC 98 D1 19 75 D3 7B C3 00
       :       E6
       :     }
       :   }


BrainPool 256 Key pair (PKCS8 format)::

  $  dumpasn1 ecc_256B_1_prv_pkcs8.der
  0 136: SEQUENCE {
  3   1:   INTEGER 0
  6  20:   SEQUENCE {
  8   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
 17   9:     OBJECT IDENTIFIER brainpoolP256r1 (1 3 36 3 3 2 8 1 1 7)
       :     }
 28 109:   OCTET STRING, encapsulates {
 30 107:     SEQUENCE {
 32   1:       INTEGER 1
 35  32:       OCTET STRING
       :         55 27 E9 FA 47 E8 58 B3 B0 CF D1 0C 4C 03 2A 80
       :         1E AB 3F C4 68 A7 2B B3 F8 E4 DC BD 47 E7 4E C1
 69  68:       [1] {
 71  66:         BIT STRING
       :           04 7D A6 C9 C2 CC 5A 4A 18 C5 7B 92 1F A1 96 3B
       :           49 3D 2A 97 BB B5 3B 1D 09 ED F9 51 85 61 A4 F9
       :           C7 19 7F 00 6D A3 9B 61 C2 09 AA 65 EF 65 1D 2E
       :           B4 38 C6 F0 29 D3 5D DC 98 D1 19 75 D3 7B C3 00
       :           E6
       :         }
       :       }
       :     }
       :   }


BrainPool-256 Public key ::

   $  dumpasn1 ecc_256B_1_pub.der
  0  90: SEQUENCE {
  2  20:   SEQUENCE {
  4   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
 13   9:     OBJECT IDENTIFIER brainpoolP256r1 (1 3 36 3 3 2 8 1 1 7)
       :     }
 24  66:   BIT STRING
       :     04 7D A6 C9 C2 CC 5A 4A 18 C5 7B 92 1F A1 96 3B
       :     49 3D 2A 97 BB B5 3B 1D 09 ED F9 51 85 61 A4 F9
       :     C7 19 7F 00 6D A3 9B 61 C2 09 AA 65 EF 65 1D 2E
       :     B4 38 C6 F0 29 D3 5D DC 98 D1 19 75 D3 7B C3 00
       :     E6
       :   }



When retrieving the key pair as data argument from the sss_key_store_get api, the full key pair cannot be retrieved. Instead the public key value is returned in ANSI X9.62 uncompressed format.

.. note:: Keys, signature and shared secret key generated all follow the big endian convention.



EDWARD and MONTGOMERY ECC keys
======================================================================

When passing the key pair / public key, the key should be passed DER encoded using the format specified in RFC 8410.
When passing the private key alone, do not include the key header.

When retrieving the key pair as data argument from the sss_key_store_get api, the full key pair cannot be retrieved. Instead the public key value is returned in ANSI X9.62 uncompressed format.

.. note:: Keys, signature and shared secret key generated all follow the little endian convention.

A set of examples of a X25519 keypair encoded according to RFC 8410::

  $  dumpasn1 X25519_keypair.der
   0  81: SEQUENCE {
   2   1:   INTEGER 1
   5   5:   SEQUENCE {
   7   3:     OBJECT IDENTIFIER curveX25519 (1 3 101 110)
        :     }
  12  34:   OCTET STRING, encapsulates {
  14  32:     OCTET STRING
        :       58 5D B1 E3 50 0B 71 24 F6 B1 E1 41 83 54 93 12
        :       F4 4B 0C A3 44 F7 52 A1 8A 12 2F E7 DA D9 CE 52
        :     }
  48  33:   [1]
        :     00 A2 8E 04 FF 1C DC 1C 3D 60 91 0F BC 98 EF 01
        :     BF 9F 0F 69 C0 B7 EF 70 61 35 34 62 F3 06 28 C7
        :     29
        :   }

  $ dumpasn1 X25519_priv.pem
    0  46: SEQUENCE {
    2   1:   INTEGER 0
    5   5:   SEQUENCE {
    7   3:     OBJECT IDENTIFIER curveX25519 (1 3 101 110)
         :     }
   12  34:   OCTET STRING, encapsulates {
   14  32:     OCTET STRING
         :       58 5D B1 E3 50 0B 71 24 F6 B1 E1 41 83 54 93 12
         :       F4 4B 0C A3 44 F7 52 A1 8A 12 2F E7 DA D9 CE 52
         :     }
         :   }

  $ dumpasn1 X25519_pub.pem
    0  42: SEQUENCE {
    2   5:   SEQUENCE {
    4   3:     OBJECT IDENTIFIER curveX25519 (1 3 101 110)
         :     }
    9  33:   BIT STRING
         :     A2 8E 04 FF 1C DC 1C 3D 60 91 0F BC 98 EF 01 BF
         :     9F 0F 69 C0 B7 EF 70 61 35 34 62 F3 06 28 C7 29
         :   }


The X25519 keypair from the example above can be created with the asn1parse OpenSSL tool.
The command line invocation is as follows::

  openssl asn1parse -genconf key_config.txt -out X25519_keypair.der

The file **key_config.txt** contains the different ASN.1 components and values of the keypair to create.
The resulting DER representation of the keypair is stored in the file  **X25519_keypair.der**.
The contents of the **key_config.txt** file is as follows::

  asn1 = SEQUENCE:seq_section

  [seq_section]

  field1 = INTEGER:1
  field2 = SEQUENCE:seq_section_oid
  field3 = OCTWRAP,FORMAT:HEX,OCT:585DB1E3500B7124F6B1E14183549312F44B0CA344F752A18A122FE7DAD9CE52
  field4 = IMP:1C,INT:0x00A28E04FF1CDC1C3D60910FBC98EF01BF9F0F69C0B7EF7061353462F30628C729

  [seq_section_oid]

  field1 = OID:X25519

.. note:: Additional information on the *asn1parse* command and the key configuration format is available under the manpages of respectively *asn1parse* and *ASN1_generate_nconf*


Set Edwards and Montgomery keys using pycli
----------------------------------------------------------------------

On generting keys using openssl, pycli tool can be used to set edwards and montomory keys.

Example - Set key pair as::

    `openssl genpkey -algorithm ed25519 -outform PEM -out test_ed25519.pem`
    `ssscli set ecc pair <KEYID> test_ed25519.pem`

Set public key as::

    `openssl pkey -in test_ed25519.pem -out test_ed25519_pub.pem -pubout`
    `ssscli set ecc pub <KEYID> test_ed25519_pub.pem`


RSA keys
======================================================================

When passing the key pair / public key, the key should be passed DER encoded using PKCS #8 or traditional OpenSSL format.
When passing the private key alone, do not include the key header.

When retrieving the key pair as data argument from the sss_key_store_get API, the full key pair cannot be retrieved. Instead the public key value is returned in ANSI X9.62 uncompressed format.

Example key format for RSA-2048 key pair is shown below -

RSA-2048 Key Pair (Traditional OpenSSL format) ::

  $  dumpasn1 rsa_2048_1_prv_openssl.der
   0 1187: SEQUENCE {
   4    1:   INTEGER 0
   7  257:   INTEGER
         :     00 91 C9 82 8D 32 D6 39 F5 B2 59 15 19 4B B8 F8
         :     71 DE 62 7A C3 E8 B9 7E 99 06 23 0C D3 1B 4B 45
         :     09 8F DD F3 69 FD 6B 79 90 0A BB 4A E9 6E 43 0C
         :     D2 4E 63 09 3C 90 45 7D D6 8A C5 54 17 D0 3D FE
         :     77 20 D3 1E 8B E3 8A B4 7C E0 06 18 3D 16 B4 C2
         :     08 47 D0 4D 08 27 EB AF 12 9B 59 2B 8F EC 6D F1
         :     ED 1C 7A 4A 5A 99 D4 DF 40 54 F3 0B 72 5D 31 E6
         :     54 70 8E 0F 55 8C 32 08 F1 46 EB 39 00 0D E5 C9
         :             [ Another 129 bytes skipped ]
 268    3:   INTEGER 65537
 273  256:   INTEGER
         :     17 B0 C9 24 1C 83 E9 D4 EE 8A 57 09 39 20 11 FB
         :     75 B9 C7 72 5E 37 5A 86 65 14 12 B4 46 DB 58 98
         :     D6 5B 53 D5 6A F1 93 F1 0A 2A BD 0B 29 8D AA CA
         :     8D 78 BE DA 56 7A D1 C3 FD E1 55 7F 83 29 B7 D8
         :     1A FF 99 17 54 14 1E 58 01 3D 96 F8 6D 0A AA FC
         :     96 7D 97 D9 AB 47 10 E2 F3 57 59 0D 61 21 CD 59
         :     0C 87 7B 88 0A 8C 7D 9F A2 23 AC 13 5B 12 A3 4D
         :     20 77 42 B0 52 56 6F D3 E9 84 35 A0 8D 21 9A 14
         :             [ Another 128 bytes skipped ]
 533  129:   INTEGER
         :     00 C1 FA D9 5B 58 84 98 79 52 80 A5 BC 36 3C 32
         :     7D 4F 15 51 8B A7 1B 32 5E 0F 52 55 A3 75 0B BA
         :     F1 B5 14 E5 5B 66 33 40 03 B2 0D 71 56 79 2A 4F
         :     1F 28 81 21 96 8F FF 28 4E F2 9C 45 BB 2F 6D BC
         :     6E DC B6 AB F1 57 B0 6A 50 64 37 86 26 A9 C1 D5
         :     59 39 4F 00 4B 6E C0 0C 07 AF DC 12 70 0F CB B8
         :     F1 E4 00 4F 04 62 1A 86 C1 A8 45 3A 7A AB D1 EF
         :     86 EF BC 7A 6A 53 7E BF 2B 5C 5A 33 B8 2B 60 CC
         :     5B
 665  129:   INTEGER
         :     00 C0 66 1C 7C E9 4B 20 5E 3A E4 35 EE 74 F2 0C
         :     A8 F8 4F EF E8 46 22 BE A2 13 36 EC A9 C4 50 30
         :     1D 8E DC 1D DA D0 BF A1 7E 85 DE 6B 82 EC EE 3B
         :     4A F6 C4 6F 81 23 B1 84 09 C8 E3 1D F4 DC 3B 48
         :     EF 15 9D 05 95 14 04 30 B5 7F 80 FE FE D3 3C 75
         :     75 AD F2 F0 90 5F A6 0C 28 F3 65 48 59 82 7C 49
         :     38 B4 F6 AB 8F 87 39 20 2D D7 3E 2E 00 D4 47 3F
         :     28 9F 5C 9F F4 1F FC 7D 67 C7 46 00 6E 99 04 CD
         :     65
 797  129:   INTEGER
         :     00 A4 5D D6 47 9C 9D DE 45 0F 2F 8B 40 0C 04 BE
         :     13 88 2B 5C 49 A5 73 5A 1E 71 85 26 A3 B6 CE 15
         :     BE 31 DE 5E EA 2F 93 45 AE DB F4 A0 10 D1 E2 93
         :     E0 A7 05 A4 5C 5B EF AD 4C 18 2F 6A B6 CD DD 82
         :     49 BE 23 DB 56 49 23 67 32 6F 78 CC E7 7D F8 8C
         :     BB 69 E0 13 33 D7 C8 4B 69 48 0E 86 61 06 41 6D
         :     99 29 C5 49 2F 41 A1 90 86 0F FB 79 2D F0 E1 96
         :     C1 13 EA F5 1F 9B 58 4E CC 83 18 BB B2 56 AF 52
         :     F9
 929  128:   INTEGER
         :     1A 22 44 A0 5A F8 0F 6F 7D 44 5E 67 03 8F 95 54
         :     A6 56 05 5A 61 9C 7A 94 7D 53 AA 95 EC CA 8F 9E
         :     94 37 25 FF 00 F7 E6 B1 CE F1 45 5D 45 5D 9E C4
         :     31 FC C0 C0 A3 DE 8A F6 E1 48 A8 5B 08 47 2D 42
         :     FC 86 95 A9 88 4C 81 69 45 E6 79 BC 97 68 D0 F3
         :     A9 2B 24 AE 17 AF F0 5A E7 A4 CC 4D 0C 42 61 97
         :     C8 4C F1 44 CF B3 5C C1 9D 49 1E EA 91 EB 13 93
         :     2B 02 63 DF BF 30 86 C0 3F FB 2C 37 D9 A5 23 59
 1060  128:   INTEGER
         :     0E AD DC 66 09 36 F6 A9 55 28 FD C3 47 6D B9 1D
         :     88 15 41 1B A2 23 5A B7 81 4E C8 90 A2 51 50 7E
         :     D9 DF 83 0B 64 DF A9 5F AF 20 DA 65 BC C8 74 F9
         :     E2 00 6E 15 1D 8E DF 47 C6 84 BF 96 F7 44 C9 38
         :     FC B8 70 B5 ED C2 3C BC B6 B3 5B 54 C3 85 66 42
         :     B7 5A 70 99 37 A8 55 C0 F6 96 F5 EF F2 34 8D 3F
         :     A3 56 2E 5D A4 97 79 00 4D 28 3E 35 03 19 41 89
         :     A3 96 A5 45 37 90 84 C1 F5 6E 75 3F 33 24 44 FF
         :   }


RSA-2048 Key Pair (PKCS8 format) ::

  $  dumpasn1 rsa_2048_1_prv_pkcs8.der
   0 1213: SEQUENCE {
   4    1:   INTEGER 0
   7   13:   SEQUENCE {
   9    9:     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
  20    0:     NULL
         :     }
  22 1191:   OCTET STRING, encapsulates {
  26 1187:     SEQUENCE {
  30    1:       INTEGER 0
  33  257:       INTEGER
         :         00 91 C9 82 8D 32 D6 39 F5 B2 59 15 19 4B B8 F8
         :         71 DE 62 7A C3 E8 B9 7E 99 06 23 0C D3 1B 4B 45
         :         09 8F DD F3 69 FD 6B 79 90 0A BB 4A E9 6E 43 0C
         :         D2 4E 63 09 3C 90 45 7D D6 8A C5 54 17 D0 3D FE
         :         77 20 D3 1E 8B E3 8A B4 7C E0 06 18 3D 16 B4 C2
         :         08 47 D0 4D 08 27 EB AF 12 9B 59 2B 8F EC 6D F1
         :         ED 1C 7A 4A 5A 99 D4 DF 40 54 F3 0B 72 5D 31 E6
         :         54 70 8E 0F 55 8C 32 08 F1 46 EB 39 00 0D E5 C9
         :                 [ Another 129 bytes skipped ]
 294    3:       INTEGER 65537
 299  256:       INTEGER
         :         17 B0 C9 24 1C 83 E9 D4 EE 8A 57 09 39 20 11 FB
         :         75 B9 C7 72 5E 37 5A 86 65 14 12 B4 46 DB 58 98
         :         D6 5B 53 D5 6A F1 93 F1 0A 2A BD 0B 29 8D AA CA
         :         8D 78 BE DA 56 7A D1 C3 FD E1 55 7F 83 29 B7 D8
         :         1A FF 99 17 54 14 1E 58 01 3D 96 F8 6D 0A AA FC
         :         96 7D 97 D9 AB 47 10 E2 F3 57 59 0D 61 21 CD 59
         :         0C 87 7B 88 0A 8C 7D 9F A2 23 AC 13 5B 12 A3 4D
         :         20 77 42 B0 52 56 6F D3 E9 84 35 A0 8D 21 9A 14
         :                 [ Another 128 bytes skipped ]
 559  129:       INTEGER
         :         00 C1 FA D9 5B 58 84 98 79 52 80 A5 BC 36 3C 32
         :         7D 4F 15 51 8B A7 1B 32 5E 0F 52 55 A3 75 0B BA
         :         F1 B5 14 E5 5B 66 33 40 03 B2 0D 71 56 79 2A 4F
         :         1F 28 81 21 96 8F FF 28 4E F2 9C 45 BB 2F 6D BC
         :         6E DC B6 AB F1 57 B0 6A 50 64 37 86 26 A9 C1 D5
         :         59 39 4F 00 4B 6E C0 0C 07 AF DC 12 70 0F CB B8
         :         F1 E4 00 4F 04 62 1A 86 C1 A8 45 3A 7A AB D1 EF
         :         86 EF BC 7A 6A 53 7E BF 2B 5C 5A 33 B8 2B 60 CC
         :         5B
 691  129:       INTEGER
         :         00 C0 66 1C 7C E9 4B 20 5E 3A E4 35 EE 74 F2 0C
         :         A8 F8 4F EF E8 46 22 BE A2 13 36 EC A9 C4 50 30
         :         1D 8E DC 1D DA D0 BF A1 7E 85 DE 6B 82 EC EE 3B
         :         4A F6 C4 6F 81 23 B1 84 09 C8 E3 1D F4 DC 3B 48
         :         EF 15 9D 05 95 14 04 30 B5 7F 80 FE FE D3 3C 75
         :         75 AD F2 F0 90 5F A6 0C 28 F3 65 48 59 82 7C 49
         :         38 B4 F6 AB 8F 87 39 20 2D D7 3E 2E 00 D4 47 3F
         :         28 9F 5C 9F F4 1F FC 7D 67 C7 46 00 6E 99 04 CD
         :         65
 823  129:       INTEGER
         :         00 A4 5D D6 47 9C 9D DE 45 0F 2F 8B 40 0C 04 BE
         :         13 88 2B 5C 49 A5 73 5A 1E 71 85 26 A3 B6 CE 15
         :         BE 31 DE 5E EA 2F 93 45 AE DB F4 A0 10 D1 E2 93
         :         E0 A7 05 A4 5C 5B EF AD 4C 18 2F 6A B6 CD DD 82
         :         49 BE 23 DB 56 49 23 67 32 6F 78 CC E7 7D F8 8C
         :         BB 69 E0 13 33 D7 C8 4B 69 48 0E 86 61 06 41 6D
         :         99 29 C5 49 2F 41 A1 90 86 0F FB 79 2D F0 E1 96
         :         C1 13 EA F5 1F 9B 58 4E CC 83 18 BB B2 56 AF 52
         :         F9
 955  128:       INTEGER
         :         1A 22 44 A0 5A F8 0F 6F 7D 44 5E 67 03 8F 95 54
         :         A6 56 05 5A 61 9C 7A 94 7D 53 AA 95 EC CA 8F 9E
         :         94 37 25 FF 00 F7 E6 B1 CE F1 45 5D 45 5D 9E C4
         :         31 FC C0 C0 A3 DE 8A F6 E1 48 A8 5B 08 47 2D 42
         :         FC 86 95 A9 88 4C 81 69 45 E6 79 BC 97 68 D0 F3
         :         A9 2B 24 AE 17 AF F0 5A E7 A4 CC 4D 0C 42 61 97
         :         C8 4C F1 44 CF B3 5C C1 9D 49 1E EA 91 EB 13 93
         :         2B 02 63 DF BF 30 86 C0 3F FB 2C 37 D9 A5 23 59
 1086  128:       INTEGER
         :         0E AD DC 66 09 36 F6 A9 55 28 FD C3 47 6D B9 1D
         :         88 15 41 1B A2 23 5A B7 81 4E C8 90 A2 51 50 7E
         :         D9 DF 83 0B 64 DF A9 5F AF 20 DA 65 BC C8 74 F9
         :         E2 00 6E 15 1D 8E DF 47 C6 84 BF 96 F7 44 C9 38
         :         FC B8 70 B5 ED C2 3C BC B6 B3 5B 54 C3 85 66 42
         :         B7 5A 70 99 37 A8 55 C0 F6 96 F5 EF F2 34 8D 3F
         :         A3 56 2E 5D A4 97 79 00 4D 28 3E 35 03 19 41 89
         :         A3 96 A5 45 37 90 84 C1 F5 6E 75 3F 33 24 44 FF
         :       }
         :     }
         :   }

RSA-2048 Public Key ::

  $  dumpasn1 rsa_2048_1_pub.der
  0 290: SEQUENCE {
  4  13:   SEQUENCE {
  6   9:     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
 17   0:     NULL
       :     }
 19 271:   BIT STRING, encapsulates {
 24 266:     SEQUENCE {
 28 257:       INTEGER
       :         00 BF 4C DD D8 6C 13 A2 B2 EB E3 81 53 0C BC 12
       :         19 46 7C 7E 05 27 EF 0A 73 60 39 90 3D 11 00 D7
       :         31 D3 F8 D5 DE 90 92 EF D1 75 B9 0D 3E 46 AC 46
       :         EE 57 12 1A 07 3B 7C 63 08 9B B2 3B B4 0C A8 30
       :         99 16 AD 96 10 FE 1C 2E 30 94 EE 92 A1 6F D8 28
       :         D4 72 80 24 77 CF 50 8A 38 72 DA 3F 9E BD 53 E2
       :         4D FB D3 08 5E 93 F5 49 55 6F AC 03 CF 06 1E 79
       :         DD 86 BB CC F0 4B 5B FC 5D 35 39 77 BA 7C AE 93
       :                 [ Another 129 bytes skipped ]
  289   3:       INTEGER 65537
       :       }
       :     }
       :   }
