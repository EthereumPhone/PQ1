..
    Copyright 2019 NXP


==========================================================
 Supported Features
==========================================================

Generate / Import:
    - ECC:
        - 224-bit
        - 256-bit
        - 384-bit
        - 521-bit
    - RSA:
        - 1024-bit
        - 2048-bit
        - 3072-bit
        - 4096-bit

    - AES:
        - 128-bit
        - 192-bit
        - 256-bit

    - HMAC
        - 64-bit to 512-bit

Export:
    - ECC:
        - 224-bit
        - 256-bit
        - 384-bit
        - 521-bit
    - RSA:
        - 1024-bit
        - 2048-bit
        - 3072-bit
        - 4096-bit

RNG:
    - Get Random number

Sign / Verify:
    - Sign / Verify with ECC
        - Supported digests:
            - DIGEST:SHA1
            - DIGEST:SHA224
            - DIGEST:SHA256
            - DIGEST:SHA384
            - DIGEST:SHA512
    - Sign / Verify with RSA
        - Supported paddings:
            - PADDING:NONE
            - PADDING:PKCS1_V1.5 (SHA1, SHA-224, SHA-256, SHA-384, SHA-512)
            - PADDING:PSS (SHA1, SHA-224, SHA-256, SHA-384, SHA-512)
    - Sign / Verify with HMAC
        - Supported digests:
            - DIGEST:SHA1
            - DIGEST:SHA256
            - DIGEST:SHA384
            - DIGEST:SHA512

Encryption / Decryption:
    - Encrypt / Decrypt with RSA
        - Supported paddings:
            - PADDING:NONE
            - PADDING:PKCS1_V1.5
            - PADDING:OAEP (SHA1)

    - Encrypt / Decrypt with AES
        - Supported block modes:
            - ECB (PADDING:NONE)
            - CBC (PADDING:NONE)
            - CTR (PADDING:NONE)

Delete:
    - Single key
    - All keys

Attestation:
    - Key attestation
