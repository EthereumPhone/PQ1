..
    Copyright 2019,2020,2024-2025 NXP


===========================================================
 Usage Examples
===========================================================

.. highlight:: shell

SE05X: VCOM Interface
===========================================================

Provisioning ECC Pair and Certificate::

    ssscli connect se05x vcom COM5
    ssscli se05x reset
    ssscli set ecc pair 0x20181001 tstData\tls_client_key.pem
    ssscli set cert 0x20181002 tstData\tls_client.cer
    ssscli disconnect

Generating ecc key and retrive public key::

    ssscli connect se05x vcom COM5
    ssscli se05x reset
    ssscli generate ecc 0x20181006 NIST_P256
    ssscli get ecc pair 0x20181006 data\tls_key.pem
    ssscli disconnect

Inject and retrieve certificate::

    ssscli connect se05x vcom COM5
    ssscli set cert 0x20181004 tstData\tls_client.cer
    ssscli get cert 0x20181004 data\extracted_certificate.cer
    ssscli disconnect

Erase key, Inject ecc Key and Sign certificate::

    ssscli connect se05x vcom COM5
    ssscli erase 0x20181001
    ssscli set ecc pair 0x20181001 tstData\tls_client_key.pem
    ssscli sign 0x20181001 tstData\tls_client.cer data\signed_data.pem
    ssscli disconnect

Inject and Retrieve AES key::

    ssscli connect se05x vcom COM5
    ssscli se05x reset
    ssscli set aes 0x40100000 tstData\aes.der
    ssscli get aes 0x40100000 data\extracted_aes_key.cer
    ssscli disconnect

Inject ECC Public Key::

    ssscli connect se05x vcom COM5
    ssscli set ecc pub 0x20181010 tstData\tls_client_key_pub.pem
    ssscli disconnect

Generate RSA Key and Get public key in DER format::

    ssscli connect se05x vcom COM5
    ssscli generate rsa 0x20182001 2048
    ssscli get rsa pub 0x20182001 data\rsa_pub_2048.der --format DER
    ssscli disconnect

Generate ecc Koblitz 256 Key, Sign Binary data and verify::

    ssscli connect se05x vcom COM5
    ssscli generate ecc 12E41001 Secp256k1
    ssscli sign 12E41001 tstData\binary_data.bin signed_data_ecc_secp256k1.pem
    ssscli verify 12E41001 tstData\binary_data.bin signed_data_ecc_secp256k1.pem
    ssscli disconnect

Generate ecc Brainpool192 Key and Sign and verify certificate using SHA512 has algorithm::

    ssscli connect se05x vcom COM5
    ssscli generate ecc 0x2E101501 Brainpool192
    ssscli sign 0x2E101501 tstData\tls_client.cer data\signed_data.pem --hashalgo=SHA512
    ssscli verify 0x2E101501 tstData\tls_client.cer data\signed_data.pem --hashalgo=SHA512
    ssscli disconnect

Read Cert UID of 10 bytes long::

    ssscli connect se05x vcom COM5
    ssscli se05x certuid

Read UID of 18 bytes long::

    ssscli connect se05x vcom COM5
    ssscli se05x uid

Session open with auth type as Platform SCP, generate ecc Brainpool192 Key::

    ssscli connect se05x vcom COM5 --auth_type PlatformSCP --scpkey "c:/_ddm/scpkey.txt"
    ssscli se05x reset
    ssscli generate ecc 2E10D532 Brainpool192
    ssscli disconnect

Generate ecc Koblitz256 key and create reference key::

    ssscli connect se05x vcom COM5
    ssscli generate ecc 7A10D838 Secp256k1
    ssscli refpem ecc pair 7A10D838 data\refkey_secp256k1.pem
    ssscli disconnect

Generate rsa 4096 key and create reference key in pkcs12 format::

    ssscli connect se05x vcom COM5
    ssscli generate rsa 0x70102040 4096
    ssscli refpem rsa pair 0x70102040 rsa_4096_rekey.pfx --password nxp
    ssscli disconnect

Generate ecc Brainpool 256 key and create pkcs12 format reference key extracted to pem format::

    ssscli connect se05x vcom COM5
    ssscli generate ecc 70102050 Brainpool256
    ssscli refpem ecc pair 70102050 ecc_bp256_rekey.pem  --format PKCS12 --password nxp
    ssscli disconnect

Generate ecc ED25519 key and sign certificate::

    ssscli connect se05x vcom COM5
    ssscli generate ecc 70102060 ED_25519
    ssscli sign 70102060 tstData\tls_client.cer data\signed_data_using_ed25519.pem
    ssscli disconnect

Generate ecc MONTH DH 25519 key::

    ssscli connect se05x vcom COM5
    ssscli generate ecc 70102080 ED_25519
    ssscli sign 70102080 tstData\tls_client.cer data\signed_data_using_ed25519.pem
    ssscli disconnect

Perform Encrypt and Decrypt using RSA 2048::

    ssscli connect se05x vcom COM5
    ssscli generate rsa 0x20182001 2048
    ssscli get rsa pub 0x20182001 rsa_pub_2048.pem
    ssscli set rsa pub 0x20184120 rsa_pub_2048.pem
    ssscli encrypt 0x20184120 "Welcome to NXP" rsa_2048_encrypted_data.pem
    ssscli decrypt 0x20182001 rsa_2048_encrypted_data.pem decrypted_data.txt
    ssscli disconnect

Provision and Retrieve Binary data::

    ssscli connect se05x vcom COM5
    ssscli set bin 0x20191005 tstData\binary_data.hex
    ssscli get bin 0x20191005 binary_data.hex
    ssscli disconnect


SE05X: PCSC interface
===========================================================

Provisioning ECC Pair and Certificate::

    ssscli connect se05x pcsc NXP
    ssscli se05x reset
    ssscli set ecc pair 0x20181001 tstData\tls_client_key.pem
    ssscli set cert 0x20181002 tstData\tls_client.cer
    ssscli disconnect

Inject ECC Public Key::

    ssscli connect se05x pcsc NXP
    ssscli set ecc pub 0x20181010 tstData\tls_client_key_pub.pem
    ssscli disconnect


se05x: JRCPV2 interface
===========================================================

Provisioning ECC Pair and Certificate::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli se05x reset
    ssscli set ecc pair 0x20181001 tstData\tls_client_key.pem
    ssscli set cert 0x20181002 tstData\tls_client.cer
    ssscli disconnect

Generating ecc key and retrive public key::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli se05x reset
    ssscli generate ecc 0x40100000 NIST_P256
    ssscli get ecc pair 0x40100000 data\tls_key.pem
    ssscli disconnect

Set and retrieve certificate::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli set cert 0x20181002 tstData\tls_client.cer
    ssscli get cert 0x20181002 data\extracted_certificate.cer
    ssscli disconnect

Erase a key, Inject ecc Key and Sign certificate::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli erase 0x20181001
    ssscli set ecc pair 0x20181001 tstData\tls_client_key.pem
    ssscli sign 0x20181001 tstData\tls_client.cer data\signed_data.pem
    ssscli disconnect

Inject and Retrieve AES key::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli se05x reset
    ssscli set aes 0x40200000 tstData\aes.der
    ssscli get aes 0x40200000 data\extracted_aes_key.cer
    ssscli disconnect

Inject ECC Public Key::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli set ecc pub 0x20181010 tstData\tls_client_key_pub.pem
    ssscli disconnect


Generate RSA Key and Get public key in PEM format::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli generate rsa 0x20182001 2048
    ssscli get rsa pub 0x20182001 data\rsa_pub_2048.pem --format PEM
    ssscli disconnect

Generate ecc Koblitz 256 Key, Sign Binary data and verify::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli generate ecc 12E41001 Secp256k1
    ssscli sign 12E41001 tstData\binary_data.bin signed_data_ecc_secp256k1.pem
    ssscli verify 12E41001 tstData\binary_data.bin signed_data_ecc_secp256k1.pem
    ssscli disconnect

Generate ecc Brainpool192 Key and Sign and verify certificate using SHA512 has algorithm::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli generate ecc 0x2E101501 Brainpool192
    ssscli sign 0x2E101501 tstData\tls_client.cer data\signed_data.pem --hashalgo=SHA512
    ssscli verify 0x2E101501 tstData\tls_client.cer data\signed_data.pem --hashalgo=SHA512
    ssscli disconnect

Read Cert UID of 10 bytes long::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli se05x certuid

Read UID of 18 bytes long::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli se05x uid

Session open with auth type as Platform SCP, generate ecc Brainpool192 Key::

    ssscli connect se05x jrcpv2 127.0.0.1:8050 --auth_type PlatformSCP  --scpkey "c:/_ddm/scpkey.txt"
    ssscli se05x reset
    ssscli generate ecc 2E10D532 Brainpool192
    ssscli disconnect

Generate ecc Koblitz256 key and create reference key::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli generate ecc 7A10D838 Secp256k1
    ssscli refpem ecc pair 7A10D838 data\refkey_secp256k1.pem
    ssscli disconnect

Generate rsa 4096 key and create reference key in pkcs12 format::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli generate rsa 0x70102040 4096
    ssscli refpem rsa pair 0x70102040 rsa_4096_rekey.pfx --password nxp
    ssscli disconnect

Generate ecc Brainpool 256 key and create pkcs12 format reference key extracted to pem format::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli generate ecc 70102050 Brainpool256
    ssscli refpem ecc pair 70102050 ecc_bp256_rekey.pem  --format PKCS12 --password nxp
    ssscli disconnect

Generate ecc ED25519 key and sign certificate::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli generate ecc 70102060 ED_25519
    ssscli sign 70102060 tstData\tls_client.cer data\signed_data_using_ed25519.pem
    ssscli disconnect

Generate ecc MONTH DH 25519 key::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli generate ecc 70102080 ED_25519
    ssscli sign 70102080 tstData\tls_client.cer data\signed_data_using_ed25519.pem
    ssscli disconnect

Perform Encrypt and Decrypt using RSA 2048::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli generate rsa 0x20182001 2048
    ssscli get rsa pub 0x20182001 rsa_pub_2048.pem
    ssscli set rsa pub 0x20184120 rsa_pub_2048.pem
    ssscli encrypt 0x20184120 "Welcome to NXP" rsa_2048_encrypted_data.pem
    ssscli decrypt 0x20182001 rsa_2048_encrypted_data.pem decrypted_data.txt
    ssscli disconnect

Provision and Retrieve Binary data::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli set bin 0x20191005 tstData\binary_data.hex
    ssscli get bin 0x20191005 binary_data.hex
    ssscli disconnect

Get available Free memory ::

    ssscli connect se05x jrcpv2 127.0.0.1:8050
    ssscli se05x getmemory
    ssscli disconnect

MBEDTLS
===========================================================

Portname is to be passed as a existing directory for keystore.

Provisioning ECC Pair and Certificate::

    ssscli connect mbedtls none data
    ssscli set ecc pair 0x20181005 tstData\tls_client_key.pem
    ssscli set cert 0x20181002 tstData\tls_client.cer
    ssscli disconnect

Generating ecc key and retrive public key::

    ssscli connect mbedtls none data
    ssscli generate ecc 0x20181003 NIST_P256
    ssscli get ecc pair 0x20181003 data\tls_key.pem
    ssscli disconnect

Set certificate and retrieve certificate::

    ssscli connect mbedtls none data
    ssscli set cert 0x20181004 tstData\tls_client.cer
    ssscli get cert 0x20181004 data\extracted_certificate.cer
    ssscli disconnect

Erase key, provisioning ecc Key and Sign certificate::

    ssscli connect mbedtls none data
    ssscli erase 0x20181005
    ssscli set ecc pair 0x20181005 tstData\tls_client_key.pem
    ssscli sign 0x20181005 tstData\tls_client.cer data\signed_data.pem
    ssscli disconnect
