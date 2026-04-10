@echo off

@REM Copyright 2019 NXP
@REM
@REM SPDX-License-Identifier: Apache-2.0
@REM

IF NOT "%~1" == "" (
    IF "%~1"=="prime192v1" (
        SET P_curve=curves=secp192r1
    ) ELSE IF "%~1"=="secp224r1" (
        SET P_curve=curves=secp224r1
    ) ELSE IF "%~1"=="prime256v1" (
        SET P_curve=curves=secp256r1
    ) ELSE IF "%~1"=="secp384r1" (
        SET P_curve=curves=secp384r1
    ) ELSE IF "%~1"=="secp521r1" (
        SET P_curve=curves=secp521r1
    ) ELSE IF "%~1"=="brainpoolP256r1" (
        SET P_curve=curves=brainpoolP256r1
    ) ELSE IF "%~1"=="brainpoolP384r1" (
        SET P_curve=curves=brainpoolP384r1
    ) ELSE IF "%~1"=="brainpoolP512r1" (
        SET P_curve=curves=brainpoolP512r1
    ) ELSE IF "%~1"=="secp192k1" (
        SET P_curve=curves=secp192k1
    ) ELSE IF "%~1"=="secp224k1" (
        SET P_curve=curves=secp224k1
    ) ELSE IF "%~1"=="secp256k1" (
        SET P_curve=curves=secp256k1
    ) ELSE IF "%~1"=="rsa2048" (
        SET P_curve=
    ) ELSE IF "%~1"=="rsa3072" (
        SET P_curve=
    ) ELSE IF "%~1"=="rsa4096" (
        SET P_curve=
    ) ELSE (
        echo %~1 is not a supported key type
        goto :EXAMPLE_USAGE
    )
) ELSE (
    goto :EXAMPLE_USAGE
)

IF NOT "%~2" == "" (
    @REM add check for valid cipher suite
) ELSE (
    goto :EXAMPLE_USAGE
)

IF NOT "%~3" == "" (
    @REM add check for valid connection string
    goto :START_CLIENT
) ELSE (
    goto :EXAMPLE_USAGE
)

:START_CLIENT
call %~dp0_setup.bat %~1
SET P_ciphersuite=force_ciphersuite=%~2
echo ..\..\..\..\tools\mbedtls_ex_sss_ssl2_client.exe %P_MBED% %P_MBED_CLIENT% %P_ciphersuite% %P_curve% %~3
..\..\..\..\tools\mbedtls_ex_sss_ssl2_client.exe %P_MBED% %P_MBED_CLIENT% %P_ciphersuite% %P_curve% %~3
goto :EOF

:EXAMPLE_USAGE
    echo Please provide as first argument:  keytype
    echo Please provide as second argument:  cipher_suite
    echo Please provide as third argument:  connection_string
    echo Example invocations
    echo %~nx0 prime256v1 TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA 127.0.0.1:8050
    echo %~nx0 rsa2048 TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256 COM1
    echo Supported key types:
    echo   prime192v1, secp224r1, prime256v1, secp384r1, secp521r1
    echo   brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
    echo   secp192k1, secp224k1, secp256k1
    echo   rsa2048, rsa3072, rsa4096
    echo Supported cipher suites:
    echo ---Add cipher suites---
    pause
    goto :EOF
