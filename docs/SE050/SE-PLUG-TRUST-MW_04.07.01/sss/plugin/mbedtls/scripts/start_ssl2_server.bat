@echo off

@REM Copyright 2019 NXP
@REM
@REM SPDX-License-Identifier: Apache-2.0
@REM

IF NOT "%~1" == "" (
    IF "%~1"=="prime192v1" goto :START_SERVER
    IF "%~1"=="secp224r1" goto :START_SERVER
    IF "%~1"=="prime256v1" goto :START_SERVER
    IF "%~1"=="secp384r1" goto :START_SERVER
    IF "%~1"=="secp521r1" goto :START_SERVER
    IF "%~1"=="brainpoolP256r1" goto :START_SERVER
    IF "%~1"=="brainpoolP384r1" goto :START_SERVER
    IF "%~1"=="brainpoolP512r1" goto :START_SERVER
    IF "%~1"=="secp192k1" goto :START_SERVER
    IF "%~1"=="secp224k1" goto :START_SERVER
    IF "%~1"=="secp256k1" goto :START_SERVER
    IF "%~1"=="rsa2048" goto :START_SERVER
    IF "%~1"=="rsa3072" goto :START_SERVER
    IF "%~1"=="rsa4096" goto :START_SERVER
    goto :SUPPORTED_KEYTYPES

) ELSE (
    goto :SUPPORTED_KEYTYPES
)

:START_SERVER
call %~dp0_setup.bat %~1
..\..\..\..\tools\mbedtls_ex_orig_ssl_server2.exe %P_MBED% %P_MBED_SERVER%
goto :EOF

:SUPPORTED_KEYTYPES
    echo Please provide as first argument:  keytype
    echo Example invocation
    echo   %~nx0 prime256v1
    echo Supported key types:
    echo   prime192v1, secp224r1, prime256v1, secp384r1, secp521r1
    echo   brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
    echo   secp160k1, secp192k1, secp224k1, secp256k1
    echo   rsa2048, rsa3072, rsa4096
    pause
    goto :EOF
