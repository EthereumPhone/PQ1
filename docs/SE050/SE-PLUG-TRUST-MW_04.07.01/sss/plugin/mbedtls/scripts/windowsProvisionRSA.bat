@echo off

SETLOCAL

@REM Copyright 2018,2019,2025 NXP
@REM
@REM SPDX-License-Identifier: Apache-2.0
@REM
@REM
@REM Use openssl and ssscli to provision attached secure element
@REM Note-1: Connect via JRCP_v2 (default) or JRCP_v1 (aka RJCT) server
@REM Note-2: Set IOT_SE to either se050
@REM
@REM The script takes two mandatory parameters:
@REM    ec_keytype
@REM    the ip_address:port of the JRCP server to connect to
@REM e.g.:
@REM    windowsProvision.bat prime256v1 192.168.2.75:8050
@REM
@REM An optional third parameter specifies the secure element targeted.
@REM The default secure element is se050

@set IOT_SE=se050

@REM Handle parameters passed, do a sanity check before proceeding
IF NOT "%~1" == "" (
    IF "%~1"=="rsa1024" (
        echo MbedTLS default configuration is RSA bit len greater or equal to 2048.
        goto :SUPPORTED_KEYTYPES
    ) ELSE IF "%~1"=="rsa2048" (
        @set RSA_KEY_TYPE=%~1
        @set RSA_KEY_LEN=2048
    ) ELSE IF "%~1"=="rsa3072" (
        @set RSA_KEY_TYPE=%~1
        @set RSA_KEY_LEN=3072
    ) ELSE IF "%~1"=="rsa4096" (
        @set RSA_KEY_TYPE=%~1
        @set RSA_KEY_LEN=4096
    ) ELSE (
        echo %~1 is not a supported key type
        goto :SUPPORTED_KEYTYPES
    )
) ELSE (
    goto :SUPPORTED_KEYTYPES
)

IF "%~2" == "jrcpv2" (
    IF NOT "%~3" == "" (
        @SET CONNECTION_TYPE=%~2
        @SET CONNECTION_PARAM=%~3
    ) ELSE (
        echo Please provide ip_address:port of JRCP server as third argument
        pause
        goto :EOF
    )
) ELSE IF "%~2" == "vcom" (
    IF NOT "%~3" == "" (
        @SET CONNECTION_TYPE=%~2
        @SET CONNECTION_PARAM=%~3
    ) ELSE (
        echo Please provide port name as third argument
        pause
        goto :EOF
    )
) ELSE (
    echo Invalid argumenets
    pause
    goto :EOF
)

IF NOT "%~4" == "" (
    @SET IOT_SE=%~4
)

@set KEY_DIR=keys/%RSA_KEY_TYPE%
@set KEY_DIR_DOS=keys\%RSA_KEY_TYPE%

@cd /d %~dp0
@set OPENSSL=..\..\..\..\ext\openssl\bin\openssl.exe
@set OPENSSL_CONF=..\..\..\..\ext\openssl\ssl\openssl.cnf

if not exist ..\%KEY_DIR_DOS%\NUL (
    echo "Folder ..\%KEY_DIR_DOS% does not exist, creating it"
    mkdir ..\%KEY_DIR_DOS%
)

@set SUBJECT="/C=GB/ST=ABC/L=ABC/O=Global Security/OU=IT Department/CN=localhost"
@set ROOT_CA=tls_rootca
@set CLIENT_FILE=tls_client
@set SERVER_FILE=tls_server
@set DIR_PATH=..\keys\%RSA_KEY_TYPE%
@set SHA_TYPE=-sha256

@REM @set pss_option=-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 -sha256
@REM goto :PROVISION

%OPENSSL% genrsa -out %DIR_PATH%\%ROOT_CA%_key.pem %RSA_KEY_LEN% %pss_option%
%OPENSSL% req -x509 -new -nodes -key %DIR_PATH%\%ROOT_CA%_key.pem %SHA_TYPE% -days 1000 -out %DIR_PATH%\%ROOT_CA%.pem -subj %SUBJECT% %pss_option%
%OPENSSL% x509 -outform der -in %DIR_PATH%\%ROOT_CA%.pem -out %DIR_PATH%\%ROOT_CA%.cer %pss_option%
%OPENSSL% x509 -pubkey -noout -in %DIR_PATH%\%ROOT_CA%.pem > %DIR_PATH%\%ROOT_CA%_pub_key.pem %pss_option%

%OPENSSL% genrsa -out %DIR_PATH%\%CLIENT_FILE%_key.pem %RSA_KEY_LEN% %pss_option%
%OPENSSL% req -new -key %DIR_PATH%\%CLIENT_FILE%_key.pem -out %DIR_PATH%\%CLIENT_FILE%_key.csr -subj %SUBJECT% %pss_option%
%OPENSSL% x509 -req -in %DIR_PATH%\%CLIENT_FILE%_key.csr -CA %DIR_PATH%\%ROOT_CA%.pem -CAkey %DIR_PATH%\%ROOT_CA%_key.pem -CAcreateserial -out %DIR_PATH%\%CLIENT_FILE%.pem -days 1000 %SHA_TYPE% %pss_option%
%OPENSSL% x509 -outform der -in %DIR_PATH%\%CLIENT_FILE%.pem -out %DIR_PATH%\%CLIENT_FILE%.cer %pss_option%

%OPENSSL% genrsa -out %DIR_PATH%\%SERVER_FILE%_key.pem %RSA_KEY_LEN% %pss_option%
%OPENSSL% req -new -key %DIR_PATH%\%SERVER_FILE%_key.pem -out %DIR_PATH%\%SERVER_FILE%_key.csr -subj %SUBJECT% %pss_option%
%OPENSSL% x509 -req -in %DIR_PATH%\%SERVER_FILE%_key.csr -CA %DIR_PATH%\%ROOT_CA%.pem -CAkey %DIR_PATH%\%ROOT_CA%_key.pem -CAcreateserial -out %DIR_PATH%\%SERVER_FILE%.pem -days 1000 %pss_option%
%OPENSSL% x509 -outform der -in %DIR_PATH%\%SERVER_FILE%.pem -out %DIR_PATH%\%SERVER_FILE%.cer %pss_option%


:PROVISION

@REM Provision using ssscli tool

IF "%CONNECTION_TYPE%" == "vcom" (
    @REM Use precompiled ssscli binary for vcom connection
    @set ssscli=..\..\..\..\binaries\PCWindows\ssscli\ssscli.exe
) ELSE (
    @REM Use ssscli from vertualenv setup
    @set ssscli=ssscli
)

%ssscli% -v disconnect
if %ERRORLEVEL% GEQ 1 GOTO :CONFIG_TOOL

if "%IOT_SE%" == "se05x" (
    %ssscli% -v connect se05x %CONNECTION_TYPE% %CONNECTION_PARAM%
    %ssscli% -v se05x reset
) else (
    echo %IOT_SE% is not supported as secure element
    goto :EOF
)


@set client_cert_key_id=20181002
%ssscli% -v set cert %client_cert_key_id% %DIR_PATH%\%CLIENT_FILE%.pem
if %ERRORLEVEL% GEQ 1 GOTO :CONFIG_TOOL

@set client_key_pair_id=20181001
%ssscli% -v set rsa pair %client_key_pair_id% %DIR_PATH%\%CLIENT_FILE%_key.pem
if %ERRORLEVEL% GEQ 1 GOTO :CONFIG_TOOL

@set root_cer_pub_id=7DCCBB22
%ssscli% -v set rsa pub %root_cer_pub_id% %DIR_PATH%\%ROOT_CA%_pub_key.pem
if %ERRORLEVEL% GEQ 1 GOTO :CONFIG_TOOL


echo ## Program completed successfully
goto :EOF


@REM Usage
:SUPPORTED_KEYTYPES
    echo Please provide as first argument:  rsa_keytype
    echo 'Please provide as second argument: connection type - vcom, jrcpv2'
    echo 'Please provide as third argument: connection parameter  - eg. COM3 , 127.0.0.1:8050'
    echo 'Please provide as fourth argument: platform <se05x / mbedtls>. Default se05x '
    echo Example invocations
    echo   %~nx0 rsa2048 jrcpv2 127.0.0.1:8050
    echo   %~nx0 rsa2048 vcom COM3
    echo Supported key types:
    echo   rsa2048
    echo   rsa3072
    echo   rsa4096
    pause
    goto :EOF

@REM Error Handling
:OPENSSL_FAILED
    echo ### OpenSSL failed
    pause
    goto :EOF

:CONFIG_TOOL
    echo ### No configuration tool (ssscli)
    pause
    goto :EOF
