@echo off

SETLOCAL

@REM Copyright 2019,2025 NXP
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
    IF "%~1"=="prime192v1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="NIST_P192"
    ) ELSE IF "%~1"=="secp224r1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="NIST_P224"
    ) ELSE IF "%~1"=="prime256v1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="NIST_P256"
    ) ELSE IF "%~1"=="secp384r1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="NIST_P384"
    ) ELSE IF "%~1"=="secp521r1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="NIST_P521"
    ) ELSE IF "%~1"=="brainpoolP256r1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="Brainpool256"
    ) ELSE IF "%~1"=="brainpoolP384r1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="Brainpool384"
    ) ELSE IF "%~1"=="brainpoolP512r1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="Brainpool512"
    ) ELSE IF "%~1"=="secp192k1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="Secp192k1"
    ) ELSE IF "%~1"=="secp224k1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="Secp224k1"
    ) ELSE IF "%~1"=="secp256k1" (
        @set EC_KEY_TYPE=%~1
        @set PYCLI_EC_KEY_TYPE="Secp256k1"
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

@set KEY_DIR=keys/%EC_KEY_TYPE%
@set KEY_DIR_DOS=keys\%EC_KEY_TYPE%

@cd /d %~dp0
@set OPENSSL=..\..\..\..\ext\openssl\bin\openssl.exe
@set OPENSSL_CONF=..\..\..\..\ext\openssl\ssl\openssl.cnf

if not exist ..\%KEY_DIR_DOS%\NUL (
    echo "Folder ..\%KEY_DIR_DOS% does not exist, creating it"
    mkdir ..\%KEY_DIR_DOS%
)

@set ROOT_CA=tls_rootca
@set CLIENT_FILE=tls_client
@set SERVER_FILE=tls_server
@set DIR_PATH=..\keys\%EC_KEY_TYPE%

@set ROOT_CA_CER=%DIR_PATH%\%ROOT_CA%.cer
@SET ROOT_CA_SR1=%DIR_PATH%\%ROOT_CA%.srl
@set KEY_TYPE_FILE=%DIR_PATH%\%EC_KEY_TYPE%.pem
@set ROOT_CA_KEY_PEM=%DIR_PATH%\%ROOT_CA%_key.pem
@set ROOT_CA_KEY_PUBLIC_PEM=%DIR_PATH%\%ROOT_CA%_pub_key.pem
@set ROOT_CA_KEY_DER=%DIR_PATH%\%ROOT_CA%_key.der
@set CLIENT_KEY_PEM=%DIR_PATH%\%CLIENT_FILE%_key.pem
@set CLIENT_KEY_PUBLIC_PEM=%DIR_PATH%\%CLIENT_FILE%_key_pub.pem
@set CLIENT_CER=%DIR_PATH%\%CLIENT_FILE%.cer
@set SERVER_KEY_PEM=%DIR_PATH%\%SERVER_FILE%_key.pem
@set SERVER_CSR=%DIR_PATH%\%SERVER_FILE%.csr
@set SERVER_CERTIFICATE=%DIR_PATH%\%SERVER_FILE%.cer

%OPENSSL% ecparam -name %EC_KEY_TYPE% -out %KEY_TYPE_FILE%
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED

@REM Conditionally create CA key
%OPENSSL% ecparam -in %KEY_TYPE_FILE% -genkey -noout -out %ROOT_CA_KEY_PEM%
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED
%OPENSSL% ec -in %ROOT_CA_KEY_PEM% -text -noout
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED
%OPENSSL% ec -in %ROOT_CA_KEY_PEM% -outform DER -out %ROOT_CA_KEY_DER%
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED
@REM Extract public part
%OPENSSL% ec -in %ROOT_CA_KEY_PEM% -pubout -out %ROOT_CA_KEY_PUBLIC_PEM%
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED


@REM create CA certificates
%OPENSSL% req -x509 -new -nodes -key %ROOT_CA_KEY_PEM% -subj "/C=BE/ST=VlaamsBrabant/L=Leuven/O=NXP-Demo-CA/OU=Demo-Unit/CN=localhost" -days 2800 -out %ROOT_CA_CER% -config %OPENSSL_CONF%
%OPENSSL% x509 -in %ROOT_CA_CER% -text -noout

@REM Create client key and extract public part
%OPENSSL% ecparam -in %KEY_TYPE_FILE% -genkey -out %CLIENT_KEY_PEM%
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED
%OPENSSL% ec -in %CLIENT_KEY_PEM% -text -noout
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED
%OPENSSL% ec -in %CLIENT_KEY_PEM% -pubout -out %CLIENT_KEY_PUBLIC_PEM%
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED

@REM Now create CSR
%OPENSSL% req -new -key %CLIENT_KEY_PEM% -subj "/C=BE/ST=VlaamsBrabant/L=Leuven/O=NXP-Demo-CA/OU=Demo-Unit/CN=localhost" -out %CLIENT_CER% -config %OPENSSL_CONF%
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED
%OPENSSL% req -in %CLIENT_CER% -text -config %OPENSSL_CONF%
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED

IF EXIST %ROOT_CA_SR1% (
    @echo ">> %ROOT_CA_SR1% already exists, use it"
    @SET x509_serial=-CAserial %ROOT_CA_SR1%
) ELSE (
    @echo ">> no %ROOT_CA_SR1% found, create it"
    @SET x509_serial=-CAserial %ROOT_CA_SR1% -CAcreateserial
)

@REM Create CA signed client certificate
%OPENSSL% x509 -req -sha256 -days 2800 -in %CLIENT_CER% %x509_serial% -CA %ROOT_CA_CER% -CAkey %ROOT_CA_KEY_PEM% -out %CLIENT_CER%
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED
%OPENSSL% x509 -in %CLIENT_CER% -text -noout
if %ERRORLEVEL% GEQ 1 GOTO :OPENSSL_FAILED

@REM Conditionally create server key
%OPENSSL% ecparam -in %KEY_TYPE_FILE% -genkey -out %SERVER_KEY_PEM%
%OPENSSL% ec -in %SERVER_KEY_PEM% -text -noout


@REM Create CSR anew
%OPENSSL% req -new -key %SERVER_KEY_PEM% -subj "/C=BE/ST=VlaamsBrabant/L=Leuven/O=NXP-Demo-CA/OU=Demo-Unit/CN=localhost" -out %SERVER_CSR% -config %OPENSSL_CONF%
%OPENSSL% req -in %SERVER_CSR% -text -noout -config %OPENSSL_CONF%


@REM Always create a CA signed server certificate
%OPENSSL% x509 -req -sha256 -days 2800 -in %SERVER_CSR% %x509_serial% -CA %ROOT_CA_CER% -CAkey %ROOT_CA_KEY_PEM% -out %SERVER_CERTIFICATE%
%OPENSSL% x509 -in %SERVER_CERTIFICATE% -text -noout

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
    echo %ssscli% -v connect se05x %CONNECTION_TYPE% %CONNECTION_PARAM%
    %ssscli% -v connect se05x %CONNECTION_TYPE% %CONNECTION_PARAM%
    %ssscli% -v se05x reset
) else (
    echo %IOT_SE% is not supported as secure element
    goto :EOF
)


@set client_cert_key_id=20181002
%ssscli% -v set cert %client_cert_key_id% %CLIENT_CER%
if %ERRORLEVEL% GEQ 1 GOTO :CONFIG_TOOL

@set client_key_pair_id=20181001
%ssscli% -v set ecc pair %client_key_pair_id% %CLIENT_KEY_PEM%
if %ERRORLEVEL% GEQ 1 GOTO :CONFIG_TOOL

@set root_cer_pub_id=7DCCBB22
%ssscli% -v set ecc pub %root_cer_pub_id% %ROOT_CA_KEY_PUBLIC_PEM%
if %ERRORLEVEL% GEQ 1 GOTO :CONFIG_TOOL


echo ## Program completed successfully
goto :EOF


@REM Usage
:SUPPORTED_KEYTYPES
    echo Please provide as first argument:  ec_keytype
    echo 'Please provide as second argument: connection type - vcom, jrcpv2'
    echo 'Please provide as third argument: connection parameter  - eg. COM3 , 127.0.0.1:8050'
    echo 'Please provide as fourth argument: Iot SE  - eg. se05x , Default:se05x'
    echo Example invocations
    echo   %~nx0 prime256v1 jrcpv2 127.0.0.1:8050
    echo Supported key types:
    echo   prime192v1
    echo   secp224r1
    echo   prime256v1
    echo   secp384r1
    echo   secp521r1
    echo   brainpoolP256r1
    echo   brainpoolP384r1
    echo   brainpoolP512r1
    echo   secp192k1
    echo   secp224k1
    echo   secp256k1
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
