@REM Copyright 2019 NXP
@REM
@REM SPDX-License-Identifier: Apache-2.0
@REM
@ECHO OFF
SETLOCAL
    call ..\venv\Scripts\activate.bat
    python cli_commands_list_gen.py
    call ..\venv\Scripts\deactivate.bat
ENDLOCAL
