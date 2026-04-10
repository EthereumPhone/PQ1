#
# Copyright 2018-2022, 2024-2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

"""License text"""

import sys
from sss.read_id_list import ReadIDList
from sss.get_memory import GetMemory
from sss.se05x import Se05x
import sss.sss_api as apis
from .cli import se05x, pass_context, session_open, session_close, \
    log_traceback, TIME_OUT


@se05x.command('reset', short_help='Reset SE05X')
@pass_context
def reset(cli_ctx):
    """
    Resets the SE05X Secure Module to the initial state.

    This command uses ``Se05x_API_DeleteAll_Iterative`` API of the SE05X
    MW to iterately delete objects provisioned inside the SE.  Because of this,
    some objects are purposefully skipped from deletion.

    It does not use the low level SE05X API ``Se05x_API_DeleteAll``

    For more information, see documentation/implementation of the
    ``Se05x_API_DeleteAll_Iterative`` API.

    """
    try:
        session_open(cli_ctx)
        se05x_obj = Se05x(cli_ctx.session)
        se05x_obj.debug_reset()
        status = apis.kStatus_SSS_Success
    except Exception as exc:  # pylint: disable=broad-except
        log_traceback(cli_ctx, exc)
        status = apis.kStatus_SSS_Fail
    session_status = session_close(cli_ctx)
    if status == apis.kStatus_SSS_Success and session_status == apis.kStatus_SSS_Success:
        ret_value = 0
    else:
        ret_value = 1
    sys.exit(ret_value)


@se05x.command('uid', short_help='Get SE05X Unique ID (18 bytes)')
@pass_context
def uid(cli_ctx):
    """ Get 18 bytes Unique ID from the SE05X Secure Module."""
    try:
        session_open(cli_ctx)
        se05x_obj = Se05x(cli_ctx.session)
        unique_id = se05x_obj.get_unique_id()
        cli_ctx.log("Unique ID: %s" % (unique_id,))
        status = apis.kStatus_SSS_Success
    except Exception as exc:  # pylint: disable=broad-except
        log_traceback(cli_ctx, exc)
        status = apis.kStatus_SSS_Fail
    session_status = session_close(cli_ctx)
    if status == apis.kStatus_SSS_Success and session_status == apis.kStatus_SSS_Success:
        ret_value = 0
    else:
        ret_value = 1
    sys.exit(ret_value)


@se05x.command('certuid', short_help='Get SE05X Cert Unique ID (10 bytes)')
@pass_context
def certuid(cli_ctx):
    """ Get 10 bytes Cert Unique ID from the SE05X Secure Module.
    The cert uid is a subset of the Secure Module Unique Identifier"""
    try:
        session_open(cli_ctx)
        se05x_obj = Se05x(cli_ctx.session)
        cert_uid = se05x_obj.get_cert_unique_id()
        cli_ctx.log("Cert UID: %s" % (cert_uid,))
        status = apis.kStatus_SSS_Success
    except Exception as exc:  # pylint: disable=broad-except
        log_traceback(cli_ctx, exc)
        status = apis.kStatus_SSS_Fail
    session_status = session_close(cli_ctx)
    if status == apis.kStatus_SSS_Success and session_status == apis.kStatus_SSS_Success:
        ret_value = 0
    else:
        ret_value = 1
    sys.exit(ret_value)

@se05x.command('getmemory', short_help='Get available memory')
@pass_context
def getmemory(cli_ctx):
    """ Get amount of free memory """
    try:
        session_open(cli_ctx)
        memory_obj = GetMemory(cli_ctx.session)
        memory_type_list=[apis.kSE05x_MemoryType_PERSISTENT,
                 apis.kSE05x_MemoryType_TRANSIENT_RESET,
                 apis.kSE05x_MemoryType_TRANSIENT_DESELECT]
        for mem_type in memory_type_list:
            memory_obj.do_get_available_memory(mem_type)
            status = apis.kStatus_SSS_Success
    except Exception as exc:  # pylint: disable=broad-except
        log_traceback(cli_ctx, exc)
        status = apis.kStatus_SSS_Fail
    session_status = session_close(cli_ctx)
    if status == apis.kStatus_SSS_Success and session_status == apis.kStatus_SSS_Success:
        ret_value = 0
    else:
        ret_value = 1
    sys.exit(ret_value)

@se05x.command('readidlist', short_help='Read contents of SE050')
@pass_context
def readidlist(cli_ctx):
    """ Read contents of SE050"""
    try:
        session_open(cli_ctx)
        read_id_list_obj = ReadIDList(cli_ctx.session)
        read_id_list_obj.do_read_id_list()
        status = apis.kStatus_SSS_Success
    except Exception as exc:  # pylint: disable=broad-except
        log_traceback(cli_ctx, exc)
        status = apis.kStatus_SSS_Fail
    session_status = session_close(cli_ctx)
    if status == apis.kStatus_SSS_Success and session_status == apis.kStatus_SSS_Success:
        ret_value = 0
    else:
        ret_value = 1
    sys.exit(ret_value)


@se05x.command('getrng', short_help='Get SE05X random number (10 bytes)')
@pass_context
def getrng(cli_ctx):
    """ Get 10 bytes random number from the SE05X Secure Module."""
    try:
        session_open(cli_ctx)
        se05x_obj = Se05x(cli_ctx.session)
        rngdata = se05x_obj.get_random_number()
        cli_ctx.log("Random number: %s" % (rngdata,))
        status = apis.kStatus_SSS_Success
    except Exception as exc:  # pylint: disable=broad-except
        log_traceback(cli_ctx, exc)
        status = apis.kStatus_SSS_Fail
    session_status = session_close(cli_ctx)
    if status == apis.kStatus_SSS_Success and session_status == apis.kStatus_SSS_Success:
        ret_value = 0
    else:
        ret_value = 1
    sys.exit(ret_value)
