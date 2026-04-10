# Copyright 2018-2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Mapping from Old to New Value.
#
# Safe handling.  If old and new have same value, just allow it.
# If they are not same, put error to user to use a new value.
# But still set the oldcfg, with value as set by the new
# PTMW_ entries.
#

MACRO(PTMW_MARK_DEPRECATED oldcfg)
    IF(${oldcfg})
        IF("${${oldcfg}}" STREQUAL "${PTMW_${oldcfg}}")
            # OK
        ELSE()
            MESSAGE(SEND_ERROR "'${oldcfg}' is deprecated. Remove it. Use 'PTMW_${oldcfg}")
        ENDIF()
        #SET(PTMW_${oldcfg} ${${oldcfg}} CACHE STRING "Set from deprecated ${oldcfg}" FORCE)
    ENDIF()
    SET(${oldcfg} ${PTMW_${oldcfg}})
endmacro()

PTMW_MARK_DEPRECATED(A71CH_AUTH)
PTMW_MARK_DEPRECATED(Applet)
PTMW_MARK_DEPRECATED(FIPS)
PTMW_MARK_DEPRECATED(Host)
PTMW_MARK_DEPRECATED(HostCrypto)
PTMW_MARK_DEPRECATED(mbedTLS_ALT)
PTMW_MARK_DEPRECATED(RTOS)
PTMW_MARK_DEPRECATED(SBL)
PTMW_MARK_DEPRECATED(SCP)
PTMW_MARK_DEPRECATED(SE05X_Auth)
PTMW_MARK_DEPRECATED(SE05X_Ver)
PTMW_MARK_DEPRECATED(SMCOM)
PTMW_MARK_DEPRECATED(Log)
