#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

ADD_SUBDIRECTORY(sems_lite_ex_update)

IF(SSS_HAVE_HOST_LINUX_LIKE OR SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_DARWIN)
    ADD_SUBDIRECTORY(sems_lite_cli_app)
ENDIF()
