# Copyright 2019 NXP
#
# This software is owned or controlled by NXP and may only be used
# strictly in accordance with the applicable license terms.  By expressly
# accepting such terms or by downloading, installing, activating and/or
# otherwise using the software, you are agreeing that you have read, and
# that you agree to comply with and are bound by, such license terms.  If
# you do not agree to be bound by the applicable license terms, then you
# may not retain, install, activate or otherwise use the software.
#


PROJECT(JRCPProxyConsole)

FILE(GLOB soruces
    *.cpp
    *.c
)

add_executable(JRCPProxyConsole ${soruces})

target_include_directories(JRCPProxyConsole PUBLIC
    *.hpp
    *.h
)

target_link_libraries(JRCPProxyConsole PUBLIC

)

IF("Windows" STREQUAL "${CMAKE_SYSTEM_NAME}")
    target_link_libraries(JRCPProxyConsole
        a7x_utils ws2_32)
ENDIF()

