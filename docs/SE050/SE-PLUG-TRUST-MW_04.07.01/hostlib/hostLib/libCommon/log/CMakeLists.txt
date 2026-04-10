PROJECT(mwlog)

FILE(
    GLOB
    source_files
    *.h
)

IF(SSS_HAVE_HOST_ANDROID)
    FILE(
        GLOB
        nxLog_sources
        nxLog_Android.c
    )
ELSEIF(NOT SSS_HAVE_LOG_SEGGERRTT)
    IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS)
        FILE(
            GLOB
            nxLog_sources
            nxLog.c
        )
    ENDIF()
    IF(SSS_HAVE_HOST_LPCXPRESSO55S_NS)
        FILE(
            GLOB
            nxLog_sources
            nxLog_lpc55s_ns.c
        )
    ENDIF()
ENDIF()

IF(BUILD_SHARED_LIBS)
    ADD_LIBRARY(${PROJECT_NAME} SHARED ${source_files} ${nxLog_sources})
ELSE()
    ADD_LIBRARY(${PROJECT_NAME} ${source_files} ${nxLog_sources})
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC .
    PUBLIC ../../platform/inc
    PUBLIC ../infra
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S_NS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} lpc55s_veneer)
ENDIF()

# UWB MW does not have board,
# Only P&T MW has it.
IF(NOT (UWBIOT_OS_FREERTOS OR UWBIOT_OS_NATIVE))
    IF(SSS_HAVE_KSDK)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} board)
    ENDIF()
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-kernel)
ENDIF()

IF(CMAKE_COMPILER_IS_GNUCC AND (NOT SSS_HAVE_KSDK))
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} -lpthread)
ENDIF()

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
    INSTALL(
        DIRECTORY .
        DESTINATION ${SIMW_INSTALL_INC_DIR}
        FILES_MATCHING
        PATTERN "*.h"
    )
ENDIF()
