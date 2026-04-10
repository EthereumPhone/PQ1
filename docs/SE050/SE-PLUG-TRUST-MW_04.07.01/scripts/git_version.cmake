# Check Git VERSION

FIND_PACKAGE(Git)

MACRO(
    GET_CMD_SHA1
    THE_DIR
    THE_VAR
)
    EXECUTE_PROCESS(
        COMMAND ${GIT_EXECUTABLE}
                rev-parse HEAD
        WORKING_DIRECTORY "${THE_DIR}"
        OUTPUT_VARIABLE
            "BUILD_GIT_VERSION_${THE_VAR}_SHA1"
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    STRING(
        SUBSTRING
            "${BUILD_GIT_VERSION_${THE_VAR}_SHA1}"
            0
            16
            BUILD_GIT_VERSION_${THE_VAR}_SHA1
    )
ENDMACRO()

MACRO(
    GET_CMD_DIRTY
    THE_DIR
    THE_VAR
)
    EXECUTE_PROCESS(
        COMMAND ${GIT_EXECUTABLE} diff
                --quiet
        WORKING_DIRECTORY "${THE_DIR}"
        RESULT_VARIABLE "DIFF_STATUS"
    )
    IF(
        "${DIFF_STATUS}"
        EQUAL
        "0"
    )
        # Passed
        SET(
            BUILD_GIT_VERSION_${THE_VAR}_SZ_DIRTY
            ""
        )
        SET(
            BUILD_GIT_VERSION_${THE_VAR}_IS_DIRTY
            0
        )
    ELSE()
        SET(
            BUILD_GIT_VERSION_${THE_VAR}_SZ_DIRTY
            "-dirty"
        )
        SET(
            BUILD_GIT_VERSION_${THE_VAR}_IS_DIRTY
            1
        )
    ENDIF()
ENDMACRO()

MACRO(
    GET_CMD_BRANCH
    THE_DIR
    THE_VAR
)
    EXECUTE_PROCESS(
        COMMAND
            ${GIT_EXECUTABLE} rev-parse
            --abbrev-ref HEAD
        WORKING_DIRECTORY "${THE_DIR}"
        OUTPUT_VARIABLE
            "BUILD_GIT_VERSION_${THE_VAR}_BRANCH"
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
ENDMACRO()


MACRO(
    GET_DESCRIBE
    THE_DIR
    THE_VAR
)
    EXECUTE_PROCESS(
        COMMAND
            ${GIT_EXECUTABLE} describe
        WORKING_DIRECTORY "${THE_DIR}"
        OUTPUT_VARIABLE
            "BUILD_GIT_VERSION_${THE_VAR}_DESCRIBE"
        ERROR_QUIET
        RESULT_VARIABLE "DESCRIBE_STATUS"
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    IF(
        "${DESCRIBE_STATUS}"
        EQUAL
        "0"
    )
        # Passed
    ELSE()
        SET(
            BUILD_GIT_VERSION_${THE_VAR}_DESCRIBE
            "-"
        )
    ENDIF()
ENDMACRO()

MACRO(
    GET_CMD_TAG
    THE_DIR
    THE_VAR
)
    EXECUTE_PROCESS(
        COMMAND
            ${GIT_EXECUTABLE} describe
            --exact-match --tags
        WORKING_DIRECTORY "${THE_DIR}"
        OUTPUT_VARIABLE
            "BUILD_GIT_VERSION_${THE_VAR}_TAG"
        ERROR_QUIET
        RESULT_VARIABLE "TAG_STATUS"
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    IF(
        "${TAG_STATUS}"
        EQUAL
        "0"
    )
        # Passed
    ELSE()
        SET(
            BUILD_GIT_VERSION_${THE_VAR}_TAG
            "-"
        )
    ENDIF()
ENDMACRO()

MACRO(
    GET_BOARD_INFO
)

    SET(BUILD_BOARD_INFO "${PTMW_Host}")

ENDMACRO()

MACRO(GET_ALL_GIT_VERSIONS)
    MESSAGE(
        STATUS
            "Using GIT to check versions"
    )

    GET_CMD_SHA1(
        "${CMAKE_SOURCE_DIR}" "TOP"
    )

    GET_CMD_DIRTY(
        "${CMAKE_SOURCE_DIR}" "TOP"
    )

    GET_CMD_BRANCH(
        "${CMAKE_SOURCE_DIR}" "TOP"
    )

    GET_CMD_TAG(
        "${CMAKE_SOURCE_DIR}" "TOP"
    )

    GET_DESCRIBE(
        "${CMAKE_SOURCE_DIR}" "TOP"
    )
    GET_BOARD_INFO(
        "${PTMW_Host}"
    )
ENDMACRO()

MACRO(
    GET_ALL_GIT_VERSIONS_STUB
    warning_message
)
    MESSAGE(
        STATUS
            "${warning_message}. Using STUB Values for GIT Version"
    )
    SET(BUILD_GIT_VERSION_TOP_SHA1
        "0000000000000000"
    )

    SET(BUILD_GIT_VERSION_TOP_BRANCH
        "-Unknown-"
    )

    SET(BUILD_GIT_VERSION_TOP_TAG
        "-Unknown-"
    )

    SET(BUILD_GIT_VERSION_TOP_IS_DIRTY
        "0"
    )

    SET(BUILD_GIT_VERSION_TOP_DESCRIBE
        "-Unknown-"
    )

ENDMACRO()

IF(
    EXISTS ${CMAKE_SOURCE_DIR}/.git
)
    FIND_PACKAGE(Git)
    IF(GIT_FOUND)
        GET_ALL_GIT_VERSIONS()
    ELSE()
        GET_ALL_GIT_VERSIONS_STUB(
            "Could not find GIT Executable"
        )
    ENDIF()
ELSE()
    GET_ALL_GIT_VERSIONS_STUB(
        "Could not detect git directories"
    )
ENDIF()

# MACRO(GET_GIT_VERSIONS)
#         execute_process(
#             COMMAND ${GIT_EXECUTABLE} describe --exact-match --tags
#             OUTPUT_VARIABLE GIT_TAG ERROR_QUIET)
#         execute_process(
#             COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
#             OUTPUT_VARIABLE GIT_BRANCH)

#         string(STRIP "${GIT_REV}" GIT_REV)
#         string(SUBSTRING "${GIT_REV}" 1 10 GIT_REV)
#         string(STRIP "${GIT_DIFF}" GIT_DIFF)
#         string(STRIP "${GIT_TAG}" GIT_TAG)
#         string(STRIP "${GIT_BRANCH}" GIT_BRANCH)
#     endif()

#     set(VERSION "const char* GIT_REV=\"${GIT_REV}${GIT_DIFF}\";
#     const char* GIT_TAG=\"${GIT_TAG}\";
#     const char* GIT_BRANCH=\"${GIT_BRANCH}\";")

#     if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/version.cpp)
#         file(READ ${CMAKE_CURRENT_SOURCE_DIR}/version.cpp VERSION_)
#     else()
#         set(VERSION_ "")
#     endif()

#     if (NOT "${VERSION}" STREQUAL "${VERSION_}")
#         file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/version.cpp "${VERSION}")
#     endif()
# ENDMACRO()
