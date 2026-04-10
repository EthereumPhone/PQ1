# Add set(CONFIG_USE_middleware_mbedtls_port_els true) in config.cmake to use this component

include_guard(GLOBAL)
message("${CMAKE_CURRENT_LIST_FILE} component is included.")

if(CONFIG_USE_component_els_pkc_els AND CONFIG_USE_middleware_mbedtls)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/port/els/aes_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/els/cbc_mac_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/els/cmac_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/els/ctr_drbg_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/els/gcm_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/els/sha256_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/els/sha512_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/els/entropy_poll_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/els/els_mbedtls.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/port/els
)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DMBEDTLS_MCUX_ELS_API
    -DMBEDTLS_MCUX_USE_ELS
    -DMCUXCL_FEATURE_CSSL_MEMORY_C_FALLBACK
    -DMBEDTLS_CONFIG_FILE="els_mbedtls_config.h"
  )

endif()

else()

message(SEND_ERROR "middleware_mbedtls_port_els dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()
