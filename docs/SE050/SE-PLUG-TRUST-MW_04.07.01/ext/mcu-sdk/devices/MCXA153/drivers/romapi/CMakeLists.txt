if (CONFIG_MCUX_COMPONENT_driver.romapi)

    mcux_add_source(
        SOURCES
            ./fsl_romapi.h
    )

    mcux_add_include(
        INCLUDES .
    )

endif()
