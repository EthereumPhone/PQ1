
# cmake_project_lpc55s_ns/Debug/Makefile

#Update these variables if needed
TOP_NAME=simw-top
BUILD_DIR?=../../../../${TOP_NAME}_build/${TOP_NAME}-eclipse_ns
BUILD_TARGET=sbl_app_ns

#BUILD_DIR?=../../../../${TOP_NAME}_build/${TOP_NAME}-eclipse_nw
#BUILD_TARGET=hello_world_sw


#... a7x_utils
#... a71ch_Main
#... a7x_a71chMainTst
#... vcom
#... test_keystore
#... test_keyobject
#... test_asymmetric
#... test_symmetric
#... test_rng
#... ex_common
#... ex_asymmetric

ifeq (help, $(ConfigName))
BUILD_TARGET=help
all: help_target
else
ifeq (edit_cache, $(ConfigName))
BUILD_TARGET=edit_cache
all: help_target
else
all: build_all
endif
endif

# vcom a71ch_Main test_session test_LoopBack
# edit_cache


help_target:
	@if [ ! -e $(BUILD_DIR)/Makefile ]; then echo ERRROR! Did you run cmake already to generate CMake Project; fi
	@if [ ! -e $(BUILD_DIR)/Makefile ]; then echo ERRROR!   Please run create_cmake_projects.py lpc55s; fi
	@if [ ! -e $(BUILD_DIR) ]; then echo $(BUILD_DIR) is missing ; fi
	@if [ ! -e $(BUILD_DIR) ]; then exit 1; fi
	$(MAKE) -Rr --no-print-directory -C $(BUILD_DIR) $(BUILD_TARGET)

build_all:
	#Remove previously generated files so that we do not download wrong files
	-rm -rf *.axf
	-rm -rf *.bin
	@-rm -rf $(BUILD_DIR)/bin/*.axf
	@-rm -rf $(BUILD_DIR)/bin/*.bin
	@if [ ! -e $(BUILD_DIR)/Makefile ]; then echo ERRROR! Did you run cmake already to generate CMake Project; fi
	@if [ ! -e $(BUILD_DIR)/Makefile ]; then echo ERRROR!   Please run create_cmake_projects.py lpc55s; fi
	@if [ ! -e $(BUILD_DIR) ]; then echo $(BUILD_DIR) is missing ; fi
	@if [ ! -e $(BUILD_DIR) ]; then exit 1; fi
	$(MAKE) -j -Rr --no-print-directory -C $(BUILD_DIR) $(BUILD_TARGET)
	@if [ -e $(BUILD_DIR)/bin/$(BUILD_TARGET).axf ]; then cp -f $(BUILD_DIR)/bin/$(BUILD_TARGET).axf cmake_project_lpc55s_ns.axf; fi
	@if [ -e $(BUILD_DIR)/bin/$(BUILD_TARGET).axf ]; then cp -f $(BUILD_DIR)/bin/$(BUILD_TARGET).bin .; fi

clean:
	$(MAKE) -Rr --no-print-directory -C $(BUILD_DIR) clean
	-rm -rf Debug/*.axf
	-rm -rf Debug/*.bin
	-rm -rf *.axf
	-rm -rf *.bin

.PHONY: clean all build_all help_target
