# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

$(call add-clean-step, rm -rf $(PRODUCT_OUT)/obj/lib/libse050keymasterdevice.so)
$(call add-clean-step, rm -rf $(PRODUCT_OUT)/obj/lib/libse050keymasterdevice.so.toc)
$(call add-clean-step, rm -rf $(PRODUCT_OUT)/obj_arm/lib/libse050keymasterdevice.so)
$(call add-clean-step, rm -rf $(PRODUCT_OUT)/obj_arm/lib/libse050keymasterdevice.so.toc)
$(call add-clean-step, rm -rf $(PRODUCT_OUT)/obj/SHARED_LIBRARIES/libse050keymasterdevice_intermediates)
$(call add-clean-step, rm -rf $(PRODUCT_OUT)/obj_arm/SHARED_LIBRARIES/libse050keymasterdevice_intermediates)
$(call add-clean-step, rm -rf $(PRODUCT_OUT)/testcases/se050keymaster_tests)
$(call add-clean-step, rm -rf $(PRODUCT_OUT)/testcases/se05xRotatePlatfSCP03)
$(call add-clean-step, rm -rf $(PRODUCT_OUT)/testcases/se05xGetCertificate)
$(call add-clean-step, rm -rf $(PRODUCT_OUT)/testcases/se05xGetInfo)
$(call add-clean-step, rm -rf $(PRODUCT_OUT)/testcases/jrcpv1_server)
