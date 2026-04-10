#
# Copyright 2018,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

import os
import sys

class DefineMacros:
    def __init__(self):
        pass
    def define_symbol(self, o, symbol, docstring = None):
        if docstring is not None:
            o.write ("\
%s\n" %(docstring)
        )

        o.write("\
#ifndef %s\n\
    #define %s\n\
#endif // %s\n" %(symbol, symbol, symbol)
            )

    def undefine_symbol(self, o, symbol, docstring = None):
        if docstring is not None:
            o.write("\
%s\n" %(docstring)
        )
        o.write("\n\
#if defined(%s)\n\
    #undef %s\n\
#endif // %s\n" %(symbol, symbol, symbol)
        )

    def _ifwrite(self, defmacro, if_macro_list, doc):
        self.o_file.write("#if%s\n" %(if_macro_list[0]))
        if len(if_macro_list) > 1:
            self._ifwrite(defmacro, if_macro_list[1:], doc)
        else:
            if self._method == "DEFINE":
                self.define_symbol(self.o_file, defmacro, doc)
            elif self._method == "UNDEFINE":
                self.undefine_symbol(self.o_file, defmacro, doc)
            else:
                print("Unknown method")
        self.o_file.write("#endif // %s\n\n" %(if_macro_list[0]))

    def write(self, macro_list, method):
        self._method = method
        for macro in macro_list:
            if len(macro) < 2:
                print("Length too less : %d. Add doc also" %(len(macro)))
            elif len(macro) > 2:
                doc = macro[-1]
                self._ifwrite(macro[0], macro[1:-1], doc)
            elif self._method == "DEFINE":
                doc = macro[-1]
                self.define_symbol(self.o_file, macro[0], macro[1])
            elif self._method == "UNDEFINE":
                doc = macro[-1]
                self.undefine_symbol(self.o_file, macro[0], macro[1])
            else:
                print("Unknown method")



COPYRIGHT ="/*\n\
 *  Copyright The Mbed TLS Contributors\n\
 *  SPDX-License-Identifier: Apache-2.0\n\
 *\n\
 *  Licensed under the Apache License, Version 2.0 (the \"License\"); you may\n\
 *  not use this file except in compliance with the License.\n\
 *  You may obtain a copy of the License at\n\
 *\n\
 *  http://www.apache.org/licenses/LICENSE-2.0\n\
 *\n\
 *  Unless required by applicable law or agreed to in writing, software\n\
 *  distributed under the License is distributed on an \"AS IS\" BASIS, WITHOUT\n\
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n\
 *  See the License for the specific language governing permissions and\n\
 *  limitations under the License.\n\
 */\n\
/* Copyright 2021,2025 NXP\n\
 * SPDX-License-Identifier: Apache-2.0\n\
 */\n\
"

C_HEADER_START = "\n\
/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!! */\n\
/* GENERATED FILE. DO NOT EDIT!! */\n\
/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!! */\n\
\n\
/* clang-format off */\n\
\n\
#ifndef __MBEDTLS_USER_CONFIG_H__\n\
#define __MBEDTLS_USER_CONFIG_H__\n\
\n\
#if defined(SSS_USE_FTR_FILE)\n\
#include \"fsl_sss_ftr.h\"\n\
#else\n\
#include \"fsl_sss_ftr_default.h\"\n\
#endif\n\
\n\
"

C_HEADER_END = "\n#endif /* __MBEDTLS_USER_CONFIG_H__ */\n"
