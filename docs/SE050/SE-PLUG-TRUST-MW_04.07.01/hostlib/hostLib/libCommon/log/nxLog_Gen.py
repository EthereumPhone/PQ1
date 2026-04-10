
# Create nxLog_<ComponentName>.h

import sys

LEVELS = [ "DEBUG", "INFO", "WARN", "ERROR"]

BIT_WIDTH = [8*1, 8*2,8*4]

class nxLogHGenerator(object):
    def __init__(self,comp_name, parent_name):
        self.comp_name = comp_name
        self.comp_nameu = comp_name.upper()
        self.parent_nameu = parent_name.upper()
        self.file_name = "nxLog_%s.h"%(comp_name)

    def run(self):
        self.hFile = open(self.file_name,"w")

        self.startHeaderGuard()
        self.commonHeaderFiles()
        self.checkPreviousDefines()
        self.setDefaulLevels()
        self.individualDefines()
        self.endHeaderGuard()

    def startHeaderGuard(self):
 *
        self.hFile.write('''/* Copyright 2018 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

''')
        self.hFile.write("#ifndef NX_LOG_%s_H\n" % self.comp_nameu)
        self.hFile.write("#define NX_LOG_%s_H\n" % self.comp_nameu)

    def commonHeaderFiles(self):
        self.hFile.write("""
#include <nxLog.h>

/* ############################################################ */
/* ## AUTO Generated ########################################## */
/* ############################################################ */

/* Default configuration file */
#include <nxLog_DefaultConfig.h>

/* clang-format off */
""")

    def checkPreviousDefines(self):
        self.hFile.write("""
/* Check if we are double defining these macros */
""")
        self.hFile.write("#if defined(LOG_%s)"%(LEVELS[0][0],))
        for level in LEVELS[1:]:
            prefix = level[0]
            self.hFile.write(" || defined(LOG_%s)"%(prefix,))
        self.hFile.write("\n")
        self.hFile.write("/* This should not happen.  The only reason this could happn is double inclusion of different log files. */\n")
        self.hFile.write("#   error \"LOG_ macro already defined\"\n")
        self.hFile.write("#endif /* LOG_%s */\n"%(prefix,))


    def setDefaulLevels(self):
        self.hFile.write("""
/* Enable/Set log levels for '%s' - start */
/* If source file, or nxLog_Config.h has not set it, set these defines
 *
 * Do not #undef these values, rather set to 0/1. This way we can
 * jump to definition and avoid plain-old-text-search to jump to
 * undef. */

"""%(self.comp_name,))
        prev_level = None
        for level in LEVELS:
            enable = "NX_LOG_ENABLE_%s_%s"%(self.comp_nameu, level)
            default = "NX_LOG_ENABLE_%s_%s" %(self.parent_nameu, level)
            self.hFile.write("#ifndef %s\n"%(enable,))
            if prev_level:
                prev_enable = "NX_LOG_ENABLE_%s_%s"%(self.comp_nameu, prev_level)
                self.hFile.write("#   define %s (%s + %s)\n"%
                    (enable, prev_enable, default))
            else:
                self.hFile.write("#   define %s (%s)\n"%
                    (enable, default))
            self.hFile.write("#endif\n")
            prev_level = level
        self.hFile.write("""
/* Enable/Set log levels for '%s' - end */
"""%(self.comp_name,))
    def individualDefines(self):
        for level in LEVELS:
            prefix = level[0]
            self.hFile.write("\n")
            enable = "NX_LOG_ENABLE_%s_%s"%(self.comp_nameu, level)
            self.hFile.write("#if %s\n"%(enable,))
            self.hFile.write("#   define LOG_%s_ENABLED 1\n"%(level,))
            self.hFile.write("#   define LOG_%s(format, ...) \\\n"%(prefix))
            self.hFile.write("        nLog(\"%s\", NX_LEVEL_%s, "%
                (self.comp_name, level))
            self.hFile.write("format, ##__VA_ARGS__)\n")
            for bit_width in BIT_WIDTH:
                self.hFile.write("#   define LOG_X%d_%s(VALUE) \\\n"%(bit_width, prefix,))
                self.hFile.write("        nLog(\"%s\", NX_LEVEL_%s, \"%%s=0x%%0%dX\",#VALUE, VALUE)\n"%
                    (self.comp_name, level, bit_width/4))

                self.hFile.write("#   define LOG_U%d_%s(VALUE) \\\n"%(bit_width, prefix,))
                self.hFile.write("        nLog(\"%s\", NX_LEVEL_%s, \"%%s=%%u\",#VALUE, VALUE)\n"%
                    (self.comp_name, level))
            for bit_width in BIT_WIDTH[:1]:
                self.hFile.write("#   define LOG_AU%d_%s(ARRAY,LEN) \\\n"%(bit_width,prefix))
                self.hFile.write("        nLog_au8(\"%s\", NX_LEVEL_%s, #ARRAY, ARRAY, LEN)\n"%
                    (self.comp_name, level))
                self.hFile.write("#   define LOG_MAU%d_%s(MESSAGE, ARRAY,LEN) \\\n"%(bit_width,prefix))
                self.hFile.write("        nLog_au8(\"%s\", NX_LEVEL_%s, MESSAGE, ARRAY, LEN)\n"%
                    (self.comp_name, level))
            self.hFile.write("#else\n")
            self.hFile.write("#   define LOG_%s_ENABLED 0\n"%(level,))
            self.hFile.write("#   define LOG_%s(...)\n"%(prefix))
            for bit_width in BIT_WIDTH:
                self.hFile.write("#   define LOG_X%d_%s(VALUE)\n"%(bit_width, prefix,))
                self.hFile.write("#   define LOG_U%d_%s(VALUE)\n"%(bit_width, prefix,))
            for bit_width in BIT_WIDTH[:1]:
                self.hFile.write("#   define LOG_AU%d_%s(ARRAY, LEN)\n"%(bit_width,prefix))
                self.hFile.write("#   define LOG_MAU%d_%s(MESSAGE, ARRAY, LEN)\n"%(bit_width,prefix))
            self.hFile.write("#endif\n")

    def endHeaderGuard(self):
        self.hFile.write("\n")
        self.hFile.write("/* clang-format on */\n")
        self.hFile.write("\n")
        self.hFile.write("#endif /* NX_LOG_%s_H */\n" % self.comp_nameu)

    def close(self):
        self.hFile.close()

def doGenerate(comp_name, parent_name = "default"):
    g = nxLogHGenerator(comp_name, parent_name)
    g.run()
    g.close()

def usage():
    print("Usage Error!")

def main():
    if 2 == len(sys.argv):
        doGenerate(sys.argv[1])
    elif 3 == len(sys.argv):
        doGenerate(sys.argv[1], sys.argv[2])
    else:
        usage()


if __name__ == '__main__':
    main()
