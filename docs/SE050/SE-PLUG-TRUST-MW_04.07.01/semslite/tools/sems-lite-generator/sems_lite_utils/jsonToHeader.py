# Copyright 2019,2022 NXP
#
# NXP Confidential. This software is owned or controlled by NXP and may only
# be used strictly in accordance with the applicable license terms.  By
# expressly accepting such terms or by downloading, installing, activating
# and/or otherwise using the software, you are agreeing that you have read,
# and that you agree to comply with and are bound by, such license terms.  If
# you do not agree to be bound by the applicable license terms, then you may
# not retain, install, activate or otherwise use the software.
#

import sys
from pathlib import Path

c_header = """/* Copyright 2021-2022 NXP
 *
 * NXP Confidential. This software is owned or controlled by NXP and may only
 * be used strictly in accordance with the applicable license terms.  By
 * expressly accepting such terms or by downloading, installing, activating
 * and/or otherwise using the software, you are agreeing that you have read,
 * and that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you may
 * not retain, install, activate or otherwise use the software.
 */

/* This is an auto generated file */

"""

h_header = "/* This is an auto generated file */\n\n"

class JsonToHeader(object):
    def __init__(self, binFile, out_file, json_obj, sems_lite_agent_major_version):
        self.binFile = open(binFile, "rb")
        self.out_file = out_file
        self.hex_h_file = open(out_file + ".h", "w")
        self.hex_c_file = open(out_file + ".c", "w")
        self.subcomponent_count = 0
        path = self.out_file + ".c"
        self.headerfilename = Path(path).stem
        self.packageinfo = json_obj
        self.sems_lite_agent_major_version = sems_lite_agent_major_version
        pass

    if sys.version > '3':
        def _byte(self, b):
            return bytes((b, ))
    else:
        def _byte(self, b):
            return chr(b)

    def encode_varint(self, number):
        """Pack `number` into varint bytes"""
        buf = b''
        while True:
            towrite = number & 0x7f
            number >>= 7
            if number:
                buf += self._byte(towrite | 0x80)
            else:
                buf += self._byte(towrite)
                break
        return buf

    def add_licence(self):
        self.hex_c_file.write(c_header)
        self.hex_c_file.flush()
        self.hex_h_file.write(c_header)
        self.hex_h_file.write(h_header)
        self.hex_h_file.flush()

    def run(self):
        self.add_licence()
        headerfilename = self.headerfilename
        self.hex_h_file.write("\n#ifndef __" + headerfilename.replace(".","_").replace("-","_") + "__H__" + "\n")
        self.hex_h_file.write("#define __" + headerfilename.replace(".","_").replace("-","_") + "__H__" + "\n\n")
        self.hex_h_file.write("\n")

        self.fill_subcomponent_to_h_file()

        self.fill_metadata_to_h_file()

        self.fill_signature_to_h_file()

        if "PkSemsCaAut" in self.packageinfo:
            self.fill_public_key_to_h_file()

        self.hex_h_file.flush()

        self.hex_c_file.write("#include \"sems_lite_api.h\"\n")
        self.hex_c_file.write("#include \""+headerfilename+".h\""+"\n")

        self.hex_c_file.write("/* doc:start:SEMS-Lite-protobuf-declare */\n\n")

        if self.subcomponent_count > 0:
            subcomp_list = ["nameLen", "pName", "aidLen", "pAid", "version", "swContentRegisterLen", "pSWContentRegister", "minimumPreviousVersion", "pNextSubComponentMetaData"]
            for i in range(1, self.subcomponent_count + 1):
                self.fill_sub_components_to_c_file(subcomp_list, i)

        multcast_pkg_list = ["semsLiteAPIVersion", "targetEntityID", "target12Nc", "requiredFreeBytesNonVolatileMemory",
                             "requiredFreeBytesTransientMemory", "multicastPackageNameLen", "pMulticastPackageName",
                             "multicastPackageVersion", "pSubComponentMetaData", "signatureOverCommandsLen",
                             "pSignatureOverCommands", "pkSemsCaAutLen", "pPkSemsCaAut", "multicastCommandsLen", "pMulticastCommands", ]

        self.fill_multi_cast_package_to_c_file(multcast_pkg_list)

        self.hex_c_file.write("\n/* doc:end:SEMS-Lite-protobuf-declare */\n")

        self.add_binary_blob_to_c_file()

    def fill_signature_to_h_file(self):
        i = 0
        data = self.packageinfo["SignatureOverCommands"]
        datatowrite = [data[index:index + 2] for index in range(0, len(data), 2)]
        self.hex_h_file.write(
            "\n#define M_signatureOverCommands" + "    \\")
#        self.hex_h_file.write("\n\t{")
#        for i in datatowrite:
#            self.hex_h_file.write("0x" + i + ",")
#        self.hex_h_file.write("} \n")

        self.hex_h_file.write("\n\t{")

        for x in datatowrite:
            if 0 == i % 16:
                self.hex_h_file.write(" \\\n\t")
            elif 0 == i % 8:
                self.hex_h_file.write("    ")
            elif 0 == i % 4:
                self.hex_h_file.write("  ")
            self.hex_h_file.write("0x" + x + ",")
            i = i + 1
        self.hex_h_file.write(" \\\n\t}\n")


        self.hex_h_file.write(
            "\n#define M_signatureOverCommandsLen" + "    \\\n")
        datatowrite = str(int(len(data) / 2))
        self.hex_h_file.write("\t" + datatowrite + "\n\n")

    def fill_metadata_to_h_file(self):
        self.hex_h_file.write("#define M_semsLiteAPIVersion" + "    \\\n")
        self.hex_h_file.write("\t" + str(self.sems_lite_agent_major_version) + "\n\n")

        data = self.packageinfo["TargetEntityID"]
        datatowrite = [data[index:index + 2] for index in range(0, len(data), 2)]
        self.hex_h_file.write("#define M_targetEntityID" + "\t\\\n")
        self.hex_h_file.write("\t{")
        for i in datatowrite:
            self.hex_h_file.write("0x" + i + ",")
        self.hex_h_file.write("}\n\n")

        self.hex_h_file.write("#define M_targetEntityIDLen" + "\t\\\n")
        self.hex_h_file.write("\t" + str(int(len(datatowrite))) + "\n")

        # Add Target12nc
        data = self.packageinfo["Target12nc"]
        datatowrite = [data[index:index + 2] for index in range(0, len(data), 2)]
        self.hex_h_file.write("#define M_target12Nc" + "\t\\\n")
        self.hex_h_file.write("\t{")
        for i in datatowrite:
            self.hex_h_file.write("0x" + i + ",")
        self.hex_h_file.write("}\n\n")

        self.hex_h_file.write("#define M_target12NcLen" + "\t\\\n")
        self.hex_h_file.write("\t" + str(int(len(datatowrite))) + "\n")

        datatowrite = str(self.packageinfo["requiredFreeBytesNonVolatileMemory"])
        self.hex_h_file.write("\n#define M_requiredFreeBytesNonVolatileMemory" + "\t\\\n")
        self.hex_h_file.write("\t" + datatowrite + "\n")

        datatowrite = str(self.packageinfo["requiredFreeBytesTransientMemory"])
        self.hex_h_file.write("\n#define M_requiredFreeBytesTransientMemory" + "\t\\\n")
        self.hex_h_file.write("\t" + datatowrite + "\n")

        self.hex_h_file.write("\n#define M_szMulticastPackageName" + "    \\\n")
        datatowrite = self.packageinfo["MulticastPackageName"]
        self.hex_h_file.write("\t\"" + datatowrite + "\"" + " \n\n")

        self.hex_h_file.write("#define M_multicastPackageNameLen" + "\t\\\n")
        self.hex_h_file.write("\t" + "sizeof(M_szMulticastPackageName)" + "\n")

        data = self.packageinfo["MulticastPackageVersion"].split(".")
        self.hex_h_file.write(
            "\n#define M_multicastPackageVersion" + "    \\\n")
        datatowrite = "{" + data[0] + "," + data[1] + "} \n"
        self.hex_h_file.write("\t" + datatowrite)

    def fill_public_key_to_h_file(self):
        i = 0
        data = self.packageinfo["PkSemsCaAut"]
        datatowrite = [data[index:index + 2] for index in range(0, len(data), 2)]
        self.hex_h_file.write(
            "\n#define M_pkSemsCaAut" + "    \\")

        self.hex_h_file.write("\n\t{")

        for x in datatowrite:
            if 0 == i % 16:
                self.hex_h_file.write(" \\\n\t")
            elif 0 == i % 8:
                self.hex_h_file.write("    ")
            elif 0 == i % 4:
                self.hex_h_file.write("  ")
            self.hex_h_file.write("0x" + x + ",")
            i = i + 1
        self.hex_h_file.write(" \\\n\t}\n")


        self.hex_h_file.write(
            "\n#define M_pkSemsCaAutLen" + "    \\\n")
        datatowrite = str(int(len(data) / 2))
        self.hex_h_file.write("\t" + datatowrite + "\n\n")

    def add_binary_blob_to_c_file(self):
        blob_data = self.binFile.read()
        i = 0
        length = len(blob_data)
        varint_len = self.encode_varint(length)

        total_len = length + len(varint_len)

        self.hex_h_file.write("#define M_multicastCommandsLen" + "    \\\n")
        self.hex_h_file.write("\t" + str(total_len) + " \n\n")

        self.hex_h_file.write("#define M_multicastCommands" + "\t\\\n")
        self.hex_h_file.write("\t{")

        self.hex_h_file.write("/* clang-format off */ \\\n")
        self.hex_h_file.write("/* Length = %d */ \\\n" % (length))

        for x in varint_len:
            self.hex_h_file.write("0x%02X, " % x)
        self.hex_h_file.write(" \\\n")

        for x in blob_data:
            if 0 == i % 16:
                self.hex_h_file.write(" \\\n")
            elif 0 == i % 8:
                self.hex_h_file.write("    ")
            elif 0 == i % 4:
                self.hex_h_file.write("  ")
            self.hex_h_file.write("0x%02X, " % x)
            i = i + 1
        self.hex_h_file.write(" \\\n}\n")
        self.hex_h_file.write("/* clang-format on */\n")

        self.binFile.close()

        self.hex_h_file.write("#endif // #define  __" + self.headerfilename + "__H__" + "\n")
        self.hex_h_file.flush()
        self.hex_h_file.close()

    def fill_subcomponent_to_h_file(self):
        self.hex_h_file.write("/*SubComponentMetaData start */\n\n")
        subcomponentlist = self.packageinfo["SubComponentMetaData"]

        if len(subcomponentlist) == 0:
            self.subcomponent_count = 0
        else:
            for subcomponent in subcomponentlist:
                count = self.subcomponent_count + 1
                self.hex_h_file.write("#define M_subComponent_" + str(count) + "_szName" + "    \\\n")
                self.hex_h_file.write("\t\"" + subcomponent["name"] + "\"" + " \n\n")

                self.hex_h_file.write("#define M_subComponent_" + str(count) + "_nameLen" +"    \\\n")
                self.hex_h_file.write("\t" + "sizeof(M_subComponent_" + str(count) + "_szName)" + "\n\n")

                self.hex_h_file.write("#define M_subComponent_" + str(count) + "_aid" + "    \\\n")
                data = subcomponent["aid"]
                datatowrite = [data[index:index + 2] for index in range(0, len(data), 2)]
                self.hex_h_file.write("\t{")
                for i in datatowrite:
                    self.hex_h_file.write("0x" + i + ",")
                self.hex_h_file.write("}\n\n")

                self.hex_h_file.write("#define M_subComponent_" + str(count) + "_aidLen" + "    \\\n")
                self.hex_h_file.write("\t" + str(int(len(datatowrite))) + "\n\n")

                self.hex_h_file.write("#define M_subComponent_" + str(count) + "_version" + "    \\\n")
                data = subcomponent["version"].split(".")
                datatowrite = "{" + data[0] + "," + data[1] + "}\n"
                self.hex_h_file.write("\t" + datatowrite + "\n")

                if "SWContentRegister" in subcomponent:
                    self.hex_h_file.write("#define M_subComponent_" + str(count) + "_SWContentRegister" + "    \\\n")
                    data = subcomponent["SWContentRegister"].splitlines()
                    for i in range(len(data)):
                        if i == 0:
                            self.hex_h_file.write("\t\"" + data[i] + " \\" + "\n")
                        else:
                            self.hex_h_file.write("\t" + data[i] + " \\"+ "\n")
                    self.hex_h_file.write("\t\"\n\n")

                    self.hex_h_file.write("#define M_subComponent_" + str(count) + "_SWContentRegisterLen" +"    \\\n")
                    self.hex_h_file.write("\t" + "sizeof(M_subComponent_" + str(count) + "_SWContentRegister)" + "\n\n")

                self.hex_h_file.write("#define M_subComponent_" + str(count) + "_minimumPreviousVersion" + "    \\\n")
                if "minimumPreviousVersion" in subcomponent.keys():
                    data = subcomponent["minimumPreviousVersion"].split(".")
                    datatowrite = "{" + data[0] + "," + data[1] + "}\n"
                else:
                    datatowrite = "{0xFF, 0xFF} \n" # Fill with invalid version number
                self.hex_h_file.write("\t" + datatowrite + "\n")

                self.subcomponent_count += 1

        self.hex_h_file.write("/*SubComponentMetaData end */ \\\n")

    def fill_multi_cast_package_to_c_file(self, multcast_pkg_list):
        self.hex_c_file.write("static const uint8_t cmd_signature[] = M_signatureOverCommands;\n\n")
        if "PkSemsCaAut" in self.packageinfo:
            self.hex_c_file.write("static const uint8_t ca_public_key[] = M_pkSemsCaAut;\n\n")
        self.hex_c_file.write("static const uint8_t commands[] = M_multicastCommands;\n\n")
        self.hex_c_file.write("const multicast_package_t multicast_package = {\n")
        for x in multcast_pkg_list:
            if x == "pMulticastPackageName":
                datatowrite = "\t." + str(x) + " = \\\n" + "\t\tM_szMulticastPackageName" + ",\n"
            elif x == "pSubComponentMetaData":
                if 0 == self.subcomponent_count:
                    datatowrite = "\t." + str(x) + " = \\\n" + "\t\tNULL" + ",\n"
                else:
                    datatowrite = "\t." + str(x) + " = \\\n" + "\t\t&subcomponent_1" + ",\n"
            elif x == "pSignatureOverCommands":
                datatowrite = "\t." + str(x) + " = \\\n" + "\t\tcmd_signature" + ",\n"
            elif x == "pPkSemsCaAut":
                if "PkSemsCaAut" in self.packageinfo:
                    datatowrite = "\t." + str(x) + " = \\\n" + "\t\tca_public_key" + ",\n"
                else:
                    datatowrite = "\t." + str(x) + " = \\\n" + "\t\tNULL" + ",\n"
            elif x == "pkSemsCaAutLen":
                if "PkSemsCaAut" in self.packageinfo:
                    datatowrite = "\t." + str(x) + " = \\\n" + "\t\tM_" + str(x) + ",\n"
                else:
                    datatowrite = "\t." + str(x) + " = \\\n" + "\t\t0" + ",\n"
            elif x == "pMulticastCommands":
                datatowrite = "\t." + str(x) + " = \\\n" + "\t\tcommands" + ",\n"
            else:
                datatowrite = "\t." + str(x) + " = \\\n" + "\t\tM_" + str(x) + ",\n"
            self.hex_c_file.write(datatowrite)
        self.hex_c_file.write("};\n")

    def fill_sub_components_to_c_file(self, subcomp_list, i):
        self.hex_c_file.write("static const uint8_t aid_" + str(i) + "[] = M_subComponent_" + str(i) + "_aid" + ";\n\n")
        self.hex_c_file.write("static const sub_component_metaData_t subcomponent_" + str(i) + " = {\n")
        for x in subcomp_list:
            if x == "pNextSubComponentMetaData":
                if i == self.subcomponent_count:
                    self.hex_c_file.write(
                        "\t." + str(x) + " = \\\n" + "\t\t" + "NULL" + ",\n")
                else:
                    self.hex_c_file.write(
                        "\t." + str(x) + " = \\\n" + "\t\t" + "&subcomponent_" + str(i + 1) + ",\n")
            elif x == "pName":
                self.hex_c_file.write("\t." + str(x) + " = \\\n" + "\t\t" + "M_subComponent_" + str(i) + "_" + "szName" + ",\n")
            elif x == "pSWContentRegister":
                subcomponentlist = self.packageinfo["SubComponentMetaData"]
                if "SWContentRegister" in subcomponentlist[0]:
                    self.hex_c_file.write("\t." + str(x) + " = \\\n" + "\t\t" + "M_subComponent_" + str(i) + "_" + "SWContentRegister" + ",\n")
                else:
                    self.hex_c_file.write("\t." + str(x) + " = \\\n" + "\t\t" + "NULL" + ",\n")
            elif x == "swContentRegisterLen":
                subcomponentlist = self.packageinfo["SubComponentMetaData"]
                if "SWContentRegister" in subcomponentlist[0]:
                    self.hex_c_file.write("\t." + str(x) + " = \\\n" + "\t\t" + "M_subComponent_" + str(i) + "_" + "SWContentRegisterLen" + ",\n")
                else:
                    self.hex_c_file.write("\t." + str(x) + " = \\\n" + "\t\t" + "0" + ",\n")
            elif x == "pAid":
                self.hex_c_file.write("\t." + str(x) + " = \\\n" + "\t\t" + "aid_" + str(i) + ",\n")
            else:
                self.hex_c_file.write("\t." + str(x) + " = \\\n" + "\t\t" + "M_subComponent_" + str(i) + "_" + str(x) + ",\n")
        self.hex_c_file.write("};\n\n")


def main():
    usage()


def usage():
    print("Usage:\n")
    print("    %s <in-binary> <out_file>\n" % (sys.argv[0]))


if __name__ == '__main__':
    main()
