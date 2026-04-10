# Copyright 2019,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Utility to generate version information files.

This file reads, version_info.txt from input directory and generates
files invarious formats.

Input:
    Param 1: Directory where version_info.txt is kept
    Param 2: Output file[s] with extension.

    For generating with different date set environment
    varaible VERSION_INFO_DATE.
    e.g. SET VERSION_INFO_DATE=2019.02.01


version_info.txt needs these inputs:

    # Product
    prod_name = "HostLib"
    prod_desc = "Host Libary"

    # Programming language specific customizations
    lang_c_prefix = prod_name.upper()
    lang_namespace = "nxp::HostLib"

    # Version
    v_major = "01"
    v_minor = "01"
    v_dev = "01"
    v_meta = "" # Meta string identifier
    # Maturity of library.  Alpha, Beta, Production
    maturity = "A"
"""

import logging
import os
import sys
import time
from string import Template

log = logging.getLogger("version_update")

logging.basicConfig(level=logging.DEBUG)

# Version of this python script.
__VUP_VERSION__ = '2019.01.17_00'

# Version Log of this file:
#
#
# 2019.01.17_00 : PGh : Added  _VER_MAJOR_MINOR and _VER_MAJOR_MINOR_DEV
#               :
# 2019.01.12_00 : PGh : Re-Write based on old version_info.py
#

COPYRIGHTS = """Copyright 2019-2025 NXP

SPDX-License-Identifier: Apache-2.0

"""


class KVINFO:  # pylint: disable=too-few-public-methods
    """
    Version info variable structure
    """
    PROD_NAME = "prod_name"
    PROD_DESC = "prod_desc"
    #
    # Programming language specific customizations
    LANG_C_PREFIX = "lang_c_prefix"
    LANG_NAMESPACE = "lang_namespace"
    #
    # Version
    V_MAJOR = "v_major"
    V_MINOR = "v_minor"
    V_DEV = "v_dev"
    V_META = "v_meta"
    # Maturity of library.  Alpha, Beta, Production
    MATURITY = "maturity"


DEF_NAME = {
    KVINFO.V_MAJOR: "VER_MAJOR",
    KVINFO.V_MINOR: "VER_MINOR",
    KVINFO.V_DEV: "VER_DEV",
}


class VersionInformation:
    """
    Version information
    """

    def __init__(self, vinfo, raw_contents):
        self.vinfo = vinfo
        self.raw_contents = raw_contents
        self.values = None

    def parse(self):
        self.values = {}
        self._parse_values()
        self._parse_date_time_meta()
        print("    v%s" % self.values['ver_date_string'])

    def generate_files(self, file_names):
        """
        Generate files
        :param file_names: list of files
        :return: None
        """
        for file_name in file_names:
            generator_fn = None
            if file_name.endswith(".h"):
                generator_fn = self.generate_h_output
            elif file_name.endswith(".cs"):
                generator_fn = self.generate_cs_output
            elif file_name.endswith(".doxyfile"):
                generator_fn = self.generate_doxy_output
            elif file_name.endswith(".org"):
                generator_fn = self.generate_org_output
            elif file_name.endswith(".sh"):
                generator_fn = self.generate_sh_output
            elif file_name.endswith(".nsh"):
                generator_fn = self.generate_nsh_output
            elif file_name.endswith(".py"):
                generator_fn = self.generate_py_output
            elif file_name.endswith(".rst.txt"):
                generator_fn = self.generate_rst_output
            else:
                raise Exception("Unsupported extension '%s'" % (file_name,))

            if generator_fn:
                with open(file_name, "w") as f:
                    generator_fn(f)

    def _parse_values(self):
        """
        Parse version info values
        :return: None
        """
        self.values["i_major"] = int(self.vinfo[KVINFO.V_MAJOR])
        self.values["i_minor"] = int(self.vinfo[KVINFO.V_MINOR])
        self.values["i_dev"] = int(self.vinfo[KVINFO.V_DEV])
        self.values["v_major"] = self.vinfo[KVINFO.V_MAJOR]
        self.values["v_minor"] = self.vinfo[KVINFO.V_MINOR]
        self.values["v_dev"] = self.vinfo[KVINFO.V_DEV]
        self.values["maturity"] = self.vinfo[KVINFO.MATURITY]
        self.values["lang_c_prefix"] = self.vinfo[KVINFO.LANG_C_PREFIX]
        self.values["prod_name"] = self.vinfo[KVINFO.PROD_NAME]
        self.values["cs_namespace"] = self.vinfo[KVINFO.LANG_C_PREFIX]
        self.values['i_major_minor'] = 0 \
                                       + (int(self.vinfo[KVINFO.V_MAJOR]) * 10000) \
                                       + (int(self.vinfo[KVINFO.V_MINOR]))
        self.values['i_major_minor_dev'] = 0 \
                                           + (int(self.vinfo[KVINFO.V_MAJOR]) * 10000 * 10000) \
                                           + (int(self.vinfo[KVINFO.V_MINOR]) * 10000) \
                                           + (int(self.vinfo[KVINFO.V_DEV]))

    def _parse_date_time_meta(self):
        """
        Parse time stamp
        :return: None
        """
        # Timestamp
        local_time = time.localtime()
        datetime_str = os.getenv("VERSION_INFO_DATE")

        if datetime_str:
            log.warning("Over-riding datetime  as '%s' because "
                        "environment varaible 'VERSION_INFO_DATE' is set", (datetime_str,))
        elif self.vinfo[KVINFO.MATURITY] == 'B':
            datetime_str = time.strftime("%Y%m%d", local_time)
        elif self.vinfo[KVINFO.MATURITY] == 'A':
            datetime_str = time.strftime("%Y%m%d", local_time) + "_" + \
                           time.strftime("%H%M", local_time)
        elif self.vinfo[KVINFO.MATURITY] == 'P':
            datetime_str = ''
        else:
            raise Exception("Invalid maturity='%s'.  Expect either 'A', 'B' or 'P'"
                            % (self.vinfo[KVINFO.MATURITY],))

        if len(datetime_str) > 0:
            uc_datetime_str = '_' + datetime_str
        else:
            uc_datetime_str = ''

        # ID String
        if len(self.vinfo[KVINFO.V_META]) > 0:
            uc_v_meta = "_" + self.vinfo[KVINFO.V_META]
        else:
            uc_v_meta = ""

        self.values["ver_date_string"] = \
            "%02d.%02d.%02d%s%s" % (
                self.values["i_major"],
                self.values["i_minor"],
                self.values["i_dev"],
                uc_datetime_str, uc_v_meta)
        self.values["ver_date_string_u"] = \
            "%02d_%02d_%02d%s%s" % (
                self.values["i_major"],
                self.values["i_minor"],
                self.values["i_dev"], uc_datetime_str, uc_v_meta)

    @classmethod
    def put_comment_c(cls, f_object, raw_contents):
        f_object.write("/*")
        if isinstance(raw_contents, list):
            f_object.write(" %s\n" % (raw_contents[0].rstrip(),))
            for l in raw_contents[1:]:
                f_object.write(" * %s\n" % (l.rstrip(),))
        elif isinstance(raw_contents, str):
            f_object.write(" %s\n" % (raw_contents.split("\n")[0].rstrip(),))
            for l in raw_contents.split("\n")[1:]:
                f_object.write(" * %s\n" % (l.rstrip(),))
        f_object.write(" */\n\n")

    # def dumpraw_contents_c(self, fObject):
    #     self.put_comment_c()
    #     fObject.write("\n/* %s" % ("______GENERATED_FROM____version_info.txt",))
    #     for l in self.raw_contents:
    #         fObject.write("\n * %s" % (l.rstrip(),))
    #     fObject.write("\n */\n")

    def lang_c_get_header_guard(self):
        header_guard_def = self.vinfo[KVINFO.LANG_C_PREFIX] + "_VERSION_INFO_H_INCLUDED"
        return header_guard_def

    def generate_h_output(self, output_f):
        self.put_comment_c(output_f, COPYRIGHTS)
        header_guard_def = self.lang_c_get_header_guard()
        output_f.write("#ifndef " + header_guard_def + "\n")
        output_f.write("#define " + header_guard_def + "\n\n")

        output_f.write(TEMPLATE_C.substitute(self.values))
        # self.putValues_c(o, c_defines)

        self.put_comment_c(output_f, self.raw_contents)
        output_f.write("#endif /* " + header_guard_def + " */\n")

    def generate_doxy_output(self, output_f):
        output_f.write(TEMPLATE_DOXYGEN.substitute(self.values))

    def generate_sh_output(self, output_f):
        output_f.write(TEMPLATE_SH.substitute(self.values))

    def generate_org_output(self, output_f):
        output_f.write(TEMPLATE_ORG.substitute(self.values))

    def generate_nsh_output(self, output_f):
        output_f.write(TEMPLATE_NSH.substitute(self.values))

    def generate_cs_output(self, output_f):
        self.put_comment_c(output_f, COPYRIGHTS)

        output_f.write(TEMPLATE_CS.substitute(self.values))
        # self.putValues_c(output_f, c_defines)

        self.put_comment_c(output_f, self.raw_contents)

    def generate_py_output(self, output_f):
        output_f.write(TEMPLATE_PY.substitute(self.values))

    def generate_rst_output(self, output_f):
        output_f.write(TEMPLATE_RST.substitute(self.values))


# def generate_cs_file_string(cs_namespace, product_name, sw_vstr, v_major,
#                             v_minor, v_dev, maturity, rd_lib_stream):
#     s = []
#
#     return "\n".join(s)


TEMPLATE_C = Template("""
/* clang-format off */
#define ${lang_c_prefix}_PROD_NAME          "${prod_name}"
#define ${lang_c_prefix}_VER_STRING_NUM     "v${ver_date_string}"
#define ${lang_c_prefix}_PROD_NAME_VER_FULL "${prod_name}_v${ver_date_string}"
#define ${lang_c_prefix}_VER_MAJOR          (${i_major}u)
#define ${lang_c_prefix}_VER_MINOR          (${i_minor}u)
#define ${lang_c_prefix}_VER_DEV            (${i_dev}u)

/* v${v_major}.${v_minor} = ${i_major_minor}u */
#define ${lang_c_prefix}_VER_MAJOR_MINOR ( 0 \\
    | (${lang_c_prefix}_VER_MAJOR * 10000u)    \\
    | (${lang_c_prefix}_VER_MINOR))

/* v${v_major}.${v_minor}.${v_dev} = ${i_major_minor_dev}ULL */
#define ${lang_c_prefix}_VER_MAJOR_MINOR_DEV ( 0 \\
    | (${lang_c_prefix}_VER_MAJOR * 10000*10000u)    \\
    | (${lang_c_prefix}_VER_MINOR * 10000u)    \\
    | (${lang_c_prefix}_VER_DEV))

/* clang-format on */


""")

TEMPLATE_DOXYGEN = Template("""
PROJECT_NUMBER         = "v${v_major}.${v_minor}.${v_dev}"
""")

TEMPLATE_SH = Template("""
${prod_name}_Ver="v${v_major}.${v_minor}.${v_dev}"
${prod_name}_Ver_Full="v${ver_date_string}"
""")

TEMPLATE_ORG = Template("""
#+MACRO: ${prod_name}_Ver v${v_major}.${v_minor}.${v_dev}
""")

TEMPLATE_NSH = Template("""
!define ${lang_c_prefix}_PRODUCT_NAME   "${prod_name}"
!define ${lang_c_prefix}_VER_STR        "v${v_major}.${v_minor}.${v_dev}.00"
!define ${lang_c_prefix}_VER_STR_FULL   "v${ver_date_string}"
!define ${lang_c_prefix}_MAJOR          "${v_major}"
!define ${lang_c_prefix}_MINOR          "${v_minor}"
!define ${lang_c_prefix}_DEV            "${v_dev}"
""")

TEMPLATE_CS = Template("""
namespace ${cs_namespace} {
    public class ${cs_namespace}_Ver {
        /// <summary>
        ///   Name of the Product
        /// </summary>
        public const string ProductName              = "${prod_name}";

        /// <summary>
        ///   Version String/Description of the Binary
        /// </summary>
        public const string ProductNameWithVersion   = "${prod_name}_v${ver_date_string}";

        /// <summary>
        ///   Version of the binary (with patch as star)
        /// </summary>
        public const string AssemblyVersion          = "${i_major}.${i_minor}.${i_dev}.*";

        /// <summary>
        ///   Assembly file version
        /// </summary>
        public const string AssemblyFileVersion      = "${i_major}.${i_minor}.${i_dev}.0";
    }
}
""")

TEMPLATE_RST = Template("""
.. |${lang_c_prefix}_PRODUCT_NAME|   replace:: :samp:`${prod_name}`
.. |${lang_c_prefix}_VER_STR|        replace:: :samp:`v${v_major}.${v_minor}.${v_dev}`
.. |${lang_c_prefix}_VER_STR_FULL|   replace:: :samp:`v${ver_date_string}`
.. |${lang_c_prefix}_MAJOR|          replace:: :samp:`${v_major}`
.. |${lang_c_prefix}_MINOR|          replace:: :samp:`${v_minor}`
.. |${lang_c_prefix}_DEV|            replace:: :samp:`${v_dev}`
""")

TEMPLATE_PY = Template("""
${lang_c_prefix}_PRODUCT_NAME   = "${prod_name}"
${lang_c_prefix}_VER_STR        = "v${v_major}.${v_minor}.${v_dev}"
${lang_c_prefix}_VER_STR_FULL   = "v${ver_date_string}"
${lang_c_prefix}_MAJOR          = "${v_major}"
${lang_c_prefix}_MINOR          = "${v_minor}"
${lang_c_prefix}_DEV            = "${v_dev}"
""")


def usage(message):
    print("ERROR!" + message)
    print(
        """
    Input:
        1. Directory where version_info.txt is kept
        2. Output files list with supported extensions

    Following extensions are supported:
        .h, .cs, .doxyfile, .nsh, .org, .py, .rst.txt, .sh,

    To override date, set VERSION_INFO_DATE. e.g.
        SET VERSION_INFO_DATE=DATE

    """)


def get_v_info():
    vinfo = {}
    raw_contents = []
    generator = os.path.relpath(sys.argv[0]) + " (v" + __VUP_VERSION__ + ")"
    try:

        version_info_file = os.path.relpath(sys.argv[1])
    except IndexError:
        version_info_file = "."

    raw_contents.append("Version Information:")
    raw_contents.append("Generated by:")
    raw_contents.append("    " + generator)
    raw_contents.append("")
    raw_contents.append("Do not edit this file. Update:")
    raw_contents.append("    " + version_info_file + "/version_info.txt instead.")

    try:
        exec(compile(open("version_info.txt", "rb").read(), "version_info.txt", 'exec'), {},
             vinfo)  # pylint: disable=exec-used
        with open("version_info.txt", "r") as vf:
            raw_contents.extend(vf.readlines())
    except IOError:
        usage("Missing version_info.txt in " + os.getcwd())
        return None
    return vinfo, raw_contents


def main_gen_required_file(vinfo_dir, input_files):
    print("> vinfo Running on " + vinfo_dir)
    the_pwd = os.getcwd()
    os.chdir(vinfo_dir)
    (vinfo, raw_contents) = get_v_info()
    os.chdir(the_pwd)
    if vinfo:
        o = VersionInformation(vinfo, raw_contents)
        o.parse()
        o.generate_files(input_files)


def test():
    ROOT = '/Users/ing05193/data/n/cm/scripts/vesion_update/'
    DEST_F = "/Users/ing05193/data/n/cm/scripts/vesion_update/tst/out_prod_one/prod_one"
    main_gen_required_file(
        ROOT + "tst/prod_one",
        [
            DEST_F + ".h",
            DEST_F + ".sh",
            DEST_F + ".doxyfile",
            DEST_F + ".org",
            DEST_F + ".nsh",
            DEST_F + ".cs",
        ])


def main():
    # if len(sys.argv) == 1:
    #    test()
    if len(sys.argv) >= 3:
        main_gen_required_file(sys.argv[1], sys.argv[2:])
    else:
        usage("Insufficient arguments")


if __name__ == '__main__':
    main()
