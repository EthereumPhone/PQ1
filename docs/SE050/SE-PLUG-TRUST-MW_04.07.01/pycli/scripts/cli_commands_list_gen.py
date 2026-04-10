#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#


import subprocess
import sys
import logging
log = logging.getLogger(__name__)

# Header of the rst file
HEADER = '''

..
    Copyright 2019,2020 NXP

.. highlight:: bat

.. _cli-cmd-list:

==================================
List of ``ssscli`` commands
==================================

ssscli uses PEM, DER and HEX data formats for keys and certificates. Refer :ref:`cli-data-format`.

.. note:: Linux Environment

    You can ``source pycli/ssscli-bash-completion.sh`` for auto-completion
    on bash with linux/posix based environemnt.

'''

# List commands to be written in the rst
MAIN_COMMANDS = ["", "connect", "disconnect", "set", "get", "generate", "erase", "cloud",
                 "se05x", "refpem", "sign", "verify", "encrypt", "decrypt", "policy"]
SET_COMMANDS = ["aes", "hmac", "cert", "ecc pair", "ecc pub", "rsa pair", "rsa pub", "bin"]
GET_COMMANDS = ["aes", "cert", "ecc pair", "ecc pub", "rsa pair", "rsa pub", "bin"]
GEN__REFPEM_COMMANDS = ["ecc", "rsa"]
REFPEM_ECC_RSA_COMMANDS = ["pair", "pub"]
SE05X_COMMANDS = ["uid", "certuid", "reset", "readidlist"]
POLICY_COMMANDS = ["asymkey", "symkey", "file", "counter", "userid", "pcr", "dump"]


def get_cmd_header(cmd):
    '''Return header for rst'''
    header = '''
%s Commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

''' % (cmd,)
    return str.encode(header)


def run_cmd(cmd):
    '''execute ssscli command help and return output'''
    cmd_str = "ssscli " + cmd + " --help"
    pipes = subprocess.Popen(
        cmd_str,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )
    std_out, std_err = pipes.communicate()
    std_out = std_out.strip()
    std_err = std_err.strip()
    assert pipes.returncode == 0
    return std_out


def write_commands(out_file, commands_list, parent_cmd=""):
    '''write list of commands in the rst '''
    for cmd in commands_list:
        if cmd == "":
            out_file.write(str.encode("1) ``ssscli``::\n\n"))
        else:
            out_file.write(str.encode("#) ``ssscli %s``::\n\n" % (parent_cmd + cmd)))
        cmd_output = run_cmd(parent_cmd + cmd)
        cmd_output_list = cmd_output.split(str.encode("\n"))
        for output_line in cmd_output_list:
            output_line = str.encode("    ") + output_line.replace(str.encode("\r"), str.encode("\n"))
            out_file.write(output_line)
        out_file.write(str.encode("\n\n\n"))
        sys.stdout.write('.')
        sys.stdout.flush()


def main():
    output_file_name = "..\\doc\\cli_commands_list.rst"
    out_file = open(output_file_name, 'wb')
    out_file.write(str.encode(HEADER))

    # ssscli group of commands
    out_file.write(get_cmd_header("ssscli"))
    out_file.write(str.encode("These are the top level commands accepted by the ssscli Tool.\n\n"))
    write_commands(out_file, MAIN_COMMANDS)

    # set commands
    out_file.write(get_cmd_header("Set"))
    out_file.write(str.encode("These commands are used to set/put objects/keys to the target secure subsystem.\n\n"))
    write_commands(out_file, SET_COMMANDS, "set ")

    # get commands
    out_file.write(get_cmd_header("Get"))
    out_file.write(str.encode("These commands are used to retereive/get objects/keys from the target secure subsystem.\n\n"))
    write_commands(out_file, GET_COMMANDS, "get ")

    # generate commands
    out_file.write(get_cmd_header("Generate"))
    out_file.write(str.encode("These commands are used to generate objects/keys inside the target secure subsystem.\n\n"))
    write_commands(out_file, GEN__REFPEM_COMMANDS, "generate ")

    # refpem commands
    out_file.write(get_cmd_header("Refpem"))
    out_file.write(str.encode("These commands are used to get Reference/masked Keys usable by openssl engines.\n\n"))
    write_commands(out_file, REFPEM_ECC_RSA_COMMANDS, "refpem ecc ")
    write_commands(out_file, ["pair"], "refpem rsa ")

    # se05x commands
    out_file.write(get_cmd_header("Se05x"))
    out_file.write(str.encode("These are the SE05x specific commands.\n\n"))
    write_commands(out_file, SE05X_COMMANDS, "se05x ")

    # policy commands
    out_file.write(get_cmd_header("POLICY"))
    out_file.write(str.encode("These are Policy commands.\n\n"))
    write_commands(out_file, POLICY_COMMANDS, "policy ")
    out_file.close()

if __name__ == '__main__':
    logging.basicConfig(format='%(message)s', level=logging.DEBUG)
    main()

