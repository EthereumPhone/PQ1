#! python3

# Copyright 2019 NXP
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
import io

DEBUG = False


class CGTParser(object):
    def __init__(self, ecgt, out_proto_txt, out_jcshell, comment="", applet="SEMS Lite"):
        self.ecgt = ecgt
        self.out_proto_txt = open(out_proto_txt, "w")
        self.out_jcshell = open(out_jcshell, "w")
        self.do_comment(comment)
        self.applet = applet

    def run(self):
        self._begin()
        self._parse_ecgt()
        self._close()

    def _begin(self):
        self.out_jcshell.write("""
/card
/send 00A4040010A0000003965453000000010330000000\n""")
        # self.out_proto_txt.write("payload { hostCmd {\n")
        # self.out_proto_txt.write("    hostControlCmd: 0x01\n")
        # self.out_proto_txt.write("} }\n")
        # self.do_comment("Card manager")
        # self.do_send("00A4040000")
        # self.do_comment("Manage channel - open 1")
        # self.do_send("0070000001")
        # self.do_comment("Card manager on channel 1")
        # self.do_send("01A4040000")
        # if (self.applet == "SEMS Lite"):
        #     self.do_comment("SEMS Lite Applet on channel 1")
        #     self.do_send("01A4040010A0000003965453000000010330000000")

    def do_send(self, the_apdu):
        self.out_jcshell.write("/send %s *9000\n" % (the_apdu,))
        message = []
        for i in range(int(len(the_apdu) / 2)):
            message.append("\\x")
            message.append("%s" % (the_apdu[i * 2]))
            message.append("%s" % (the_apdu[i * 2 + 1]))

        self.out_proto_txt.write("payload { apdu {\n")
        self.out_proto_txt.write("    expectation: 0x9000\n")
        self.out_proto_txt.write("    message: \"%s\"\n" % ("".join(message),))
        self.out_proto_txt.write("} }\n")

    def do_comment(self, message):
        self.out_proto_txt.write("# /* %s */\n" % (message,))
        message = message.replace('\n', "\"\n/echo \"")
        self.out_jcshell.write("\n/echo \"%s\"\n" % (message,))

    def _parse_ecgt(self):
        for l in self.ecgt.readlines():
            if l.startswith("4081"):
                self._process_4081(l.strip())
            elif l.startswith("40"):
                self._process_40Only(l.strip())
            elif l.lower().startswith("7f"):
                self._process_7f(l.strip())
            elif l.startswith("60"):
                self._process_60(l.strip())

    def _process_4081(self, line):
        byte2 = line[4:6]
        full_len = (len(line) / 2) - 3
        tlv_len = int(byte2, 16)
        assert(full_len == tlv_len)

        self.do_comment("SEMS Lite: %s" % line,)
        the_apdu = "80" + line[8:]
        self.do_send(the_apdu)
        self.out_jcshell.write("\n")

    def _process_40Only(self, line):
        byte2 = line[2:4]
        full_len = (len(line) / 2) - 2
        tlv_len = int(byte2, 16)
        assert(full_len == tlv_len)

        self.do_comment("SEMS Lite: %s" % line,)
        the_apdu = "80" + line[6:]
        self.do_send(the_apdu)

    def _process_60(self, line):
        self.do_comment("SEMS Lite: %s" % line,)
        the_apdu = "80a00000" + line[10:]
        self.do_send(the_apdu)

    def _return_split_line(self, line, marker):
        ret = []
        if len(line) > 256 * 2:
            CHUNK = line.find(marker)
            ret.append(line[0:CHUNK])
            ret.append(line[CHUNK:])
        else:
            ret = [line]
        return ret

    def _process_7f(self, line):
        self.do_comment("SEMS Lite: %s" % line,)
        SIG_TAG = "5f37"
        splitted_apdus = self._return_split_line(line, SIG_TAG)
        splitted_apdu = splitted_apdus[0]
        send_apdu = "80A00100" \
            + "%02X" % (len(splitted_apdu) // 2) \
            + splitted_apdu
        self.do_send(send_apdu)
        for splitted_apdu in splitted_apdus[1:]:
            if len(splitted_apdu):
                send_apdu = "80A00000" \
                    + "%02X" % (len(splitted_apdu) // 2) \
                    + splitted_apdu
                self.do_send(send_apdu)

    def _close(self):
        # self.do_comment("manage channel close")
        # self.do_send("00708001")
        # self.out_proto_txt.write("payload { hostCmd {\n")
        # self.out_proto_txt.write("    hostControlCmd: 0x02\n")
        # self.out_proto_txt.write("} }\n")
        self.ecgt.close()
        self.out_jcshell.close()
        self.out_proto_txt.close()


def main():
    if DEBUG:
        test()
    else:
        if len(sys.argv) == 4:
            with open(sys.argv[1], 'r') as f:
                encrypted_data = f.read()
            g = CGTParser(io.StringIO(encrypted_data), sys.argv[2], sys.argv[3])
            g.run()
            print("Done... %s and %s created" % (sys.argv[2], sys.argv[3]))
        else:
            usage()


def usage():
    print("Usage:\n")
    print("    %s <in-encrypted.txt> <out-protobuf> <out-jcsh> applet to select\n" % (sys.argv[0]))


def test():
    ecgt = r"S:\SEMS_Lite_1.1.1.11JxR_AppletPackage\sems_lite_scripts\encryptedScripts\04_SEMS_Lite_IoT_Applet_Load_Install_V1_Upgrade_V2-encrypted.txt"
    out_proto_txt = "out_proto.txt"
    out_jcshell = "out_sems_lite.jcsh"

    g = CGTParser(ecgt, out_proto_txt, out_jcshell)

    g.run()


if __name__ == '__main__':
    main()
